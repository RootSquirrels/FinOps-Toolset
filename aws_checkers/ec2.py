"""Checkers: Amazon EC2.

Included checks:

  - check_ec2_underutilized_instances
      Running instances with low CPU and low network traffic.

  - check_ec2_stopped_instances
      Instances stopped for a long time (heuristic) + EBS monthly storage estimate.

  - check_ec2_old_generation_instances
      Previous/legacy generation instance families.

  - check_ec2_unused_security_groups
      Security groups not attached to any ENI (excludes 'default').

Design:
  - Dependencies via finops_toolset.checkers.config.setup(...).
  - CloudWatch via finops_toolset.cloudwatch.CloudWatchBatcher.
  - Tolerant signatures; graceful skips; no return values.
  - UTC datetimes; pylint-friendly; lines ≤ 100 chars.
"""

from __future__ import annotations

import logging
import re
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from botocore.exceptions import ClientError

from aws_checkers import config
from core.retry import retry_with_backoff
from core.cloudwatch import CloudWatchBatcher


# -------------------------------- helpers -------------------------------- #

def _logger(fallback: Optional[logging.Logger]) -> logging.Logger:
    return fallback or config.LOGGER or logging.getLogger(__name__)


def _signals_str(pairs: Dict[str, object]) -> str:
    items: List[str] = []
    for k, v in pairs.items():
        if v is None or v == "":
            continue
        items.append(f"{k}={v}")
    return "|".join(items)


def _to_utc_iso(dt_obj: Optional[datetime]) -> Optional[str]:
    if not isinstance(dt_obj, datetime):
        return None
    if dt_obj.tzinfo is None:
        dt_obj = dt_obj.replace(tzinfo=timezone.utc)
    else:
        dt_obj = dt_obj.astimezone(timezone.utc)
    return dt_obj.replace(microsecond=0).isoformat()


def _extract_writer_ec2_cw(
    args: Tuple[Any, ...],
    kwargs: Dict[str, Any],
) -> Tuple[Any, Any, Any]:
    """Accept writer/ec2/cloudwatch passed positionally or by keyword."""
    writer = kwargs.get("writer", args[0] if len(args) >= 1 else None)
    ec2 = kwargs.get("ec2", args[1] if len(args) >= 2 else None)
    cloudwatch = kwargs.get("cloudwatch", args[2] if len(args) >= 3 else None)
    if writer is None or ec2 is None or cloudwatch is None:
        raise TypeError(
            "Expected 'writer', 'ec2', and 'cloudwatch' "
            f"(got writer={writer!r}, ec2={ec2!r}, cloudwatch={cloudwatch!r})"
        )
    return writer, ec2, cloudwatch


def _chunk(seq: Sequence[str], n: int) -> Iterable[List[str]]:
    for i in range(0, len(seq), n):
        yield list(seq[i:i + n])


def _sum_from_result(res: Any) -> float:
    if res is None:
        return 0.0
    if isinstance(res, list) and res and isinstance(res[0], tuple):
        try:
            return float(sum(float(v) for _, v in res))
        except Exception:  # pylint: disable=broad-except
            return 0.0
    if isinstance(res, dict):
        vals = res.get("Values") or res.get("values") or []
        try:
            return float(sum(vals))
        except Exception:  # pylint: disable=broad-except
            return 0.0
    return 0.0


def _avg_from_result(res: Any) -> float:
    if res is None:
        return 0.0
    if isinstance(res, list) and res and isinstance(res[0], tuple):
        try:
            vs = [float(v) for _, v in res]
            return float(sum(vs) / len(vs)) if vs else 0.0
        except Exception:  # pylint: disable=broad-except
            return 0.0
    if isinstance(res, dict):
        vals = res.get("Values") or res.get("values") or []
        try:
            return float(sum(vals) / len(vals)) if vals else 0.0
        except Exception:  # pylint: disable=broad-except
            return 0.0
    return 0.0


def _instance_hour_price(inst_type: str) -> float:
    """Pricebook hook. Provide 'EC2' → 'OD_<type>_HR' entries when available."""
    key = f"OD_{(inst_type or '').replace('.', '_').upper()}_HR"
    return float(config.safe_price("EC2", key, 0.0))


def _volume_monthly_cost(vol: Dict[str, Any]) -> float:
    """Heuristic EBS volume monthly cost (same logic as EBS checker)."""
    vtype = (vol.get("VolumeType") or "").lower()
    size_gb = float(vol.get("Size") or 0)
    iops = int(vol.get("Iops") or 0)
    throughput = int(vol.get("Throughput") or 0)  # gp3 only

    price_gb = {
        "gp2": config.safe_price("EBS", "GP2_GB_MONTH", 0.0),
        "gp3": config.safe_price("EBS", "GP3_GB_MONTH", 0.0),
        "io1": config.safe_price("EBS", "IO1_GB_MONTH", 0.0),
        "io2": config.safe_price("EBS", "IO2_GB_MONTH", 0.0),
        "st1": config.safe_price("EBS", "ST1_GB_MONTH", 0.0),
        "sc1": config.safe_price("EBS", "SC1_GB_MONTH", 0.0),
        "standard": config.safe_price("EBS", "MAGNETIC_GB_MONTH", 0.0),
    }.get(vtype, 0.0)

    base = size_gb * price_gb
    add = 0.0
    if vtype in {"io1", "io2"} and iops > 0:
        add += iops * (
            config.safe_price("EBS", "IO1_IOPS_MONTH", 0.0) if vtype == "io1"
            else config.safe_price("EBS", "IO2_IOPS_MONTH", 0.0)
        )
    if vtype == "gp3":
        extra_iops = max(0, iops - 3000)
        extra_tp = max(0, throughput - 125)
        if extra_iops > 0:
            add += extra_iops * config.safe_price("EBS", "GP3_IOPS_MONTH", 0.0)
        if extra_tp > 0:
            add += extra_tp * config.safe_price("EBS", "GP3_THROUGHPUT_MBPS_MONTH", 0.0)
    return base + add


def _describe_volumes_map(ec2, vol_ids: List[str], log: logging.Logger) -> Dict[str, Dict[str, Any]]:
    info: Dict[str, Dict[str, Any]] = {}
    if not vol_ids:
        return info
    vids = list({v for v in vol_ids if v})
    for chunk_ids in _chunk(vids, 200):
        try:
            resp = ec2.describe_volumes(VolumeIds=chunk_ids)
            for v in resp.get("Volumes", []) or []:
                vid = v.get("VolumeId")
                if vid:
                    info[vid] = v
        except ClientError as exc:
            log.debug("[ec2] describe_volumes chunk failed: %s", exc)
    return info


def _parse_stopped_time(reason: Optional[str]) -> Optional[datetime]:
    """Parse '(YYYY-MM-DD HH:MM:SS GMT)' from StateTransitionReason if present."""
    if not reason:
        return None
    # Examples: 'User initiated (2021-08-26 12:54:38 GMT)'
    m = re.search(r"\((\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})\s+GMT\)", reason)
    if not m:
        return None
    try:
        dt = datetime.strptime(m.group(1), "%Y-%m-%d %H:%M:%S")
        return dt.replace(tzinfo=timezone.utc)
    except Exception:  # pylint: disable=broad-except
        return None


# ---------------------- 1) Underutilized instances ---------------------- #

@retry_with_backoff(exceptions=(ClientError,))
def check_ec2_underutilized_instances(  # pylint: disable=unused-argument
    *args,
    logger: Optional[logging.Logger] = None,
    lookback_days: int = 14,
    cpu_avg_threshold: float = 5.0,
    cpu_max_threshold: float = 10.0,
    net_avg_bps_threshold: float = 100_000.0,
    **kwargs,
) -> None:
    log = _logger(kwargs.get("logger") or logger)
    try:
        writer, ec2, cloudwatch = _extract_writer_ec2_cw(args, kwargs)
    except TypeError as exc:
        log.warning("[check_ec2_underutilized_instances] Skipping: %s", exc)
        return
    if not (config.ACCOUNT_ID and config.WRITE_ROW and config.GET_PRICE):
        log.warning("[check_ec2_underutilized_instances] Skipping: checker config not provided.")
        return

    region = getattr(getattr(ec2, "meta", None), "region_name", "") or ""

    insts: List[Dict[str, Any]] = []
    try:
        paginator = ec2.get_paginator("describe_instances")
        for page in paginator.paginate(
            Filters=[{"Name": "instance-state-name", "Values": ["running"]}]
        ):
            for r in page.get("Reservations", []) or []:
                insts.extend(r.get("Instances", []) or [])
    except ClientError as exc:
        log.error("[ec2] describe_instances failed: %s", exc)
        return
    if not insts:
        return

    now_utc = datetime.now(timezone.utc).replace(microsecond=0)
    start = now_utc - timedelta(days=int(lookback_days))
    seconds = float((now_utc - start).total_seconds())
    period = 300

    id_map: Dict[str, Dict[str, str]] = {}
    results: Dict[str, Any] = {}
    metrics_ok = True
    try:
        cw = CloudWatchBatcher(region=region, client=cloudwatch)
        for inst in insts:
            iid = inst.get("InstanceId")
            if not iid:
                continue
            dims = [("InstanceId", iid)]

            id_cpu_avg = f"cpuA_{iid}"
            id_cpu_max = f"cpuM_{iid}"
            id_net_in = f"netI_{iid}"
            id_net_out = f"netO_{iid}"

            cw.add_q(
                id_hint=id_cpu_avg,
                namespace="AWS/EC2",
                metric="CPUUtilization",
                dims=dims,
                stat="Average",
                period=period,
            )
            cw.add_q(
                id_hint=id_cpu_max,
                namespace="AWS/EC2",
                metric="CPUUtilization",
                dims=dims,
                stat="Maximum",
                period=period,
            )
            cw.add_q(
                id_hint=id_net_in,
                namespace="AWS/EC2",
                metric="NetworkIn",
                dims=dims,
                stat="Sum",
                period=period,
            )
            cw.add_q(
                id_hint=id_net_out,
                namespace="AWS/EC2",
                metric="NetworkOut",
                dims=dims,
                stat="Sum",
                period=period,
            )

            id_map[iid] = {
                "cpu_avg": id_cpu_avg,
                "cpu_max": id_cpu_max,
                "net_in": id_net_in,
                "net_out": id_net_out,
            }

        results = cw.execute(start=start, end=now_utc)
    except ClientError as exc:
        log.warning("[ec2] CloudWatch metrics unavailable: %s", exc)
        metrics_ok = False
    except Exception as exc:  # pylint: disable=broad-except
        log.warning("[ec2] CloudWatch batch error: %s", exc)
        metrics_ok = False
    if not metrics_ok:
        return

    for inst in insts:
        iid = inst.get("InstanceId") or ""
        itype = inst.get("InstanceType") or ""
        name = next((t.get("Value") for t in inst.get("Tags", []) or []
                     if t.get("Key") == "Name"), "") or ""

        ids = id_map.get(iid, {})
        cpu_avg = _avg_from_result(results.get(ids.get("cpu_avg")))
        cpu_max = _avg_from_result(results.get(ids.get("cpu_max")))
        net_in = _sum_from_result(results.get(ids.get("net_in")))
        net_out = _sum_from_result(results.get(ids.get("net_out")))
        net_avg_bps = (net_in + net_out) / seconds if seconds > 0 else 0.0

        if not (
            cpu_avg < float(cpu_avg_threshold)
            and cpu_max < float(cpu_max_threshold)
            and net_avg_bps < float(net_avg_bps_threshold)
        ):
            continue

        hr_price = _instance_hour_price(itype)
        est = 730.0 * hr_price
        potential = est

        flags = ["EC2InstanceUnderutilized"]
        signals = _signals_str(
            {
                "Region": region,
                "InstanceId": iid,
                "Name": name,
                "Type": itype,
                "CPUAvg": round(cpu_avg, 3),
                "CPUMax": round(cpu_max, 3),
                "NetAvgBps": int(net_avg_bps),
                "LookbackDays": lookback_days,
            }
        )

        try:
            config.WRITE_ROW(  # type: ignore[call-arg]
                writer=writer,
                resource_id=iid,
                name=name or iid,
                owner_id=config.ACCOUNT_ID,  # type: ignore[arg-type]
                resource_type="EC2Instance",
                estimated_cost=est,
                potential_saving=potential,
                flags=flags,
                confidence=100,
                signals=signals,
            )
        except Exception as exc:  # pylint: disable=broad-except
            log.warning("[ec2] write_row failed for %s: %s", iid, exc)

        log.info("[ec2] Wrote underutilized: %s (%s)", iid, itype)

# ---------------------- 2) Stopped instances (old) ---------------------- #

@retry_with_backoff(exceptions=(ClientError,))
def check_ec2_stopped_instances(  # pylint: disable=unused-argument
    *args,
    logger: Optional[logging.Logger] = None,
    stale_days: int = 14,
    **kwargs,
) -> None:
    """
    Flag instances in 'stopped' state for longer than 'stale_days'.

    Estimated cost = monthly storage of attached EBS volumes (heuristic).
    """
    log = _logger(kwargs.get("logger") or logger)
    try:
        writer, ec2, cloudwatch = _extract_writer_ec2_cw(args, kwargs)  # cloudwatch unused
    except TypeError as exc:
        log.warning("[check_ec2_stopped_instances] Skipping: %s", exc)
        return
    if not (config.ACCOUNT_ID and config.WRITE_ROW and config.GET_PRICE):
        log.warning("[check_ec2_stopped_instances] Skipping: checker config not provided.")
        return

    region = getattr(getattr(ec2, "meta", None), "region_name", "") or ""
    cutoff = (datetime.now(timezone.utc) - timedelta(days=int(stale_days))).replace(microsecond=0)

    insts: List[Dict[str, Any]] = []
    try:
        paginator = ec2.get_paginator("describe_instances")
        for page in paginator.paginate(
            Filters=[{"Name": "instance-state-name", "Values": ["stopped"]}]
        ):
            for r in page.get("Reservations", []) or []:
                insts.extend(r.get("Instances", []) or [])
    except ClientError as exc:
        log.error("[ec2] describe_instances failed: %s", exc)
        return
    if not insts:
        return

    # Collect volume ids from block device mappings
    vol_ids: List[str] = []
    for i in insts:
        for bdm in i.get("BlockDeviceMappings", []) or []:
            ebs = bdm.get("Ebs") or {}
            sid = ebs.get("VolumeId")
            if sid:
                vol_ids.append(sid)
    vols_map = _describe_volumes_map(ec2, vol_ids, log)

    for i in insts:
        iid = i.get("InstanceId") or ""
        itype = i.get("InstanceType") or ""
        name = ""
        for t in i.get("Tags", []) or []:
            if t.get("Key") == "Name":
                name = t.get("Value") or ""
                break
        reason = i.get("StateTransitionReason")
        stopped_at = _parse_stopped_time(reason)
        if not stopped_at or stopped_at >= cutoff:
            continue

        # Sum monthly cost of all mapped volumes
        est = 0.0
        attached: List[str] = []
        for bdm in i.get("BlockDeviceMappings", []) or []:
            ebs = bdm.get("Ebs") or {}
            vid = ebs.get("VolumeId")
            if not vid:
                continue
            attached.append(vid)
            est += _volume_monthly_cost(vols_map.get(vid, {}))

        potential = est  # delete-on-termination of stale instance volumes

        flags = ["EC2InstanceStoppedLong"]
        signals = _signals_str(
            {
                "Region": region,
                "InstanceId": iid,
                "Name": name,
                "Type": itype,
                "StoppedAt": _to_utc_iso(stopped_at),
                "StaleDays": stale_days,
                "VolumeCount": len(attached),
                "VolumeIds": ",".join(attached),
            }
        )

        try:
            # type: ignore[call-arg]
            config.WRITE_ROW(
                writer=writer,
                resource_id=iid,
                name=name or iid,
                owner_id=config.ACCOUNT_ID,  # type: ignore[arg-type]
                resource_type="EC2Instance",
                estimated_cost=est,
                potential_saving=potential,
                flags=flags,
                confidence=100,
                signals=signals,
            )
        except Exception as exc:  # pylint: disable=broad-except
            log.warning("[ec2] write_row failed for %s: %s", iid, exc)

        log.info("[ec2] Wrote stopped-long: %s", iid)


# ------------------- 3) Old generation instance families ---------------- #

_OLD_LEGACY = {
    "t1", "t2",
    "m1", "m2", "m3",
    "c1", "c3",
    "r3",
    "i2",
    "g2",
    "d2",
}
_PREVIOUS_GEN = {
    "m4", "c4", "r4", "i3", "t3", "t3a",
    "m5", "c5", "r5", "i3en", "m5a", "c5a", "r5a", "m5n", "c5n", "r5n",
}


@retry_with_backoff(exceptions=(ClientError,))
def check_ec2_old_generation_instances(  # pylint: disable=unused-argument
    *args,
    logger: Optional[logging.Logger] = None,
    **kwargs,
) -> None:
    """Flag instances on legacy/previous generation families."""
    log = _logger(kwargs.get("logger") or logger)
    try:
        writer, ec2, cloudwatch = _extract_writer_ec2_cw(args, kwargs)  # cloudwatch unused
    except TypeError as exc:
        log.warning("[check_ec2_old_generation_instances] Skipping: %s", exc)
        return
    if not (config.ACCOUNT_ID and config.WRITE_ROW):
        log.warning("[check_ec2_old_generation_instances] Skipping: checker config not provided.")
        return

    region = getattr(getattr(ec2, "meta", None), "region_name", "") or ""

    insts: List[Dict[str, Any]] = []
    try:
        paginator = ec2.get_paginator("describe_instances")
        for page in paginator.paginate():
            for r in page.get("Reservations", []) or []:
                insts.extend(r.get("Instances", []) or [])
    except ClientError as exc:
        log.error("[ec2] describe_instances failed: %s", exc)
        return
    if not insts:
        return

    for i in insts:
        iid = i.get("InstanceId") or ""
        itype = (i.get("InstanceType") or "").lower()
        fam = itype.split(".")[0] if "." in itype else itype
        name = ""
        for t in i.get("Tags", []) or []:
            if t.get("Key") == "Name":
                name = t.get("Value") or ""
                break

        flags: List[str] = []
        if fam in _OLD_LEGACY:
            flags.append("EC2InstanceLegacyGen")
        elif fam in _PREVIOUS_GEN:
            flags.append("EC2InstancePreviousGen")
        else:
            continue

        try:
            # type: ignore[call-arg]
            config.WRITE_ROW(
                writer=writer,
                resource_id=iid,
                name=name or iid,
                owner_id=config.ACCOUNT_ID,  # type: ignore[arg-type]
                resource_type="EC2Instance",
                estimated_cost=0.0,
                potential_saving=0.0,
                flags=flags,
                confidence=100,
                signals=_signals_str(
                    {"Region": region, "InstanceId": iid, "Type": itype, "Family": fam}
                ),
            )
        except Exception as exc:  # pylint: disable=broad-except
            log.warning("[ec2] write_row failed for %s: %s", iid, exc)

        log.info("[ec2] Wrote old-gen: %s (%s)", iid, fam)


# ---------------------- 4) Unused security groups ----------------------- #

@retry_with_backoff(exceptions=(ClientError,))
def check_ec2_unused_security_groups(  # pylint: disable=unused-argument
    *args,
    logger: Optional[logging.Logger] = None,
    **kwargs,
) -> None:
    """Flag security groups not attached to any network interface (excl. 'default')."""
    log = _logger(kwargs.get("logger") or logger)
    try:
        writer, ec2, cloudwatch = _extract_writer_ec2_cw(args, kwargs)  # cloudwatch unused
    except TypeError as exc:
        log.warning("[check_ec2_unused_security_groups] Skipping: %s", exc)
        return
    if not (config.ACCOUNT_ID and config.WRITE_ROW):
        log.warning("[check_ec2_unused_security_groups] Skipping: checker config not provided.")
        return

    region = getattr(getattr(ec2, "meta", None), "region_name", "") or ""

    # All SGs
    sgs: List[Dict[str, Any]] = []
    try:
        p = ec2.get_paginator("describe_security_groups")
        for page in p.paginate():
            sgs.extend(page.get("SecurityGroups", []) or [])
    except ClientError as exc:
        log.error("[ec2] describe_security_groups failed: %s", exc)
        return

    # All ENIs → used SG ids
    used: set = set()
    try:
        p = ec2.get_paginator("describe_network_interfaces")
        for page in p.paginate():
            for eni in page.get("NetworkInterfaces", []) or []:
                for g in eni.get("Groups", []) or []:
                    gid = g.get("GroupId")
                    if gid:
                        used.add(gid)
    except ClientError as exc:
        log.error("[ec2] describe_network_interfaces failed: %s", exc)
        return

    for sg in sgs:
        gid = sg.get("GroupId")
        name = sg.get("GroupName") or gid
        if not gid or name == "default":
            continue
        if gid in used:
            continue

        try:
            # type: ignore[call-arg]
            config.WRITE_ROW(
                writer=writer,
                resource_id=gid,
                name=name or gid,
                owner_id=config.ACCOUNT_ID,  # type: ignore[arg-type]
                resource_type="EC2SecurityGroup",
                estimated_cost=0.0,
                potential_saving=0.0,
                flags=["EC2SecurityGroupUnused"],
                confidence=100,
                signals=_signals_str({"Region": region, "GroupId": gid, "Name": name}),
            )
        except Exception as exc:  # pylint: disable=broad-except
            log.warning("[ec2] write_row failed for SG %s: %s", gid, exc)

        log.info("[ec2] Wrote unused SG: %s", gid)
