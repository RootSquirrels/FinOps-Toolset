"""Checkers: Amazon EC2.
notes:
  - CloudWatch-driven checks include datapoint coverage guards to reduce false
    positives when metrics are sparse.
  - Security group "unused" check excludes groups referenced by Launch
    Templates / Launch Configurations when possible (optional autoscaling
    client).

Included findings :
  - Underutilized running instances (low CPU + low acknowledging network)
  - Stopped instances for a long time (best-effort stop time parsing)
  - Old generation instance families
  - Unused security groups (not attached to any ENI; excludes referenced SGs)
"""

from __future__ import annotations

import logging
import re
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set, Tuple

from botocore.exceptions import ClientError
from finops_toolset import config as const

from aws_checkers import config
from aws_checkers.common import _logger, _to_utc_iso
from core.retry import retry_with_backoff
from core.cloudwatch import CloudWatchBatcher


# ------------------------------ small utils ------------------------------ #

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


def _extract_writer_ec2(
    args: Tuple[Any, ...],
    kwargs: Dict[str, Any],
) -> Tuple[Any, Any]:
    writer = kwargs.get("writer", args[0] if len(args) >= 1 else None)
    ec2 = kwargs.get("ec2", args[1] if len(args) >= 2 else None)
    if writer is None or ec2 is None:
        raise TypeError(
            "Expected 'writer' and 'ec2' "
            f"(got writer={writer!r}, ec2={ec2!r})"
        )
    return writer, ec2


def _chunk(seq: Sequence[str], n: int) -> Iterable[List[str]]:
    for i in range(0, len(seq), n):
        yield list(seq[i : i + n])


def _series_values(res: Any) -> List[float]:
    """Normalize CloudWatchBatcher result to a list of floats."""
    if res is None:
        return []
    if isinstance(res, list) and res and isinstance(res[0], tuple):
        out: List[float] = []
        for _, v in res:
            try:
                out.append(float(v))
            except Exception:  # pylint: disable=broad-except
                continue
        return out
    if isinstance(res, dict):
        vals = res.get("Values") or res.get("values") or []
        out = []
        for v in vals:
            try:
                out.append(float(v))
            except Exception:  # pylint: disable=broad-except
                continue
        return out
    return []


def _sum_from_result(res: Any) -> float:
    vs = _series_values(res)
    return float(sum(vs)) if vs else 0.0


def _avg_from_result(res: Any) -> float:
    vs = _series_values(res)
    return float(sum(vs) / len(vs)) if vs else 0.0


def _max_from_result(res: Any) -> float:
    vs = _series_values(res)
    return float(max(vs)) if vs else 0.0


def _count_from_result(res: Any) -> int:
    return len(_series_values(res))


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

    base = size_gb * float(price_gb)
    add = 0.0
    if vtype in {"io1", "io2"} and iops > 0:
        add += iops * (
            float(config.safe_price("EBS", "IO1_IOPS_MONTH", 0.0))
            if vtype == "io1"
            else float(config.safe_price("EBS", "IO2_IOPS_MONTH", 0.0))
        )
    if vtype == "gp3":
        extra_iops = max(0, iops - 3000)
        extra_tp = max(0, throughput - 125)
        if extra_iops > 0:
            add += extra_iops * float(config.safe_price("EBS", "GP3_IOPS_MONTH", 0.0))
        if extra_tp > 0:
            add += extra_tp * float(
                config.safe_price("EBS", "GP3_THROUGHPUT_MBPS_MONTH", 0.0)
            )
    return base + add


def _describe_volumes_map(
    ec2,
    vol_ids: List[str],
    log: logging.Logger,
) -> Dict[str, Dict[str, Any]]:
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
                    info[str(vid)] = v
        except ClientError as exc:
            log.debug("[ec2] describe_volumes chunk failed: %s", exc)
    return info


def _parse_stopped_time(reason: Optional[str]) -> Optional[datetime]:
    """Parse stop time from StateTransitionReason if present (best-effort)."""
    if not reason:
        return None
    # Most common: 'User initiated (2021-08-26 12:54:38 GMT)'
    m = re.search(r"\((\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})\s+GMT\)", reason)
    if not m:
        # Sometimes: 'Server.InternalError: ... (2021-08-26 12:54:38 UTC)'
        m = re.search(
            r"\((\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})\s+(?:UTC|GMT)\)",
            reason,
        )
    if not m:
        return None
    try:
        dt = datetime.strptime(m.group(1), "%Y-%m-%d %H:%M:%S")
        return dt.replace(tzinfo=timezone.utc)
    except Exception:  # pylint: disable=broad-except
        return None


def _writer_stream_id(writer: Any) -> int:
    """Best-effort identity for the underlying output stream."""
    for attr in ("f", "fp", "stream", "file", "buffer", "raw"):
        stream = getattr(writer, attr, None)
        if stream is not None:
            return id(stream)
    inner = getattr(writer, "writer", None)
    if inner is not None:
        for attr in ("f", "fp", "stream", "file", "buffer", "raw"):
            stream = getattr(inner, attr, None)
            if stream is not None:
                return id(stream)
        return id(inner)
    return id(writer)


def _dedupe_key(row: Dict[str, Any]) -> Tuple[str, str, str, str]:
    return (
        str(row.get("resource_id") or ""),
        str(row.get("resource_type") or ""),
        str(row.get("region") or ""),
        str(row.get("owner_id") or ""),
    )


def _merge_flags(existing: List[str], incoming: List[str]) -> List[str]:
    if not incoming:
        return existing
    if not existing:
        return list(incoming)
    seen = set(existing)
    for f in incoming:
        if f not in seen:
            existing.append(f)
            seen.add(f)
    return existing


def _merge_signals(existing: Dict[str, Any], incoming: Dict[str, Any]) -> Dict[str, Any]:
    if not incoming:
        return existing
    if not existing:
        return dict(incoming)
    for k, v in incoming.items():
        if k not in existing:
            existing[k] = v
        elif existing.get(k) in (None, "", "NULL") and v not in (None, "", "NULL"):
            existing[k] = v
    return existing


def _max_float(a: Any, b: Any) -> float:
    try:
        fa = float(a)
    except Exception:  # pylint: disable=broad-except
        fa = 0.0
    try:
        fb = float(b)
    except Exception:  # pylint: disable=broad-except
        fb = 0.0
    return fa if fa >= fb else fb


def _collect_row(
    rows: Dict[Tuple[str, str, str, str], Dict[str, Any]],
    row: Dict[str, Any],
) -> None:
    key = _dedupe_key(row)
    existing = rows.get(key)
    if existing is None:
        if row.get("flags") is None:
            row["flags"] = []
        if row.get("signals") is None:
            row["signals"] = {}
        rows[key] = row
        return

    existing["flags"] = _merge_flags(
        list(existing.get("flags") or []),
        list(row.get("flags") or []),
    )
    existing["signals"] = _merge_signals(
        dict(existing.get("signals") or {}),
        dict(row.get("signals") or {}),
    )
    existing["estimated_cost"] = _max_float(existing.get("estimated_cost"), row.get("estimated_cost"))
    existing["potential_saving"] = _max_float(
        existing.get("potential_saving"), row.get("potential_saving")
    )
    # fill missing fields
    for k, v in row.items():
        if k in ("flags", "signals", "estimated_cost", "potential_saving"):
            continue
        if existing.get(k) in (None, "", "NULL") and v not in (None, "", "NULL"):
            existing[k] = v


# ------------------- security group reference helpers ------------------- #

def _sg_ids_from_launch_templates(ec2, log: logging.Logger) -> Set[str]:
    """Return SG ids referenced by *latest* versions of launch templates."""
    referenced: Set[str] = set()
    try:
        p = ec2.get_paginator("describe_launch_templates")
        templates: List[Dict[str, Any]] = []
        for page in p.paginate():
            templates.extend(page.get("LaunchTemplates", []) or [])
    except ClientError as exc:
        log.debug("[ec2] describe_launch_templates not available: %s", exc)
        return referenced

    # Fetch latest version data per template; do this once per run.
    for t in templates:
        lt_id = t.get("LaunchTemplateId")
        if not lt_id:
            continue
        try:
            resp = ec2.describe_launch_template_versions(
                LaunchTemplateId=lt_id,
                Versions=["$Latest"],
            )
            for v in resp.get("LaunchTemplateVersions", []) or []:
                data = v.get("LaunchTemplateData") or {}
                for sgid in data.get("SecurityGroupIds", []) or []:
                    if sgid:
                        referenced.add(str(sgid))
                for ni in data.get("NetworkInterfaces", []) or []:
                    for sgid in ni.get("Groups", []) or []:
                        if sgid:
                            referenced.add(str(sgid))
        except ClientError as exc:
            log.debug("[ec2] describe_launch_template_versions failed for %s: %s", lt_id, exc)
            continue
    return referenced


def _sg_ids_from_launch_configurations(autoscaling, log: logging.Logger) -> Set[str]:
    referenced: Set[str] = set()
    if autoscaling is None:
        return referenced
    try:
        p = autoscaling.get_paginator("describe_launch_configurations")
        for page in p.paginate():
            for lc in page.get("LaunchConfigurations", []) or []:
                for sgid in lc.get("SecurityGroups", []) or []:
                    if sgid:
                        referenced.add(str(sgid))
    except Exception as exc:  # pylint: disable=broad-except
        log.debug("[ec2] describe_launch_configurations not available: %s", exc)
    return referenced


# ----------------------------- family tables ----------------------------- #

_OLD_LEGACY = {
    "t1",
    "t2",
    "m1",
    "m2",
    "m3",
    "c1",
    "c3",
    "r3",
    "i2",
    "g2",
    "d2",
}

_PREVIOUS_GEN = {
    "m4",
    "c4",
    "r4",
    "i3",
    "t3",
    "t3a",
    "m5",
    "c5",
    "r5",
    "i3en",
    "m5a",
    "c5a",
    "r5a",
    "m5n",
    "c5n",
    "r5n",
}


# ---------------------------- global entrypoint -------------------------- #

_EC2_ALREADY_RAN: Set[Tuple[int, str, str]] = set()


@retry_with_backoff(exceptions=(ClientError,))
def check_ec2_resources(  # pylint: disable=unused-argument
    *args,
    logger: Optional[logging.Logger] = None,
    lookback_days: int = 14,
    cpu_avg_threshold: float = 5.0,
    cpu_max_threshold: float = 10.0,
    net_avg_bps_threshold: float = 100_000.0,
    metrics_min_coverage: float = 0.75,
    stale_days: int = 14,
    autoscaling=None,
    **kwargs,
) -> None:
    """Global EC2 checker (KMS-style): merge all findings and write once."""
    log = _logger(kwargs.get("logger") or logger)

    try:
        writer, ec2, cloudwatch = _extract_writer_ec2_cw(args, kwargs)
    except TypeError:
        # Allow checks that don't need CloudWatch to still run.
        try:
            writer, ec2 = _extract_writer_ec2(args, kwargs)
            cloudwatch = kwargs.get("cloudwatch")
        except TypeError as exc:
            log.warning("[check_ec2_resources] Skipping: %s", exc)
            return

    if not (config.ACCOUNT_ID and config.WRITE_ROW):
        log.warning("[check_ec2_resources] Skipping: checker config not provided.")
        return

    region = getattr(getattr(ec2, "meta", None), "region_name", "") or ""
    run_key = (_writer_stream_id(writer), region, str(config.ACCOUNT_ID))
    if run_key in _EC2_ALREADY_RAN:
        log.info("[ec2] Skipping duplicate EC2 run for %s", region)
        return
    _EC2_ALREADY_RAN.add(run_key)

    rows: Dict[Tuple[str, str, str, str], Dict[str, Any]] = {}

    # ------------------------- 1) Underutilized ------------------------- #
    if cloudwatch is not None and config.GET_PRICE is not None:
        _collect_underutilized(
            rows,
            writer=writer,
            ec2=ec2,
            cloudwatch=cloudwatch,
            region=region,
            lookback_days=lookback_days,
            cpu_avg_threshold=cpu_avg_threshold,
            cpu_max_threshold=cpu_max_threshold,
            net_avg_bps_threshold=net_avg_bps_threshold,
            metrics_min_coverage=metrics_min_coverage,
            log=log,
        )
    else:
        log.debug("[ec2] Skipping underutilized: CloudWatch or pricing missing")

    # ------------------------- 2) Stopped long -------------------------- #
    _collect_stopped_long(
        rows,
        ec2=ec2,
        region=region,
        stale_days=stale_days,
        log=log,
    )

    # ------------------------- 3) Old generation ------------------------ #
    _collect_old_generation(rows, ec2=ec2, region=region, log=log)

    # ------------------------- 4) Unused SGs ---------------------------- #
    _collect_unused_security_groups(
        rows,
        ec2=ec2,
        autoscaling=autoscaling or kwargs.get("autoscaling"),
        region=region,
        log=log,
    )

    # ------------------------------ flush ------------------------------- #
    ordered = sorted(
        rows.values(),
        key=lambda r: (str(r.get("resource_type") or ""), str(r.get("resource_id") or "")),
    )
    for row in ordered:
        try:
            config.WRITE_ROW(writer=writer, **row)  # type: ignore[call-arg]
        except Exception as exc:  # pylint: disable=broad-except
            log.warning("[ec2] write_row failed for %s: %s", row.get("resource_id"), exc)

    log.info("[ec2] Completed check_ec2_resources (rows=%d)", len(ordered))


# -------------------------- collectors (internal) ------------------------- #

def _collect_underutilized(
    rows: Dict[Tuple[str, str, str, str], Dict[str, Any]],
    *,
    writer: Any,  # unused; kept for symmetry
    ec2,
    cloudwatch,
    region: str,
    lookback_days: int,
    cpu_avg_threshold: float,
    cpu_max_threshold: float,
    net_avg_bps_threshold: float,
    metrics_min_coverage: float,
    log: logging.Logger,
) -> None:
    """Collect underutilized instance findings with metrics coverage guards."""
    insts: List[Dict[str, Any]] = []
    try:
        paginator = ec2.get_paginator("describe_instances")
        for page in paginator.paginate(
            Filters=[{"Name": "instance-state-name", "Values": ["running"]}]
        ):
            for res in page.get("Reservations", []) or []:
                insts.extend(res.get("Instances", []) or [])
    except ClientError as exc:
        log.error("[ec2] describe_instances failed: %s", exc)
        return
    if not insts:
        return

    now_utc = datetime.now(timezone.utc).replace(microsecond=0)
    start = now_utc - timedelta(days=int(lookback_days))
    seconds = float((now_utc - start).total_seconds())
    period = 300
    expected_points = max(1, int(seconds / period))

    id_map: Dict[str, Dict[str, str]] = {}
    results: Dict[str, Any] = {}
    try:
        cw = CloudWatchBatcher(region=region, client=cloudwatch)
        for inst in insts:
            iid = inst.get("InstanceId")
            if not iid:
                continue
            dims = [("InstanceId", str(iid))]

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

            id_map[str(iid)] = {
                "cpu_avg": id_cpu_avg,
                "cpu_max": id_cpu_max,
                "net_in": id_net_in,
                "net_out": id_net_out,
            }

        results = cw.execute(start=start, end=now_utc)
    except Exception as exc:  # pylint: disable=broad-except
        log.warning("[ec2] CloudWatch metrics unavailable: %s", exc)
        return

    for inst in insts:
        iid = str(inst.get("InstanceId") or "")
        if not iid:
            continue
        itype = str(inst.get("InstanceType") or "")
        name = next(
            (t.get("Value") for t in inst.get("Tags", []) or [] if t.get("Key") == "Name"),
            "",
        ) or ""

        ids = id_map.get(iid, {})
        cpu_avg_res = results.get(ids.get("cpu_avg"))
        cpu_max_res = results.get(ids.get("cpu_max"))
        net_in_res = results.get(ids.get("net_in"))
        net_out_res = results.get(ids.get("net_out"))

        # Coverage guard: require sufficient datapoints for both CPU series.
        cpu_avg_count = _count_from_result(cpu_avg_res)
        cpu_max_count = _count_from_result(cpu_max_res)
        coverage = min(cpu_avg_count, cpu_max_count) / float(expected_points)
        if coverage < float(metrics_min_coverage):
            continue

        cpu_avg = _avg_from_result(cpu_avg_res)
        cpu_max = _max_from_result(cpu_max_res)  # FIX: max must be max, not avg

        net_in = _sum_from_result(net_in_res)
        net_out = _sum_from_result(net_out_res)
        net_avg_bps = (net_in + net_out) / seconds if seconds > 0 else 0.0

        if not (
            cpu_avg < float(cpu_avg_threshold)
            and cpu_max < float(cpu_max_threshold)
            and net_avg_bps < float(net_avg_bps_threshold)
        ):
            continue

        hr_price = _instance_hour_price(itype)
        est = const.HOURS_PER_MONTH * hr_price
        potential = est

        _collect_row(
            rows,
            {
                "resource_id": iid,
                "name": name or iid,
                "owner_id": config.ACCOUNT_ID,
                "resource_type": "EC2Instance",
                "region": region,
                "estimated_cost": est,
                "potential_saving": potential,
                "flags": ["EC2InstanceUnderutilized"],
                "confidence": 100,
                "signals": {
                    "Region": region,
                    "InstanceId": iid,
                    "Name": name,
                    "Type": itype,
                    "CPUAvg": round(cpu_avg, 3),
                    "CPUMax": round(cpu_max, 3),
                    "NetAvgBps": int(net_avg_bps),
                    "LookbackDays": int(lookback_days),
                    "MetricsCoverage": round(coverage, 3),
                    "MetricsPeriodSec": period,
                },
            },
        )


def _collect_stopped_long(
    rows: Dict[Tuple[str, str, str, str], Dict[str, Any]],
    *,
    ec2,
    region: str,
    stale_days: int,
    log: logging.Logger,
) -> None:
    """Collect stopped instances; include date-unknown findings instead of skipping."""
    cutoff = (datetime.now(timezone.utc) - timedelta(days=int(stale_days))).replace(microsecond=0)
    insts: List[Dict[str, Any]] = []
    try:
        paginator = ec2.get_paginator("describe_instances")
        for page in paginator.paginate(
            Filters=[{"Name": "instance-state-name", "Values": ["stopped"]}]
        ):
            for res in page.get("Reservations", []) or []:
                insts.extend(res.get("Instances", []) or [])
    except ClientError as exc:
        log.error("[ec2] describe_instances failed: %s", exc)
        return
    if not insts:
        return

    # Collect volume ids from block device mappings
    vol_ids: List[str] = []
    for inst in insts:
        for bdm in inst.get("BlockDeviceMappings", []) or []:
            ebs = bdm.get("Ebs") or {}
            vid = ebs.get("VolumeId")
            if vid:
                vol_ids.append(str(vid))
    vols_map = _describe_volumes_map(ec2, vol_ids, log)

    for inst in insts:
        iid = str(inst.get("InstanceId") or "")
        if not iid:
            continue
        itype = str(inst.get("InstanceType") or "")
        name = next(
            (t.get("Value") for t in inst.get("Tags", []) or [] if t.get("Key") == "Name"),
            "",
        ) or ""

        reason = inst.get("StateTransitionReason")
        stopped_at = _parse_stopped_time(str(reason) if reason else None)

        attached: List[str] = []
        est = 0.0
        for bdm in inst.get("BlockDeviceMappings", []) or []:
            ebs = bdm.get("Ebs") or {}
            vid = ebs.get("VolumeId")
            if not vid:
                continue
            attached.append(str(vid))
            est += _volume_monthly_cost(vols_map.get(str(vid), {}))

        # Two flavors:
        #   - Known stop time, older than cutoff -> actionable
        #   - Unknown stop time -> informational (avoid false positives)
        if stopped_at is None:
            _collect_row(
                rows,
                {
                    "resource_id": iid,
                    "name": name or iid,
                    "owner_id": config.ACCOUNT_ID,
                    "resource_type": "EC2Instance",
                    "region": region,
                    "estimated_cost": est,
                    "potential_saving": 0.0,
                    "flags": ["EC2InstanceStoppedDateUnknown"],
                    "confidence": 50,
                    "signals": {
                        "Region": region,
                        "InstanceId": iid,
                        "Name": name,
                        "Type": itype,
                        "StoppedAt": "NULL",
                        "StaleDays": int(stale_days),
                        "VolumeCount": len(attached),
                        "VolumeIds": ",".join(attached),
                        "StateTransitionReason": str(reason or ""),
                    },
                },
            )
            continue

        if stopped_at >= cutoff:
            continue

        _collect_row(
            rows,
            {
                "resource_id": iid,
                "name": name or iid,
                "owner_id": config.ACCOUNT_ID,
                "resource_type": "EC2Instance",
                "region": region,
                "estimated_cost": est,
                "potential_saving": est,
                "flags": ["EC2InstanceStoppedLong"],
                "confidence": 100,
                "signals": {
                    "Region": region,
                    "InstanceId": iid,
                    "Name": name,
                    "Type": itype,
                    "StoppedAt": _to_utc_iso(stopped_at),
                    "StaleDays": int(stale_days),
                    "VolumeCount": len(attached),
                    "VolumeIds": ",".join(attached),
                },
            },
        )


def _collect_old_generation(
    rows: Dict[Tuple[str, str, str, str], Dict[str, Any]],
    *,
    ec2,
    region: str,
    log: logging.Logger,
) -> None:
    insts: List[Dict[str, Any]] = []
    try:
        paginator = ec2.get_paginator("describe_instances")
        for page in paginator.paginate():
            for res in page.get("Reservations", []) or []:
                insts.extend(res.get("Instances", []) or [])
    except ClientError as exc:
        log.error("[ec2] describe_instances failed: %s", exc)
        return
    if not insts:
        return

    for inst in insts:
        iid = str(inst.get("InstanceId") or "")
        if not iid:
            continue
        itype = str(inst.get("InstanceType") or "").lower()
        fam = itype.split(".")[0] if "." in itype else itype
        name = next(
            (t.get("Value") for t in inst.get("Tags", []) or [] if t.get("Key") == "Name"),
            "",
        ) or ""

        flags: List[str] = []
        if fam in _OLD_LEGACY:
            flags.append("EC2InstanceLegacyGen")
        elif fam in _PREVIOUS_GEN:
            flags.append("EC2InstancePreviousGen")
        else:
            continue

        _collect_row(
            rows,
            {
                "resource_id": iid,
                "name": name or iid,
                "owner_id": config.ACCOUNT_ID,
                "resource_type": "EC2Instance",
                "region": region,
                "estimated_cost": 0.0,
                "potential_saving": 0.0,
                "flags": flags,
                "confidence": 100,
                "signals": {"Region": region, "InstanceId": iid, "Type": itype, "Family": fam},
            },
        )


def _collect_unused_security_groups(
    rows: Dict[Tuple[str, str, str, str], Dict[str, Any]],
    *,
    ec2,
    autoscaling,
    region: str,
    log: logging.Logger,
) -> None:
    """Collect unused SGs, excluding referenced by ENIs and (optionally) LT/LC."""
    # All SGs
    sgs: List[Dict[str, Any]] = []
    try:
        p = ec2.get_paginator("describe_security_groups")
        for page in p.paginate():
            sgs.extend(page.get("SecurityGroups", []) or [])
    except ClientError as exc:
        log.error("[ec2] describe_security_groups failed: %s", exc)
        return

    # All ENIs -> used SG ids
    used: Set[str] = set()
    try:
        p = ec2.get_paginator("describe_network_interfaces")
        for page in p.paginate():
            for eni in page.get("NetworkInterfaces", []) or []:
                for g in eni.get("Groups", []) or []:
                    gid = g.get("GroupId")
                    if gid:
                        used.add(str(gid))
    except ClientError as exc:
        log.error("[ec2] describe_network_interfaces failed: %s", exc)
        return

    # Optional: SG ids referenced by launch templates / launch configurations
    referenced_lt = _sg_ids_from_launch_templates(ec2, log)
    referenced_lc = _sg_ids_from_launch_configurations(autoscaling, log)
    referenced = referenced_lt.union(referenced_lc)

    for sg in sgs:
        gid = sg.get("GroupId")
        name = sg.get("GroupName") or gid
        if not gid or name == "default":
            continue
        gid_s = str(gid)
        if gid_s in used:
            continue
        if gid_s in referenced:
            # Safety: do not claim unused if referenced by templates/configs
            continue

        _collect_row(
            rows,
            {
                "resource_id": gid_s,
                "name": str(name or gid_s),
                "owner_id": config.ACCOUNT_ID,
                "resource_type": "EC2SecurityGroup",
                "region": region,
                "estimated_cost": 0.0,
                "potential_saving": 0.0,
                "flags": ["EC2SecurityGroupUnused"],
                "confidence": 100,
                "signals": {
                    "Region": region,
                    "GroupId": gid_s,
                    "Name": name,
                    "ExcludedByLaunchTemplate": False,
                    "ExcludedByLaunchConfig": False,
                },
            },
        )
