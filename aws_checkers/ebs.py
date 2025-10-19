"""Checkers: Amazon EBS (Elastic Block Store).

Contains:
  - check_unattached_ebs_volumes: Volumes in 'available' state (likely waste).
  - check_ebs_low_activity_volumes: Attached volumes with no/low I/O in window.
  - check_ebs_gp2_to_gp3_migration: gp2 volumes with potential gp3 savings.
  - check_ebs_snapshots_old_or_orphaned: stale/orphan snapshots, archive suggestions.

Design:
  - Dependencies (account_id, write_row, get_price, logger) provided via
    finops_toolset.checkers.config.setup(...).
  - CloudWatch metrics via finops_toolset.cloudwatch.CloudWatchBatcher.
  - Each checker is tolerant to run_check calling style and to partial AWS failures.
  - Emits Flags, Signals (compact k=v), Estimated_Cost_USD, Potential_Saving_USD.
  - Datetimes are timezone-aware (datetime.now(timezone.utc)).
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple

from botocore.exceptions import ClientError

from aws_checkers import config
from core.retry import retry_with_backoff
from core.cloudwatch import CloudWatchBatcher


# ----------------------------- shared helpers ---------------------------- #

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
    """Accept writer/ec2/cloudwatch passed positionally or by keyword; prefer keywords."""
    writer = kwargs.get("writer", args[0] if len(args) >= 1 else None)
    ec2 = kwargs.get("ec2", args[1] if len(args) >= 2 else None)
    cloudwatch = kwargs.get("cloudwatch", args[2] if len(args) >= 3 else None)
    if writer is None or ec2 is None or cloudwatch is None:
        raise TypeError(
            "Expected 'writer', 'ec2' and 'cloudwatch' "
            f"(got writer={writer!r}, ec2={ec2!r}, cloudwatch={cloudwatch!r})"
        )
    return writer, ec2, cloudwatch


def _sum_from_result(res: Any) -> float:
    """Reduce CloudWatchBatcher result → sum of values (supports [(ts, val)])."""
    if res is None:
        return 0.0
    if isinstance(res, list) and res and isinstance(res[0], tuple):
        try:
            return float(sum(float(v) for _, v in res))
        except Exception:  # pylint: disable=broad-except
            return 0.0
    if isinstance(res, dict):
        values = res.get("Values") or res.get("values") or []
        try:
            return float(sum(values))
        except Exception:  # pylint: disable=broad-except
            return 0.0
    return 0.0


def _name_tag(tags: Optional[List[Dict[str, str]]]) -> Optional[str]:
    if not tags:
        return None
    for t in tags:
        if t.get("Key") == "Name":
            return t.get("Value")
    return None


def _volume_monthly_cost(vol: Dict[str, Any]) -> float:
    """Heuristic monthly cost estimate for an EBS volume."""
    vtype = (vol.get("VolumeType") or "").lower()
    size_gb = float(vol.get("Size") or 0)
    iops = int(vol.get("Iops") or 0)
    throughput = int(vol.get("Throughput") or 0)  # gp3 only

    # Per-GB prices (defaults safe to 0.0)
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

    # Provisioned IOPS/Throughput adders
    add = 0.0
    if vtype in {"io1", "io2"} and iops > 0:
        add += iops * (
            config.safe_price("EBS", "IO1_IOPS_MONTH", 0.0) if vtype == "io1"
            else config.safe_price("EBS", "IO2_IOPS_MONTH", 0.0)
        )
    if vtype == "gp3":
        extra_iops = max(0, iops - 3000)  # gp3 includes 3k IOPS
        extra_tp = max(0, throughput - 125)  # gp3 includes 125 MB/s
        if extra_iops > 0:
            add += extra_iops * config.safe_price("EBS", "GP3_IOPS_MONTH", 0.0)
        if extra_tp > 0:
            add += extra_tp * config.safe_price("EBS", "GP3_THROUGHPUT_MBPS_MONTH", 0.0)

    return base + add


def _gp2_to_gp3_saving(vol: Dict[str, Any]) -> float:
    """Estimate monthly saving from moving gp2 → gp3 (per-GB delta only)."""
    if (vol.get("VolumeType") or "").lower() != "gp2":
        return 0.0
    size_gb = float(vol.get("Size") or 0)
    gp2_gb = config.safe_price("EBS", "GP2_GB_MONTH", 0.0)
    gp3_gb = config.safe_price("EBS", "GP3_GB_MONTH", 0.0)
    delta = max(0.0, gp2_gb - gp3_gb)
    return size_gb * delta


# ----------------------- volumes: unattached (available) ------------------ #

@retry_with_backoff(exceptions=(ClientError,))
def check_unattached_ebs_volumes(  # pylint: disable=unused-argument
    *args,
    logger: Optional[logging.Logger] = None,
    **kwargs,
) -> None:
    """Flag EBS volumes in 'available' state (unattached)."""
    log = _logger(kwargs.get("logger") or logger)

    try:
        writer, ec2, cloudwatch = _extract_writer_ec2_cw(args, kwargs)  # cloudwatch unused but keeps signature consistent
    except TypeError as exc:
        log.warning("[check_unattached_ebs_volumes] Skipping: %s", exc)
        return
    if not (config.ACCOUNT_ID and config.WRITE_ROW and config.GET_PRICE):
        log.warning("[check_unattached_ebs_volumes] Skipping: checker config not provided.")
        return

    region = getattr(getattr(ec2, "meta", None), "region_name", "") or ""

    try:
        paginator = ec2.get_paginator("describe_volumes")
        for page in paginator.paginate(Filters=[{"Name": "status", "Values": ["available"]}]):
            for vol in page.get("Volumes", []) or []:
                vid = vol.get("VolumeId")
                if not vid:
                    continue

                name = _name_tag(vol.get("Tags"))
                size_gb = vol.get("Size")
                vtype = vol.get("VolumeType")
                encrypted = vol.get("Encrypted")

                est = _volume_monthly_cost(vol)
                # Unattached → assume full saving if deleted
                potential = est

                signals = _signals_str(
                    {
                        "Region": region,
                        "VolumeId": vid,
                        "Name": name or "",
                        "State": "available",
                        "VolumeType": vtype,
                        "SizeGB": size_gb,
                        "Encrypted": encrypted,
                    }
                )

                try:
                    # type: ignore[call-arg]
                    config.WRITE_ROW(
                        writer=writer,
                        resource_id=vid,
                        name=name or vid,
                        owner_id=config.ACCOUNT_ID,  # type: ignore[arg-type]
                        resource_type="EBSVolume",
                        estimated_cost=est,
                        potential_saving=potential,
                        flags=["EBSVolumeUnattached"],
                        confidence=100,
                        signals=signals,
                    )
                except Exception as exc:  # pylint: disable=broad-except
                    log.warning("[check_unattached_ebs_volumes] write_row failed for %s: %s", vid, exc)

                log.info("[check_unattached_ebs_volumes] Wrote volume: %s (size=%sGB type=%s)", vid, size_gb, vtype)

    except ClientError as exc:
        log.error("[check_unattached_ebs_volumes] describe_volumes failed: %s", exc)
        raise


# ---------------- volumes: low/zero activity while attached --------------- #

@retry_with_backoff(exceptions=(ClientError,))
def check_ebs_low_activity_volumes(  # pylint: disable=unused-argument
    *args,
    logger: Optional[logging.Logger] = None,
    lookback_days: int = 30,
    io_threshold_bytes: int = 0,
    **kwargs,
) -> None:
    """
    Flag attached volumes with no/low I/O across [now - lookback_days, now].

    Unused definition:
      Sum(VolumeReadBytes + VolumeWriteBytes) <= io_threshold_bytes

    We only set the flag when CloudWatch metrics are available; otherwise we log and skip.
    """
    log = _logger(kwargs.get("logger") or logger)

    try:
        writer, ec2, cloudwatch = _extract_writer_ec2_cw(args, kwargs)
    except TypeError as exc:
        log.warning("[check_ebs_low_activity_volumes] Skipping: %s", exc)
        return
    if not (config.ACCOUNT_ID and config.WRITE_ROW and config.GET_PRICE):
        log.warning("[check_ebs_low_activity_volumes] Skipping: checker config not provided.")
        return

    region = getattr(getattr(ec2, "meta", None), "region_name", "") or ""
    now_utc = datetime.now(timezone.utc).replace(microsecond=0)
    start_time = now_utc - timedelta(days=lookback_days)
    period = 3600  # 1 hour

    # Collect attached volumes
    vols: List[Dict[str, Any]] = []
    try:
        paginator = ec2.get_paginator("describe_volumes")
        for page in paginator.paginate(Filters=[{"Name": "status", "Values": ["in-use"]}]):
            vols.extend(page.get("Volumes", []) or [])
    except ClientError as exc:
        log.error("[check_ebs_low_activity_volumes] describe_volumes failed: %s", exc)
        return

    if not vols:
        return

    # CloudWatch batching
    metrics_ok = True
    results: Dict[str, Any] = {}
    id_map: Dict[str, Dict[str, str]] = {}
    try:
        cw_batch = CloudWatchBatcher(region=region, client=cloudwatch)
        for v in vols:
            vid = v.get("VolumeId")
            if not vid:
                continue
            rd_id = f"rd_{vid}"
            wr_id = f"wr_{vid}"
            dims = [("VolumeId", vid)]

            cw_batch.add_q(id_hint=rd_id, namespace="AWS/EBS", metric="VolumeReadBytes", dims=dims, stat="Sum", period=period)
            cw_batch.add_q(id_hint=wr_id, namespace="AWS/EBS", metric="VolumeWriteBytes", dims=dims, stat="Sum", period=period)
            id_map[vid] = {"rd": rd_id, "wr": wr_id}

        results = cw_batch.execute(start=start_time, end=now_utc)
    except ClientError as exc:
        log.warning("[check_ebs_low_activity_volumes] CloudWatch metrics unavailable: %s", exc)
        metrics_ok = False
    except Exception as exc:  # pylint: disable=broad-except
        log.warning("[check_ebs_low_activity_volumes] CloudWatch batch error: %s", exc)
        metrics_ok = False

    if not metrics_ok:
        return  # avoid false positives

    for v in vols:
        vid = v.get("VolumeId")
        if not vid:
            continue

        vtype = v.get("VolumeType")
        size_gb = v.get("Size")
        encrypted = v.get("Encrypted")
        attach = (v.get("Attachments") or [{}])[0]
        instance_id = attach.get("InstanceId")

        ids = id_map.get(vid, {})
        read_series = results.get(ids.get("rd"))
        write_series = results.get(ids.get("wr"))
        total_io = _sum_from_result(read_series) + _sum_from_result(write_series)

        if total_io <= float(io_threshold_bytes):
            est = _volume_monthly_cost(v)
            potential = est  # heuristic: if truly unused, full savings possible

            name = _name_tag(v.get("Tags"))
            signals = _signals_str(
                {
                    "Region": region,
                    "VolumeId": vid,
                    "Name": name or "",
                    "VolumeType": vtype,
                    "SizeGB": size_gb,
                    "Encrypted": encrypted,
                    "InstanceId": instance_id or "",
                    "TotalIOBytesSum": int(total_io),
                    "LookbackDays": lookback_days,
                }
            )

            try:
                # type: ignore[call-arg]
                config.WRITE_ROW(
                    writer=writer,
                    resource_id=vid,
                    name=name or vid,
                    owner_id=config.ACCOUNT_ID,  # type: ignore[arg-type]
                    resource_type="EBSVolume",
                    estimated_cost=est,
                    potential_saving=potential,
                    flags=["EBSVolumeLowActivity"],
                    confidence=100,
                    signals=signals,
                )
            except Exception as exc:  # pylint: disable=broad-except
                log.warning("[check_ebs_low_activity_volumes] write failed for %s: %s", vid, exc)

            log.info("[check_ebs_low_activity_volumes] Wrote low-activity volume: %s (size=%sGB type=%s)", vid, size_gb, vtype)


# ------------------------ volumes: gp2 → gp3 savings ---------------------- #

@retry_with_backoff(exceptions=(ClientError,))
def check_ebs_gp2_to_gp3_migration(  # pylint: disable=unused-argument
    *args,
    logger: Optional[logging.Logger] = None,
    **kwargs,
) -> None:
    """Flag gp2 volumes and estimate monthly savings if migrated to gp3."""
    log = _logger(kwargs.get("logger") or logger)

    try:
        writer, ec2, cloudwatch = _extract_writer_ec2_cw(args, kwargs)  # cloudwatch unused
    except TypeError as exc:
        log.warning("[check_ebs_gp2_to_gp3_migration] Skipping: %s", exc)
        return
    if not (config.ACCOUNT_ID and config.WRITE_ROW and config.GET_PRICE):
        log.warning("[check_ebs_gp2_to_gp3_migration] Skipping: checker config not provided.")
        return

    region = getattr(getattr(ec2, "meta", None), "region_name", "") or ""

    try:
        paginator = ec2.get_paginator("describe_volumes")
        for page in paginator.paginate(Filters=[{"Name": "volume-type", "Values": ["gp2"]}]):
            for vol in page.get("Volumes", []) or []:
                vid = vol.get("VolumeId")
                if not vid:
                    continue

                est = _volume_monthly_cost(vol)
                saving = _gp2_to_gp3_saving(vol)
                if saving <= 0.0:
                    continue  # nothing to report

                name = _name_tag(vol.get("Tags"))
                size_gb = vol.get("Size")
                encrypted = vol.get("Encrypted")

                # attached?
                attached = bool(vol.get("Attachments"))

                signals = _signals_str(
                    {
                        "Region": region,
                        "VolumeId": vid,
                        "Name": name or "",
                        "VolumeType": "gp2",
                        "SizeGB": size_gb,
                        "Encrypted": encrypted,
                        "Attached": attached,
                        "EstMonthly": round(est, 2),
                        "EstSavingIfGp3": round(saving, 2),
                    }
                )

                try:
                    # type: ignore[call-arg]
                    config.WRITE_ROW(
                        writer=writer,
                        resource_id=vid,
                        name=name or vid,
                        owner_id=config.ACCOUNT_ID,  # type: ignore[arg-type]
                        resource_type="EBSVolume",
                        estimated_cost=est,
                        potential_saving=saving,
                        flags=["EBSVolumeUseGp2"],
                        confidence=100,
                        signals=signals,
                    )
                except Exception as exc:  # pylint: disable=broad-except
                    log.warning("[GP2->GP3] write_row failed for %s: %s", vid, exc)

                log.info("[GP2->GP3] Wrote gp2 volume: %s (size=%sGB)", vid, size_gb)

    except ClientError as exc:
        log.error("[GP2->GP3] describe_volumes failed: %s", exc)
        raise


# ------------------- snapshots: stale and/or orphaned -------------------- #

def _list_all_volume_ids(ec2, log: logging.Logger) -> set[str]:
    ids: set[str] = set()
    try:
        paginator = ec2.get_paginator("describe_volumes")
        for page in paginator.paginate():
            for v in page.get("Volumes", []) or []:
                vid = v.get("VolumeId")
                if vid:
                    ids.add(vid)
    except ClientError as exc:
        log.debug("[ebs snapshots] describe_volumes failed: %s", exc)
    return ids


@retry_with_backoff(exceptions=(ClientError,))
def check_ebs_snapshots_old_or_orphaned(  # pylint: disable=unused-argument
    *args,
    logger: Optional[logging.Logger] = None,
    stale_days: int = 90,
    archive_recommend_days: int = 180,
    **kwargs,
) -> None:
    """
    Flag EBS snapshots that are:
      - Orphaned (source volume no longer exists) → EbsSnapshotOrphaned
      - Old (StartTime older than stale_days) → EbsSnapshotStale
      - Standard tier & old enough to archive → EbsSnapshotArchiveCandidate

    Estimated cost uses VolumeSize * price per GB-month (heuristic).
    Potential saving = estimated_cost for orphaned/stale.
    Archive candidate saving = (std_price - archive_price) * VolumeSize.
    """
    log = _logger(kwargs.get("logger") or logger)

    try:
        writer, ec2, cloudwatch = _extract_writer_ec2_cw(args, kwargs)  # cloudwatch unused
    except TypeError as exc:
        log.warning("[check_ebs_snapshots_old_or_orphaned] Skipping: %s", exc)
        return
    if not (config.ACCOUNT_ID and config.WRITE_ROW and config.GET_PRICE):
        log.warning("[check_ebs_snapshots_old_or_orphaned] Skipping: checker config not provided.")
        return

    region = getattr(getattr(ec2, "meta", None), "region_name", "") or ""
    cutoff = (datetime.now(timezone.utc) - timedelta(days=stale_days)).replace(microsecond=0)

    price_std = config.safe_price("EBS", "SNAPSHOT_STANDARD_GB_MONTH", 0.0)
    price_arch = config.safe_price("EBS", "SNAPSHOT_ARCHIVE_GB_MONTH", 0.0)

    existing_vol_ids = _list_all_volume_ids(ec2, log)

    try:
        paginator = ec2.get_paginator("describe_snapshots")
        # OwnerIds param avoids scanning public snapshots
        for page in paginator.paginate(OwnerIds=["self"]):
            for snap in page.get("Snapshots", []) or []:
                sid = snap.get("SnapshotId")
                if not sid:
                    continue

                vol_id = snap.get("VolumeId")
                size_gb = float(snap.get("VolumeSize") or 0)
                start: Optional[datetime] = snap.get("StartTime")
                tier = (snap.get("StorageTier") or "standard").lower()
                enc = snap.get("Encrypted")
                prog = snap.get("Progress")
                state = snap.get("State")

                created_iso = _to_utc_iso(start)
                is_old = bool(isinstance(start, datetime) and (start if start.tzinfo else start.replace(tzinfo=timezone.utc)) < cutoff)
                is_orphan = bool(vol_id and (vol_id not in existing_vol_ids))

                est = size_gb * (price_arch if tier == "archive" else price_std)
                potential = est if (is_old or is_orphan) else 0.0

                flags: List[str] = []
                if is_orphan:
                    flags.append("EbsSnapshotOrphaned")
                if is_old:
                    flags.append("EbsSnapshotStale")
                # archive recommendation
                if (tier == "standard") and isinstance(start, datetime):
                    age_days = (datetime.now(timezone.utc) - (start if start.tzinfo else start.replace(tzinfo=timezone.utc))).days
                    if age_days >= int(archive_recommend_days):
                        flags.append("EbsSnapshotArchiveCandidate")

                if not flags:
                    continue

                # Archive saving (delta between std and archive) if applicable
                if "EbsSnapshotArchiveCandidate" in flags and price_std > price_arch:
                    potential = max(potential, size_gb * (price_std - price_arch))

                signals = _signals_str(
                    {
                        "Region": region,
                        "SnapshotId": sid,
                        "VolumeId": vol_id or "",
                        "SizeGB": int(size_gb),
                        "Tier": tier,
                        "Encrypted": enc,
                        "State": state,
                        "Progress": prog,
                        "StartTime": created_iso,
                        "StaleDays": stale_days,
                        "ArchiveSuggestDays": archive_recommend_days,
                        "Orphan": is_orphan,
                    }
                )

                try:
                    # type: ignore[call-arg]
                    config.WRITE_ROW(
                        writer=writer,
                        resource_id=sid,
                        name=sid,
                        owner_id=config.ACCOUNT_ID,  # type: ignore[arg-type]
                        resource_type="EBSSnapshot",
                        estimated_cost=est,
                        potential_saving=potential,
                        flags=flags,
                        confidence=100,
                        signals=signals,
                    )
                except Exception as exc:  # pylint: disable=broad-except
                    log.warning("[EBS_Old_Orphaned] write_row failed for %s: %s", sid, exc)

                log.info("[EBS_Old_Orphaned] Wrote snapshot: %s (flags=%s)", sid, flags)

    except ClientError as exc:
        log.error("[EBS_Old_Orphaned] describe_snapshots failed: %s", exc)
        raise
