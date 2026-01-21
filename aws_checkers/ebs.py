"""AWS Checkers: EBS — volumes & snapshots.
"""

from __future__ import annotations

import concurrent.futures as cf
import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Set, Tuple

from botocore.exceptions import ClientError

from aws_checkers import config
from aws_checkers.common import (
    _logger,
    _to_utc_iso,
    tags_to_dict,
    tag_triplet,
    _safe_workers,
    iter_chunks,
)
from core.retry import retry_with_backoff
from core.cloudwatch import CloudWatchBatcher


# ------------------------------- module caches ------------------------------ #

_VOL_INV: Dict[int, List[Dict[str, Any]]] = {}
_SNAP_INV: Dict[int, List[Dict[str, Any]]] = {}
_AMI_SNAP_IDS: Dict[int, Set[str]] = {}
_SNAP_ATTRS: Dict[int, Dict[str, List[Dict[str, Any]]]] = {}  # client_id -> {sid: perms}


# ------------------------------ pricing helpers ---------------------------- #

def _p(service: str, key: str, default: float) -> float:
    return float(config.safe_price(service, key, default))


_EBS_GB_MONTH: Dict[str, float] = {
    "gp2": _p("EBS", "GP2_GB_MONTH", 0.10),
    "gp3": _p("EBS", "GP3_GB_MONTH", 0.08),
    "io1": _p("EBS", "IO1_GB_MONTH", 0.125),
    "io2": _p("EBS", "IO2_GB_MONTH", 0.125),
    "st1": _p("EBS", "ST1_GB_MONTH", 0.045),
    "sc1": _p("EBS", "SC1_GB_MONTH", 0.025),
    "standard": _p("EBS", "MAGNETIC_GB_MONTH", 0.05),
}

_SNAPSHOT_GB_MONTH = _p("EBS", "SNAPSHOT_GB_MONTH", 0.05)


# -------------------------------- tiny helpers ----------------------------- #

def _iso(dt_obj: Optional[datetime]) -> str:
    val = _to_utc_iso(dt_obj)
    return "" if val is None else val


def _extract_writer_ec2(
    args: Tuple[Any, ...],
    kwargs: Dict[str, Any],
) -> Tuple[Any, Any]:
    writer = kwargs.get("writer", args[0] if len(args) >= 1 else None)
    ec2 = kwargs.get("ec2", args[1] if len(args) >= 2 else None)
    if writer is None or ec2 is None:
        raise TypeError(
            f"Expected 'writer' and 'ec2' (got writer={writer!r}, ec2={ec2!r})"
        )
    return writer, ec2


def _extract_writer_ec2_cw(
    args: Tuple[Any, ...],
    kwargs: Dict[str, Any],
) -> Tuple[Any, Any, Optional[Any]]:
    writer, ec2 = _extract_writer_ec2(args, kwargs)
    cloudwatch = kwargs.get("cloudwatch", args[2] if len(args) >= 3 else None)
    return writer, ec2, cloudwatch


# ------------------------------- inventories ------------------------------- #

@retry_with_backoff(exceptions=(ClientError,))
def _ensure_volumes(ec2, log: logging.Logger) -> List[Dict[str, Any]]:
    key = id(ec2)
    if key in _VOL_INV:
        return _VOL_INV[key]

    vols: List[Dict[str, Any]] = []
    try:
        paginator = ec2.get_paginator("describe_volumes")
        for page in paginator.paginate():
            for v in page.get("Volumes", []) or []:
                vols.append(
                    {
                        "VolumeId": v.get("VolumeId"),
                        "State": v.get("State"),
                        "Size": v.get("Size"),
                        "VolumeType": (v.get("VolumeType") or "gp3"),
                        "Iops": v.get("Iops"),
                        "Throughput": v.get("Throughput"),
                        "Encrypted": bool(v.get("Encrypted")),
                        "Attachments": v.get("Attachments") or [],
                        "CreateTime": v.get("CreateTime"),
                        "Tags": v.get("Tags") or [],
                        "AvailabilityZone": v.get("AvailabilityZone"),
                    }
                )
    except ClientError as exc:
        log.error("[ebs] describe_volumes failed: %s", exc)

    _VOL_INV[key] = vols
    return vols


@retry_with_backoff(exceptions=(ClientError,))
def _ensure_snapshots(ec2, log: logging.Logger) -> List[Dict[str, Any]]:
    """One-time, per-client snapshot inventory (your snapshots only)."""
    key = id(ec2)
    if key in _SNAP_INV:
        return _SNAP_INV[key]

    snaps: List[Dict[str, Any]] = []
    try:
        paginator = ec2.get_paginator("describe_snapshots")
        for page in paginator.paginate(OwnerIds=["self"]):
            for s in page.get("Snapshots", []) or []:
                snaps.append(
                    {
                        "SnapshotId": s.get("SnapshotId"),
                        "Encrypted": bool(s.get("Encrypted")),
                        "KmsKeyId": s.get("KmsKeyId"),
                        "VolumeId": s.get("VolumeId"),
                        "VolumeSize": s.get("VolumeSize"),
                        "StartTime": s.get("StartTime"),
                        "Tags": s.get("Tags") or [],
                        "StorageTier": s.get("StorageTier"),
                        "State": s.get("State"),
                        "Progress": s.get("Progress"),
                    }
                )
    except ClientError as exc:
        log.error("[ebs] describe_snapshots failed: %s", exc)

    _SNAP_INV[key] = snaps
    return snaps


@retry_with_backoff(exceptions=(ClientError,))
def _ensure_ami_snapshot_ids(ec2, log: logging.Logger) -> Set[str]:
    key = id(ec2)
    if key in _AMI_SNAP_IDS:
        return _AMI_SNAP_IDS[key]

    used: Set[str] = set()
    try:
        paginator = ec2.get_paginator("describe_images")
        try:
            # Include self-owned AMIs and AMIs shared to this account (more conservative
            # for "orphan" detection).
            pages = paginator.paginate(ExecutableUsers=["self"])
        except ClientError:
            # Fallback for partitions/permissions where ExecutableUsers may fail.
            pages = paginator.paginate(Owners=["self"])

        for page in pages:
            for img in page.get("Images", []) or []:
                for bdm in img.get("BlockDeviceMappings", []) or []:
                    ebs = bdm.get("Ebs") or {}
                    sid = ebs.get("SnapshotId")
                    if sid:
                        used.add(str(sid))
    except ClientError as exc:
        log.error("[ebs] describe_images failed: %s", exc)

    _AMI_SNAP_IDS[key] = used
    return used


# ------------------- snapshot attributes (concurrent, cached) -------------- #

@retry_with_backoff(exceptions=(ClientError,))
def _get_cvperm(ec2, snapshot_id: str) -> List[Dict[str, Any]]:
    r = ec2.describe_snapshot_attribute(
        SnapshotId=snapshot_id, Attribute="createVolumePermission"
    )
    return r.get("CreateVolumePermissions", []) or []


def _ensure_snapshot_attrs(
    ec2,
    snapshot_ids: List[str],
    log: logging.Logger,
    max_workers: Optional[int],
) -> Dict[str, List[Dict[str, Any]]]:
    """Fetch snapshot permissions concurrently, with per-client caching."""
    key = id(ec2)
    cache = _SNAP_ATTRS.setdefault(key, {})
    needed = [sid for sid in snapshot_ids if sid not in cache]
    if not needed:
        return cache

    workers = _safe_workers(ec2, max_workers)
    chunk = max(1, workers * 8)

    for ids in iter_chunks(needed, chunk):
        with cf.ThreadPoolExecutor(max_workers=workers) as pool:
            futs = {pool.submit(_get_cvperm, ec2, sid): sid for sid in ids}
            for fut in cf.as_completed(futs):
                sid = futs[fut]
                try:
                    cache[sid] = list(fut.result())
                except ClientError as exc:
                    log.debug("[ebs] attr %s failed: %s", sid, exc)
                    cache[sid] = []
                except Exception as exc:  # pylint: disable=broad-except
                    log.debug("[ebs] attr worker %s error: %s", sid, exc)
                    cache[sid] = []

    return cache


# ----------------------------- cost estimators ----------------------------- #

def _volume_monthly_cost(vol: Dict[str, Any]) -> float:
    size = float(vol.get("Size") or 0.0)
    vtype = str(vol.get("VolumeType") or "gp3").lower()
    price = _EBS_GB_MONTH.get(vtype, _EBS_GB_MONTH["gp3"])
    return size * price


def _gp2_to_gp3_saving(vol: Dict[str, Any]) -> float:
    if str(vol.get("VolumeType", "")).lower() != "gp2":
        return 0.0
    size = float(vol.get("Size") or 0.0)
    return size * max(0.0, _EBS_GB_MONTH["gp2"] - _EBS_GB_MONTH["gp3"])


def _snapshot_upper_bound_monthly_cost(snap: Dict[str, Any]) -> float:
    """Upper-bound monthly cost estimate for a snapshot.

    EC2 does not expose the actual billable snapshot size (used blocks) via
    DescribeSnapshots, so using VolumeSize is a worst-case approximation.
    We keep this value as an *upper bound* and expose it in signals.
    """
    size_gib = float(snap.get("VolumeSize") or 0.0)
    return size_gib * _SNAPSHOT_GB_MONTH


def _is_managed_snapshot(tags: Dict[str, str]) -> bool:
    """Return True when snapshot is managed by AWS Backup / DLM policies."""
    # AWS Backup adds multiple aws:backup:* tags (recovery point ARN, job id, etc.)
    if any(k.startswith("aws:backup:") for k in tags):
        return True
    # DLM-managed snapshots commonly use aws:dlm:* (or sometimes dlm:*).
    if any(k.startswith("aws:dlm:") or k.startswith("dlm:") for k in tags):
        return True
    return False


# --------------------------------- checks --------------------------------- #

@retry_with_backoff(exceptions=(ClientError,))
def check_ebs_unattached_volumes(  # pylint: disable=unused-argument
    *args,
    logger: Optional[logging.Logger] = None,
    **kwargs,
) -> None:
    """Flag 'available' EBS volumes (not attached)."""
    log = _logger(kwargs.get("logger") or logger)
    try:
        writer, ec2 = _extract_writer_ec2(args, kwargs)
    except TypeError as exc:
        log.warning("[check_ebs_unattached_volumes] Skipping: %s", exc)
        return
    if not (config.ACCOUNT_ID and config.WRITE_ROW):
        log.warning("[check_ebs_unattached_volumes] Skipping: config not provided.")
        return

    region = getattr(getattr(ec2, "meta", None), "region_name", "") or ""
    for v in _ensure_volumes(ec2, log):
        if str(v.get("State")) != "available":
            continue
        tags = tags_to_dict(v.get("Tags"))
        app_id, app, env = tag_triplet(tags)
        est = _volume_monthly_cost(v)

        config.WRITE_ROW(
            writer=writer,
            resource_id=str(v.get("VolumeId")),
            name=str(v.get("VolumeId")),
            resource_type="EBSVolume",
            region=region,
            owner_id=config.ACCOUNT_ID,
            flags=["EBSUnattachedVolume"],
            estimated_cost=0.0,
            potential_saving=est,
            signals={
                "Region": region,
                "Type": v.get("VolumeType"),
                "Encrypted": bool(v.get("Encrypted")),
                "AZ": v.get("AvailabilityZone"),
            },
            state=str(v.get("State") or ""),
            creation_date=_iso(v.get("CreateTime")),
            storage_gb=float(v.get("Size") or 0.0),
            app_id=app_id,
            app=app,
            env=env,
        )

    log.info("[ebs] Completed check_ebs_unattached_volumes")


@retry_with_backoff(exceptions=(ClientError,))
def check_ebs_gp2_not_gp3(  # pylint: disable=unused-argument
    *args,
    logger: Optional[logging.Logger] = None,
    **kwargs,
) -> None:
    """Flag gp2 volumes as gp3 migration candidates; include potential saving."""
    log = _logger(kwargs.get("logger") or logger)
    try:
        writer, ec2 = _extract_writer_ec2(args, kwargs)
    except TypeError as exc:
        log.warning("[check_ebs_gp2_not_gp3] Skipping: %s", exc)
        return
    if not (config.ACCOUNT_ID and config.WRITE_ROW):
        log.warning("[check_ebs_gp2_not_gp3] Skipping: config not provided.")
        return

    region = getattr(getattr(ec2, "meta", None), "region_name", "") or ""
    for v in _ensure_volumes(ec2, log):
        if str(v.get("VolumeType")).lower() != "gp2":
            continue
        tags = tags_to_dict(v.get("Tags"))
        app_id, app, env = tag_triplet(tags)
        est = _volume_monthly_cost(v)
        pot = _gp2_to_gp3_saving(v)

        config.WRITE_ROW(
            writer=writer,
            resource_id=str(v.get("VolumeId")),
            name=str(v.get("VolumeId")),
            resource_type="EBSVolume",
            region=region,
            owner_id=config.ACCOUNT_ID,
            flags=["EBSGp2ToGp3Candidate"],
            estimated_cost=est,
            potential_saving=pot,
            signals={
                "Region": region,
                "Type": v.get("VolumeType"),
                "Encrypted": bool(v.get("Encrypted")),
                "AZ": v.get("AvailabilityZone"),
                "SavingPerGB": round(
                    max(0.0, _EBS_GB_MONTH["gp2"] - _EBS_GB_MONTH["gp3"]), 4
                ),
            },
            state=str(v.get("State") or ""),
            creation_date=_iso(v.get("CreateTime")),
            storage_gb=float(v.get("Size") or 0.0),
            app_id=app_id,
            app=app,
            env=env,
        )

    log.info("[ebs] Completed check_ebs_gp2_not_gp3")

@retry_with_backoff(exceptions=(ClientError,))
def check_ebs_unencrypted_volumes(  # pylint: disable=unused-argument
    *args,
    logger: Optional[logging.Logger] = None,
    **kwargs,
) -> None:
    """Flag unencrypted EBS volumes."""
    log = _logger(kwargs.get("logger") or logger)
    try:
        writer, ec2 = _extract_writer_ec2(args, kwargs)
    except TypeError as exc:
        log.warning("[check_ebs_unencrypted_volumes] Skipping: %s", exc)
        return
    if not (config.ACCOUNT_ID and config.WRITE_ROW):
        log.warning("[check_ebs_unencrypted_volumes] Skipping: config not provided.")
        return

    region = getattr(getattr(ec2, "meta", None), "region_name", "") or ""
    for v in _ensure_volumes(ec2, log):
        if bool(v.get("Encrypted")):
            continue
        tags = tags_to_dict(v.get("Tags"))
        app_id, app, env = tag_triplet(tags)
        est = _volume_monthly_cost(v)

        config.WRITE_ROW(
            writer=writer,
            resource_id=str(v.get("VolumeId")),
            name=str(v.get("VolumeId")),
            resource_type="EBSVolume",
            region=region,
            owner_id=config.ACCOUNT_ID,
            flags=["EBSVolumeUnencrypted"],
            estimated_cost=est,
            potential_saving=0.0,
            signals={"Region": region, "Type": v.get("VolumeType"), "AZ": v.get("AvailabilityZone")},
            state=str(v.get("State") or ""),
            creation_date=_iso(v.get("CreateTime")),
            storage_gb=float(v.get("Size") or 0.0),
            app_id=app_id,
            app=app,
            env=env,
        )

    log.info("[ebs] Completed check_ebs_unencrypted_volumes")


@retry_with_backoff(exceptions=(ClientError,))
def check_ebs_volumes_low_utilization(  # pylint: disable=unused-argument
    *args,
    logger: Optional[logging.Logger] = None,
    window_days: int = 7,
    **kwargs,
) -> None:
    """Heuristic: flag attached volumes with very low I/O in the lookback window."""
    log = _logger(kwargs.get("logger") or logger)
    try:
        writer, ec2, cw = _extract_writer_ec2_cw(args, kwargs)
    except TypeError as exc:
        log.warning("[check_ebs_volumes_low_utilization] Skipping: %s", exc)
        return
    if not (config.ACCOUNT_ID and config.WRITE_ROW):
        log.warning("[check_ebs_volumes_low_utilization] Skipping: config not provided.")
        return
    if CloudWatchBatcher is None or cw is None:
        log.debug("[ebs] CloudWatchBatcher unavailable; skipping low-util check.")
        return

    region = getattr(getattr(ec2, "meta", None), "region_name", "") or ""
    vols = [v for v in _ensure_volumes(ec2, log) if str(v.get("State")) == "in-use"]
    if not vols:
        log.info("[ebs] No in-use volumes for low-utilization check")
        return

    start = datetime.now(timezone.utc) - timedelta(days=int(window_days))
    end = datetime.now(timezone.utc)

    try:
        batch = CloudWatchBatcher(region=region, client=cw)
        for v in vols:
            vid = str(v.get("VolumeId"))
            dims = [("VolumeId", vid)]
            for metric in ("VolumeReadBytes", "VolumeWriteBytes",
                           "VolumeReadOps", "VolumeWriteOps"):
                batch.add_q(
                    id_hint=f"{metric}_{vid}",
                    namespace="AWS/EBS",
                    metric=metric,
                    dims=dims,
                    stat="Sum",
                    period=3600,
                )
        results = batch.execute(start=start, end=end)
    except ClientError as exc:
        log.debug("[ebs] CloudWatch metrics failed: %s", exc)
        return
    except Exception as exc:  # pylint: disable=broad-except
        log.debug("[ebs] CloudWatch batch error: %s", exc)
        return

    def _sum(mid: str) -> float:
        series = results.get(mid)
        if isinstance(series, list) and series:
            total = 0.0
            for item in series:
                try:
                    total += float(item[1])
                except Exception:  # pylint: disable=broad-except
                    continue
            return total
        if isinstance(series, dict):
            vals = series.get("Values") or []
            total = 0.0
            for v in vals:
                try:
                    total += float(v)
                except Exception:  # pylint: disable=broad-except
                    continue
            return total
        return 0.0

    for v in vols:
        vid = str(v.get("VolumeId"))
        rb = _sum(f"VolumeReadBytes_{vid}")
        wb = _sum(f"VolumeWriteBytes_{vid}")
        ro = _sum(f"VolumeReadOps_{vid}")
        wo = _sum(f"VolumeWriteOps_{vid}")

        # Very low across board (simple heuristic)
        hours = max(1, int(window_days) * 24)
        max_bytes = 5 * 1024 * 1024 * hours
        max_ops = 10 * hours
        if rb + wb > max_bytes or ro + wo > max_ops:
            continue

        tags = tags_to_dict(v.get("Tags"))
        app_id, app, env = tag_triplet(tags)
        est = _volume_monthly_cost(v)

        config.WRITE_ROW(
            writer=writer,
            resource_id=vid,
            name=vid,
            resource_type="EBSVolume",
            region=region,
            owner_id=config.ACCOUNT_ID,
            flags=["EBSLowUtilization"],
            estimated_cost=est,
            potential_saving=0.0,
            signals={
                "Region": region,
                "ReadBytes": int(rb),
                "WriteBytes": int(wb),
                "ReadOps": int(ro),
                "WriteOps": int(wo),
                "LookbackDays": int(window_days),
            },
            state=str(v.get("State") or ""),
            creation_date=_iso(v.get("CreateTime")),
            storage_gb=float(v.get("Size") or 0.0),
            app_id=app_id,
            app=app,
            env=env,
        )

    log.info("[ebs] Completed check_ebs_volumes_low_utilization")


@retry_with_backoff(exceptions=(ClientError,))
def check_ebs_snapshots_public_or_shared(  # pylint: disable=unused-argument
    *args,
    logger: Optional[logging.Logger] = None,
    max_workers: Optional[int] = None,
    **kwargs,
) -> None:
    """Flag EBS snapshots that are PUBLIC or shared with other accounts."""
    log = _logger(kwargs.get("logger") or logger)
    try:
        writer, ec2 = _extract_writer_ec2(args, kwargs)
    except TypeError as exc:
        log.warning("[check_ebs_snapshots_public_or_shared] Skipping: %s", exc)
        return
    if not (config.ACCOUNT_ID and config.WRITE_ROW):
        log.warning("[check_ebs_snapshots_public_or_shared] Skipping: config not provided.")
        return

    region = getattr(getattr(ec2, "meta", None), "region_name", "") or ""
    snaps = _ensure_snapshots(ec2, log)
    # Only completed snapshots with an id
    subset: List[Dict[str, Any]] = []
    for snap in snaps:
        if not (snap.get("SnapshotId") and snap.get("State") == "completed"):
            continue
        # Skip AWS-managed snapshots (Backup/DLM) to reduce API calls and noise.
        tags = tags_to_dict(snap.get("Tags"))
        if _is_managed_snapshot(tags):
            continue
        subset.append(snap)

    if not subset:
        log.info("[ebs] No eligible snapshots for public/shared check")
        return

    sid_list = [str(s["SnapshotId"]) for s in subset]
    attrs = _ensure_snapshot_attrs(ec2, sid_list, log, max_workers)

    for s in subset:
        sid = str(s["SnapshotId"])
        perms = attrs.get(sid, [])
        # 'public' only makes sense for unencrypted snaps
        is_public = (not bool(s.get("Encrypted"))) and any(p.get("Group") == "all" for p in perms)
        shared_to = [p.get("UserId") for p in perms if p.get("UserId")]
        shared_to = [x for x in shared_to if x and x != str(config.ACCOUNT_ID)]
        if not is_public and not shared_to:
            continue

        tags = tags_to_dict(s.get("Tags"))
        if _is_managed_snapshot(tags):
            continue
        app_id, app, env = tag_triplet(tags)

        flags: List[str] = []
        if is_public:
            flags.append("EBSSnapshotPublic")
        if shared_to and not is_public:
            flags.append("EBSSnapshotShared")
        if is_public and "EBSSnapshotShared" in flags:
            flags = ["EBSSnapshotPublic"]

        config.WRITE_ROW(
            writer=writer,
            resource_id=sid,
            name=sid,
            resource_type="EBSSnapshot",
            region=region,
            owner_id=config.ACCOUNT_ID,
            flags=flags,
            estimated_cost=0.0,
            potential_saving=0.0,
            signals={
                "Region": region,
                "KmsKeyId": s.get("KmsKeyId") or "NULL",
                "VolumeSizeGiB": s.get("VolumeSize"),
                "StorageTier": s.get("StorageTier") or "NULL",
                "SharedCount": len(shared_to),
                "SharedTo": ";".join(shared_to) if shared_to else "NULL",
                "Public": is_public,
            },
            state=str(s.get("State") or ""),
            creation_date=_iso(s.get("StartTime")),
            storage_gb=float(s.get("VolumeSize") or 0.0),
            app_id=app_id,
            app=app,
            env=env,
        )

    log.info("[ebs] Completed check_ebs_snapshots_public_or_shared")


@retry_with_backoff(exceptions=(ClientError,))
def check_ebs_snapshot_stale(  # pylint: disable=unused-argument
    *args,
    logger: Optional[logging.Logger] = None,
    lookback_days: int = 90,
    **kwargs,
) -> None:
    """Flag snapshots older than `lookback_days`."""
    log = _logger(kwargs.get("logger") or logger)
    try:
        writer, ec2 = _extract_writer_ec2(args, kwargs)
    except TypeError as exc:
        log.warning("[check_ebs_snapshot_stale] Skipping: %s", exc)
        return
    if not (config.ACCOUNT_ID and config.WRITE_ROW):
        log.warning("[check_ebs_snapshot_stale] Skipping: config not provided.")
        return

    region = getattr(getattr(ec2, "meta", None), "region_name", "") or ""
    cutoff = datetime.now(timezone.utc) - timedelta(days=int(lookback_days))
    for s in _ensure_snapshots(ec2, log):
        st = s.get("StartTime")
        if not isinstance(st, datetime):
            continue
        st = st if st.tzinfo else st.replace(tzinfo=timezone.utc)
        if st > cutoff:
            continue

        tags = tags_to_dict(s.get("Tags"))
        app_id, app, env = tag_triplet(tags)
        upper = _snapshot_upper_bound_monthly_cost(s)

        config.WRITE_ROW(
            writer=writer,
            resource_id=str(s.get("SnapshotId")),
            name=str(s.get("SnapshotId")),
            resource_type="EBSSnapshot",
            region=region,
            owner_id=config.ACCOUNT_ID,
            flags=["EBSSnapshotOld"],
            estimated_cost=0.0,
            potential_saving=upper,
            signals={
                "Region": region,
                "AgeDays": int((datetime.now(timezone.utc) - st).days),
                "StorageTier": s.get("StorageTier") or "NULL",
                "CostEstimation": "upper_bound_volume_size",
                "UpperBoundMonthlyCost": round(upper, 6),
            },
            state=str(s.get("State") or ""),
            creation_date=_iso(s.get("StartTime")),
            storage_gb=float(s.get("VolumeSize") or 0.0),
            app_id=app_id,
            app=app,
            env=env,
        )

    log.info("[ebs] Completed check_ebs_snapshot_stale")


@retry_with_backoff(exceptions=(ClientError,))
def check_ebs_orphan_snapshots(  # pylint: disable=unused-argument
    *args,
    logger: Optional[logging.Logger] = None,
    **kwargs,
) -> None:
    """Flag snapshots not referenced by AMIs you own."""
    log = _logger(kwargs.get("logger") or logger)
    try:
        writer, ec2 = _extract_writer_ec2(args, kwargs)
    except TypeError as exc:
        log.warning("[check_ebs_orphan_snapshots] Skipping: %s", exc)
        return
    if not (config.ACCOUNT_ID and config.WRITE_ROW):
        log.warning("[check_ebs_orphan_snapshots] Skipping: config not provided.")
        return

    region = getattr(getattr(ec2, "meta", None), "region_name", "") or ""
    used_ids = _ensure_ami_snapshot_ids(ec2, log)

    for s in _ensure_snapshots(ec2, log):
        sid = str(s.get("SnapshotId"))
        if not sid or sid in used_ids:
            continue

        tags = tags_to_dict(s.get("Tags"))
        app_id, app, env = tag_triplet(tags)
        upper = _snapshot_upper_bound_monthly_cost(s)

        config.WRITE_ROW(
            writer=writer,
            resource_id=sid,
            name=sid,
            resource_type="EBSSnapshot",
            region=region,
            owner_id=config.ACCOUNT_ID,
            flags=["EBSSnapshotOrphan"],
            estimated_cost=0.0,
            potential_saving=upper,
            signals={
                "Region": region,
                "CostEstimation": "upper_bound_volume_size",
                "UpperBoundMonthlyCost": round(upper, 6),
            },
            state=str(s.get("State") or ""),
            creation_date=_iso(s.get("StartTime")),
            storage_gb=float(s.get("VolumeSize") or 0.0),
            app_id=app_id,
            app=app,
            env=env,
            referenced_in="",
        )

    log.info("[ebs] Completed check_ebs_orphan_snapshots")
