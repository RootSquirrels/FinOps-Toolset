"""Checkers: Amazon EBS — volumes & snapshots (fast, tagged, no duplicates).

Highlights
- Single-pass inventories for volumes, snapshots, and AMI-used snapshots (per EC2 client).
- Concurrent snapshot attribute fetch for PUBLIC/SHARED detection (bounded pool).
- Tag enrichment via CSV columns: app_id / app / env (NOT in Signals).
- f-strings, ≤100 chars/line, pylint-friendly.
- No-regression: legacy checker name aliases preserved.

"""

from __future__ import annotations

import concurrent.futures as cf
import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

from botocore.exceptions import ClientError

from aws_checkers import config
from core.retry import retry_with_backoff
from core.cloudwatch import CloudWatchBatcher 


# ------------------------------- module state ------------------------------ #

_VOL_INV: Dict[int, List[Dict[str, Any]]] = {}
_SNAP_INV: Dict[int, List[Dict[str, Any]]] = {}
_AMI_SNAP_IDS: Dict[int, Set[str]] = {}


# ------------------------------- price helpers ----------------------------- #

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


# ------------------------------- tiny helpers ------------------------------ #

def _logger(fallback: Optional[logging.Logger]) -> logging.Logger:
    return fallback or config.LOGGER or logging.getLogger(__name__)


def _nonnull(s: Optional[str]) -> str:
    return "NULL" if not s else s


def _tags_to_dict(pairs: Optional[List[Dict[str, str]]]) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for t in pairs or []:
        k, v = t.get("Key"), t.get("Value")
        if k:
            out[str(k)] = "" if v is None else str(v)
    return out


def _pick_tag(tags: Dict[str, str], keys: Iterable[str]) -> Optional[str]:
    low = {k.lower(): v for k, v in tags.items()}
    for k in keys:
        v = low.get(str(k).lower())
        if v:
            return v
    return None


def _tag_triplet(tags: Dict[str, str]) -> Tuple[str, str, str]:
    app_id = _pick_tag(tags, ["app_id", "application_id", "app-id"])
    app = _pick_tag(tags, ["app", "application", "service"])
    env = _pick_tag(tags, ["environment", "env", "stage"])
    return _nonnull(app_id), _nonnull(app), _nonnull(env)


def _signals_str(pairs: Dict[str, object]) -> str:
    parts: List[str] = []
    for k, v in pairs.items():
        if v is None or v == "":
            continue
        parts.append(f"{k}={v}")
    return " | ".join(parts)


def _iso(dt: Optional[datetime]) -> str:
    if not isinstance(dt, datetime):
        return ""
    d = dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    return d.replace(microsecond=0).isoformat()


def _write_row(  # noqa: D401
    *,
    writer,
    resource_id: str,
    resource_type: str,
    name: str,
    region: str,
    flags: List[str],
    estimated_cost: float = 0.0,
    potential_saving: float = 0.0,
    signals: Dict[str, object],
    logger: logging.Logger,
    state: str = "",
    creation_date: str = "",
    storage_gb: float = 0.0,
    app_id: str = "NULL",
    app: str = "NULL",
    env: str = "NULL",
    referenced_in: str = "",
    object_count: Optional[int] = None,
) -> None:
    """Safely write one normalized row via the toolset writer."""
    try:
        # type: ignore[call-arg]
        config.WRITE_ROW(
            writer=writer,
            resource_id=resource_id,
            name=name,
            resource_type=resource_type,
            owner_id=config.ACCOUNT_ID,  # type: ignore[arg-type]
            state=state,
            creation_date=creation_date,
            storage_gb=storage_gb,
            estimated_cost=float(estimated_cost),
            app_id=app_id,
            app=app,
            env=env,
            referenced_in=referenced_in,
            flags=flags,
            object_count=object_count if object_count is not None else "",
            potential_saving=float(potential_saving),
            confidence=100,
            signals=_signals_str(signals),
        )
    except Exception as exc:  # pylint: disable=broad-except
        logger.warning(f"[ebs] write_row failed for {resource_id}: {exc}")


def _extract_writer_ec2(
    args: Tuple[Any, ...],
    kwargs: Dict[str, Any],
) -> Tuple[Any, Any]:
    writer = kwargs.get("writer", args[0] if len(args) >= 1 else None)
    ec2 = kwargs.get("ec2", args[1] if len(args) >= 2 else None)
    if writer is None or ec2 is None:
        raise TypeError(f"Expected 'writer' and 'ec2' (got writer={writer!r}, ec2={ec2!r})")
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
def _inventory_volumes(ec2, log: logging.Logger) -> List[Dict[str, Any]]:
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
        log.error(f"[ebs] describe_volumes failed: {exc}")
    _VOL_INV[key] = vols
    return vols


@retry_with_backoff(exceptions=(ClientError,))
def _inventory_snapshots(ec2, log: logging.Logger) -> List[Dict[str, Any]]:
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
        log.error(f"[ebs] describe_snapshots failed: {exc}")
    _SNAP_INV[key] = snaps
    return snaps


@retry_with_backoff(exceptions=(ClientError,))
def _ami_snapshot_ids(ec2, log: logging.Logger) -> Set[str]:
    key = id(ec2)
    if key in _AMI_SNAP_IDS:
        return _AMI_SNAP_IDS[key]
    used: Set[str] = set()
    try:
        paginator = ec2.get_paginator("describe_images")
        for page in paginator.paginate(Owners=["self"]):
            for img in page.get("Images", []) or []:
                for bdm in img.get("BlockDeviceMappings", []) or []:
                    ebs = bdm.get("Ebs") or {}
                    sid = ebs.get("SnapshotId")
                    if sid:
                        used.add(str(sid))
    except ClientError as exc:
        log.error(f"[ebs] describe_images failed: {exc}")
    _AMI_SNAP_IDS[key] = used
    return used


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


def _snapshot_monthly_cost_guesstimate(snap: Dict[str, Any]) -> float:
    size = float(snap.get("VolumeSize") or 0.0)
    return size * _SNAPSHOT_GB_MONTH


# ------------------- snapshot attributes (concurrent) --------------------- #

@retry_with_backoff(exceptions=(ClientError,))
def _get_cvperm(ec2, snapshot_id: str) -> List[Dict[str, Any]]:
    r = ec2.describe_snapshot_attribute(
        SnapshotId=snapshot_id, Attribute="createVolumePermission"
    )
    return r.get("CreateVolumePermissions", []) or []


def _fetch_attrs_concurrent(
    ec2,
    snapshot_ids: List[str],
    log: logging.Logger,
    max_workers: int,
) -> Dict[str, List[Dict[str, Any]]]:
    out: Dict[str, List[Dict[str, Any]]] = {}
    if not snapshot_ids:
        return out
    with cf.ThreadPoolExecutor(max_workers=max_workers) as pool:
        futs = {pool.submit(_get_cvperm, ec2, sid): sid for sid in snapshot_ids}
        for fut in cf.as_completed(futs):
            sid = futs[fut]
            try:
                out[sid] = list(fut.result())
            except ClientError as exc:
                log.debug(f"[ebs] attribute fetch {sid} failed: {exc}")
                out[sid] = []
            except Exception as exc:  # pylint: disable=broad-except
                log.debug(f"[ebs] attribute worker {sid} error: {exc}")
                out[sid] = []
    return out


# -------------------------------- checkers -------------------------------- #

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
        log.warning(f"[check_ebs_unattached_volumes] Skipping: {exc}")
        return
    if not (config.ACCOUNT_ID and config.WRITE_ROW):
        log.warning("[check_ebs_unattached_volumes] Skipping: checker config not provided.")
        return

    region = getattr(getattr(ec2, "meta", None), "region_name", "") or ""
    for v in _inventory_volumes(ec2, log):
        if str(v.get("State")) != "available":
            continue
        tags = _tags_to_dict(v.get("Tags"))
        app_id, app, env = _tag_triplet(tags)
        est = _volume_monthly_cost(v)
        _write_row(
            writer=writer,
            resource_id=str(v.get("VolumeId")),
            resource_type="EBSVolume",
            name=str(v.get("VolumeId")),
            region=region,
            flags=["EBSUnattachedVolume"],
            estimated_cost=est,
            potential_saving=est,
            signals={
                "Region": region,
                "Type": v.get("VolumeType"),
                "Encrypted": bool(v.get("Encrypted")),
                "AZ": v.get("AvailabilityZone"),
            },
            logger=log,
            state=str(v.get("State") or ""),
            creation_date=_iso(v.get("CreateTime")),
            storage_gb=float(v.get("Size") or 0.0),
            app_id=app_id,
            app=app,
            env=env,
        )
        log.info(f"[ebs] Wrote unattached volume: {v.get('VolumeId')}")


@retry_with_backoff(exceptions=(ClientError,))
def check_ebs_gp2_to_gp3_candidates(  # pylint: disable=unused-argument
    *args,
    logger: Optional[logging.Logger] = None,
    **kwargs,
) -> None:
    """Flag gp2 volumes as gp3 migration candidates; include potential saving."""
    log = _logger(kwargs.get("logger") or logger)
    try:
        writer, ec2 = _extract_writer_ec2(args, kwargs)
    except TypeError as exc:
        log.warning(f"[check_ebs_gp2_to_gp3_candidates] Skipping: {exc}")
        return
    if not (config.ACCOUNT_ID and config.WRITE_ROW):
        log.warning("[check_ebs_gp2_to_gp3_candidates] Skipping: checker config not provided.")
        return

    region = getattr(getattr(ec2, "meta", None), "region_name", "") or ""
    for v in _inventory_volumes(ec2, log):
        if str(v.get("VolumeType")).lower() != "gp2":
            continue
        tags = _tags_to_dict(v.get("Tags"))
        app_id, app, env = _tag_triplet(tags)
        est = _volume_monthly_cost(v)
        pot = _gp2_to_gp3_saving(v)
        _write_row(
            writer=writer,
            resource_id=str(v.get("VolumeId")),
            resource_type="EBSVolume",
            name=str(v.get("VolumeId")),
            region=region,
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
            logger=log,
            state=str(v.get("State") or ""),
            creation_date=_iso(v.get("CreateTime")),
            storage_gb=float(v.get("Size") or 0.0),
            app_id=app_id,
            app=app,
            env=env,
        )
        log.info(f"[ebs] Wrote gp2→gp3 candidate: {v.get('VolumeId')}")


# Legacy alias (no regression)
def check_ebs_gp2_not_gp3(*args, **kwargs) -> None:  # noqa: D401
    """Alias of :func:`check_ebs_gp2_to_gp3_candidates`."""
    return check_ebs_gp2_to_gp3_candidates(*args, **kwargs)


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
        log.warning(f"[check_ebs_unencrypted_volumes] Skipping: {exc}")
        return
    if not (config.ACCOUNT_ID and config.WRITE_ROW):
        log.warning("[check_ebs_unencrypted_volumes] Skipping: checker config not provided.")
        return

    region = getattr(getattr(ec2, "meta", None), "region_name", "") or ""
    for v in _inventory_volumes(ec2, log):
        if bool(v.get("Encrypted")):
            continue
        tags = _tags_to_dict(v.get("Tags"))
        app_id, app, env = _tag_triplet(tags)
        est = _volume_monthly_cost(v)
        _write_row(
            writer=writer,
            resource_id=str(v.get("VolumeId")),
            resource_type="EBSVolume",
            name=str(v.get("VolumeId")),
            region=region,
            flags=["EBSVolumeUnencrypted"],
            estimated_cost=est,
            potential_saving=0.0,
            signals={
                "Region": region,
                "Type": v.get("VolumeType"),
                "AZ": v.get("AvailabilityZone"),
            },
            logger=log,
            state=str(v.get("State") or ""),
            creation_date=_iso(v.get("CreateTime")),
            storage_gb=float(v.get("Size") or 0.0),
            app_id=app_id,
            app=app,
            env=env,
        )
        log.info(f"[ebs] Wrote unencrypted volume: {v.get('VolumeId')}")


@retry_with_backoff(exceptions=(ClientError,))
def check_ebs_volumes_low_utilization(  # pylint: disable=unused-argument
    *args,
    logger: Optional[logging.Logger] = None,
    window_days: int = 7,
    **kwargs,
) -> None:
    """Heuristic: flag volumes with very low I/O over the lookback window."""
    log = _logger(kwargs.get("logger") or logger)
    try:
        writer, ec2, cw = _extract_writer_ec2_cw(args, kwargs)
    except TypeError as exc:
        log.warning(f"[check_ebs_volumes_low_utilization] Skipping: {exc}")
        return
    if not (config.ACCOUNT_ID and config.WRITE_ROW):
        log.warning("[check_ebs_volumes_low_utilization] Skipping: checker config not provided.")
        return
    if CloudWatchBatcher is None or cw is None:
        log.debug("[ebs] CloudWatchBatcher unavailable; skipping low-util check.")
        return

    region = getattr(getattr(ec2, "meta", None), "region_name", "") or ""
    vols = [v for v in _inventory_volumes(ec2, log) if str(v.get("State")) == "in-use"]
    if not vols:
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
        log.debug(f"[ebs] CloudWatch metrics failed: {exc}")
        return
    except Exception as exc:  # pylint: disable=broad-except
        log.debug(f"[ebs] CloudWatch batch error: {exc}")
        return

    def _last_val(mid: str) -> float:
        r = results.get(mid)
        if isinstance(r, list) and r:
            try:
                return float(r[-1][1])
            except Exception:  # pylint: disable=broad-except
                return 0.0
        if isinstance(r, dict):
            vals = r.get("Values") or []
            return float(vals[-1]) if vals else 0.0
        return 0.0

    for v in vols:
        vid = str(v.get("VolumeId"))
        rb = _last_val(f"VolumeReadBytes_{vid}")
        wb = _last_val(f"VolumeWriteBytes_{vid}")
        ro = _last_val(f"VolumeReadOps_{vid}")
        wo = _last_val(f"VolumeWriteOps_{vid}")

        if rb + wb > 5 * 1024 * 1024 or ro + wo > 10:
            continue

        tags = _tags_to_dict(v.get("Tags"))
        app_id, app, env = _tag_triplet(tags)
        est = _volume_monthly_cost(v)

        _write_row(
            writer=writer,
            resource_id=vid,
            resource_type="EBSVolume",
            name=vid,
            region=region,
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
            logger=log,
            state=str(v.get("State") or ""),
            creation_date=_iso(v.get("CreateTime")),
            storage_gb=float(v.get("Size") or 0.0),
            app_id=app_id,
            app=app,
            env=env,
        )
        log.info(f"[ebs] Wrote low-utilization volume: {vid}")


@retry_with_backoff(exceptions=(ClientError,))
def check_ebs_snapshots_public_or_shared(  # pylint: disable=unused-argument
    *args,
    logger: Optional[logging.Logger] = None,
    max_workers: int = 16,
    **kwargs,
) -> None:
    """Flag EBS snapshots that are PUBLIC or shared with other accounts."""
    log = _logger(kwargs.get("logger") or logger)
    try:
        writer, ec2 = _extract_writer_ec2(args, kwargs)
    except TypeError as exc:
        log.warning(f"[check_ebs_snapshots_public_or_shared] Skipping: {exc}")
        return
    if not (config.ACCOUNT_ID and config.WRITE_ROW):
        log.warning("[check_ebs_snapshots_public_or_shared] Skipping: config not provided.")
        return

    snaps = _inventory_snapshots(ec2, log)
    if not snaps:
        return
    sid_list = [s["SnapshotId"] for s in snaps if s.get("SnapshotId")]
    attrs = _fetch_attrs_concurrent(ec2, sid_list, log, int(max_workers))

    region = getattr(getattr(ec2, "meta", None), "region_name", "") or ""
    for s in snaps:
        sid = s.get("SnapshotId")
        if not sid:
            continue
        perms = attrs.get(sid, [])
        is_public = any(p.get("Group") == "all" for p in perms)
        shared_to = [p.get("UserId") for p in perms if p.get("UserId")]
        shared_to = [x for x in shared_to if x and x != str(config.ACCOUNT_ID)]
        if not is_public and not shared_to:
            continue

        tags = _tags_to_dict(s.get("Tags"))
        app_id, app, env = _tag_triplet(tags)

        flags: List[str] = []
        if is_public:
            flags.append("EBSSnapshotPublic")
        if shared_to and not is_public:
            flags.append("EBSSnapshotShared")
        if is_public and "EBSSnapshotShared" in flags:
            flags = ["EBSSnapshotPublic"]

        _write_row(
            writer=writer,
            resource_id=str(sid),
            resource_type="EBSSnapshot",
            name=str(sid),
            region=region,
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
            logger=log,
            state=str(s.get("State") or ""),
            creation_date=_iso(s.get("StartTime")),
            storage_gb=float(s.get("VolumeSize") or 0.0),
            app_id=app_id,
            app=app,
            env=env,
        )
        log.info(
            f"[ebs] Wrote snapshot {sid} "
            f"({'public' if is_public else 'shared'})"
        )


@retry_with_backoff(exceptions=(ClientError,))
def check_ebs_snapshots_old(  # pylint: disable=unused-argument
    *args,
    logger: Optional[logging.Logger] = None,
    lookback_days: int = 90,
    **kwargs,
) -> None:
    """Flag snapshots older than ``lookback_days``."""
    log = _logger(kwargs.get("logger") or logger)
    try:
        writer, ec2 = _extract_writer_ec2(args, kwargs)
    except TypeError as exc:
        log.warning(f"[check_ebs_snapshots_old] Skipping: {exc}")
        return
    if not (config.ACCOUNT_ID and config.WRITE_ROW):
        log.warning("[check_ebs_snapshots_old] Skipping: checker config not provided.")
        return

    region = getattr(getattr(ec2, "meta", None), "region_name", "") or ""
    cutoff = datetime.now(timezone.utc) - timedelta(days=int(lookback_days))
    for s in _inventory_snapshots(ec2, log):
        st = s.get("StartTime")
        if not isinstance(st, datetime):
            continue
        st = st if st.tzinfo else st.replace(tzinfo=timezone.utc)
        if st > cutoff:
            continue
        tags = _tags_to_dict(s.get("Tags"))
        app_id, app, env = _tag_triplet(tags)
        est = _snapshot_monthly_cost_guesstimate(s)
        _write_row(
            writer=writer,
            resource_id=str(s.get("SnapshotId")),
            resource_type="EBSSnapshot",
            name=str(s.get("SnapshotId")),
            region=region,
            flags=["EBSSnapshotOld"],
            estimated_cost=est,
            potential_saving=est,
            signals={
                "Region": region,
                "AgeDays": int((datetime.now(timezone.utc) - st).days),
                "StorageTier": s.get("StorageTier") or "NULL",
            },
            logger=log,
            state=str(s.get("State") or ""),
            creation_date=_iso(s.get("StartTime")),
            storage_gb=float(s.get("VolumeSize") or 0.0),
            app_id=app_id,
            app=app,
            env=env,
        )
        log.info(f"[ebs] Wrote old snapshot: {s.get('SnapshotId')}")


# Legacy alias (no regression)
def check_ebs_snapshot_stale(*args, **kwargs) -> None:  # noqa: D401
    """Alias of :func:`check_ebs_snapshots_old`."""
    return check_ebs_snapshots_old(*args, **kwargs)


@retry_with_backoff(exceptions=(ClientError,))
def check_ebs_snapshots_unreferenced(  # pylint: disable=unused-argument
    *args,
    logger: Optional[logging.Logger] = None,
    **kwargs,
) -> None:
    """Flag snapshots not referenced by AMIs you own."""
    log = _logger(kwargs.get("logger") or logger)
    try:
        writer, ec2 = _extract_writer_ec2(args, kwargs)
    except TypeError as exc:
        log.warning(f"[check_ebs_snapshots_unreferenced] Skipping: {exc}")
        return
    if not (config.ACCOUNT_ID and config.WRITE_ROW):
        log.warning("[check_ebs_snapshots_unreferenced] Skipping: config not provided.")
        return

    region = getattr(getattr(ec2, "meta", None), "region_name", "") or ""
    used_ids = _ami_snapshot_ids(ec2, log)
    for s in _inventory_snapshots(ec2, log):
        sid = str(s.get("SnapshotId"))
        if not sid or sid in used_ids:
            continue
        tags = _tags_to_dict(s.get("Tags"))
        app_id, app, env = _tag_triplet(tags)
        est = _snapshot_monthly_cost_guesstimate(s)
        _write_row(
            writer=writer,
            resource_id=sid,
            resource_type="EBSSnapshot",
            name=sid,
            region=region,
            flags=["EBSSnapshotUnreferenced"],
            estimated_cost=est,
            potential_saving=est,
            signals={"Region": region},
            logger=log,
            state=str(s.get("State") or ""),
            creation_date=_iso(s.get("StartTime")),
            storage_gb=float(s.get("VolumeSize") or 0.0),
            app_id=app_id,
            app=app,
            env=env,
            referenced_in="",
        )
        log.info(f"[ebs] Wrote unreferenced snapshot: {sid}")


# Legacy alias (no regression)
def check_ebs_orphan_snapshots(*args, **kwargs) -> None:  # noqa: D401
    """Alias of :func:`check_ebs_snapshots_unreferenced`."""
    return check_ebs_snapshots_unreferenced(*args, **kwargs)
