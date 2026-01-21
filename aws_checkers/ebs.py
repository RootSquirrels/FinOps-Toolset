"""AWS Checkers: EBS — volumes & snapshots.
"""

from __future__ import annotations

import atexit
import concurrent.futures as cf
import logging
from datetime import datetime, timedelta, timezone
from threading import Lock
from typing import Any, Dict, List, Optional, Set, Tuple

from botocore.exceptions import ClientError

from aws_checkers import config
from aws_checkers.common import (
    _logger,
    _to_utc_iso,
    iter_chunks,
    tag_triplet,
    tags_to_dict,
    _safe_workers,
)
from core.retry import retry_with_backoff
from core.cloudwatch import CloudWatchBatcher


# ------------------------------- module caches ------------------------------ #

_VOL_INV: Dict[int, List[Dict[str, Any]]] = {}
_SNAP_INV: Dict[int, List[Dict[str, Any]]] = {}
_AMI_SNAP_IDS: Dict[int, Set[str]] = {}
_SNAP_ATTRS: Dict[int, Dict[str, List[Dict[str, Any]]]] = {}  # client_id -> {sid: perms}


# ------------------------------ unified writer ------------------------------ #

_UNIFIED_LOCK = Lock()
_UNIFIED_WRITERS: Dict[Tuple[Any, int], "UnifiedRowWriter"] = {}
_UNIFIED_REGISTERED = False


def _writer_identity(writer: Any) -> Tuple[Any, int]:
    """
    Attempt to derive a stable identity for the *output target* behind `writer`.
    This helps unify outputs even if the profiler creates a new DictWriter per check.
    """
    # Common patterns: csv.DictWriter has .writer (csv writer), may have .f / .fp / .stream.
    for attr in ("f", "fp", "stream", "file", "buffer", "raw"):
        stream = getattr(writer, attr, None)
        if stream is not None:
            return (type(writer), id(stream))

    inner = getattr(writer, "writer", None)
    if inner is not None:
        for attr in ("f", "fp", "stream", "file", "buffer", "raw"):
            stream = getattr(inner, attr, None)
            if stream is not None:
                return (type(writer), id(stream))
        return (type(writer), id(inner))

    return (type(writer), id(writer))


def _merge_flags(existing: List[str], incoming: List[str]) -> List[str]:
    if not incoming:
        return existing
    if not existing:
        return list(incoming)
    seen = set(existing)
    merged = list(existing)
    for f in incoming:
        if f not in seen:
            merged.append(f)
            seen.add(f)
    return merged


def _merge_signals(existing: Dict[str, Any], incoming: Dict[str, Any]) -> Dict[str, Any]:
    if not incoming:
        return existing
    if not existing:
        return dict(incoming)
    merged = dict(existing)
    # Prefer existing value unless it's empty/"NULL"
    for k, v in incoming.items():
        if k not in merged:
            merged[k] = v
            continue
        cur = merged.get(k)
        if cur in (None, "", "NULL") and v not in (None, "", "NULL"):
            merged[k] = v
    return merged


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


class UnifiedRowWriter:
    """
    Wrap a CSV writer-like object and unify duplicate resources across checks.
    Rows are buffered & merged, then flushed once at interpreter exit.

    This avoids duplicate lines in the final CSV when the same resource is flagged
    by multiple checks.
    """

    __slots__ = ("_base", "_rows", "_flushed", "_lock")

    def __init__(self, base_writer: Any) -> None:
        self._base = base_writer
        self._rows: Dict[Tuple[str, str, str, str], Dict[str, Any]] = {}
        self._flushed = False
        self._lock = Lock()

    def writerow(self, row: Dict[str, Any]) -> None:
        """
        Buffer the row. If a row already exists for the same resource key,
        merge flags/signals and keep the max costs to avoid double counting.
        """
        rid = str(row.get("resource_id") or "")
        rtype = str(row.get("resource_type") or "")
        region = str(row.get("region") or "")
        owner = str(row.get("owner_id") or "")
        key = (rid, rtype, region, owner)

        with self._lock:
            existing = self._rows.get(key)
            if existing is None:
                self._rows[key] = dict(row)
                # normalize flags/signals if present
                if "flags" in self._rows[key] and self._rows[key]["flags"] is None:
                    self._rows[key]["flags"] = []
                if "signals" in self._rows[key] and self._rows[key]["signals"] is None:
                    self._rows[key]["signals"] = {}
                return

            # Merge flags
            existing_flags = existing.get("flags") or []
            incoming_flags = row.get("flags") or []
            existing["flags"] = _merge_flags(list(existing_flags), list(incoming_flags))

            # Merge signals
            existing_signals = existing.get("signals") or {}
            incoming_signals = row.get("signals") or {}
            existing["signals"] = _merge_signals(
                dict(existing_signals), dict(incoming_signals)
            )

            # Costs: keep max to avoid double counting across checks
            existing["estimated_cost"] = _max_float(
                existing.get("estimated_cost"), row.get("estimated_cost")
            )
            existing["potential_saving"] = _max_float(
                existing.get("potential_saving"), row.get("potential_saving")
            )

            # Prefer existing non-empty fields; fill gaps from incoming row
            for k, v in row.items():
                if k in ("flags", "signals", "estimated_cost", "potential_saving"):
                    continue
                cur = existing.get(k)
                if cur in (None, "", "NULL") and v not in (None, "", "NULL"):
                    existing[k] = v

    def writerows(self, rows: List[Dict[str, Any]]) -> None:
        for r in rows:
            self.writerow(r)

    def flush(self) -> None:
        """Flush buffered unified rows to the underlying writer once."""
        with self._lock:
            if self._flushed:
                return
            self._flushed = True
            # Stable-ish output order: by resource_type then resource_id
            for _, row in sorted(
                self._rows.items(), key=lambda kv: (kv[0][1], kv[0][0])
            ):
                self._base.writerow(row)

    def __getattr__(self, name: str) -> Any:
        # Delegate any other attribute access to the base writer
        return getattr(self._base, name)


def _flush_all_unified_writers() -> None:
    with _UNIFIED_LOCK:
        writers = list(_UNIFIED_WRITERS.values())
    for uw in writers:
        try:
            uw.flush()
        except Exception:  # pylint: disable=broad-except
            # Avoid crashing at interpreter shutdown
            continue


def _unified_writer(writer: Any) -> UnifiedRowWriter:
    global _UNIFIED_REGISTERED  # pylint: disable=global-statement
    ident = _writer_identity(writer)
    with _UNIFIED_LOCK:
        uw = _UNIFIED_WRITERS.get(ident)
        if uw is None:
            uw = UnifiedRowWriter(writer)
            _UNIFIED_WRITERS[ident] = uw
        if not _UNIFIED_REGISTERED:
            atexit.register(_flush_all_unified_writers)
            _UNIFIED_REGISTERED = True
    return uw


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
        for page in paginator.paginate(Owners=["self"]):
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


def _snapshot_monthly_cost_guesstimate(snap: Dict[str, Any]) -> float:
    size = float(snap.get("VolumeSize") or 0.0)
    return size * _SNAPSHOT_GB_MONTH


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

    uwriter = _unified_writer(writer)
    region = getattr(getattr(ec2, "meta", None), "region_name", "") or ""
    for v in _ensure_volumes(ec2, log):
        if str(v.get("State")) != "available":
            continue
        tags = tags_to_dict(v.get("Tags"))
        app_id, app, env = tag_triplet(tags)
        est = _volume_monthly_cost(v)

        config.WRITE_ROW(
            writer=uwriter,
            resource_id=str(v.get("VolumeId")),
            name=str(v.get("VolumeId")),
            resource_type="EBSVolume",
            region=region,
            owner_id=config.ACCOUNT_ID,
            flags=["EBSUnattachedVolume"],
            estimated_cost=est,
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

    uwriter = _unified_writer(writer)
    region = getattr(getattr(ec2, "meta", None), "region_name", "") or ""
    for v in _ensure_volumes(ec2, log):
        if str(v.get("VolumeType")).lower() != "gp2":
            continue
        tags = tags_to_dict(v.get("Tags"))
        app_id, app, env = tag_triplet(tags)
        est = _volume_monthly_cost(v)
        pot = _gp2_to_gp3_saving(v)

        config.WRITE_ROW(
            writer=uwriter,
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

    uwriter = _unified_writer(writer)
    region = getattr(getattr(ec2, "meta", None), "region_name", "") or ""
    for v in _ensure_volumes(ec2, log):
        if bool(v.get("Encrypted")):
            continue
        tags = tags_to_dict(v.get("Tags"))
        app_id, app, env = tag_triplet(tags)
        est = _volume_monthly_cost(v)

        config.WRITE_ROW(
            writer=uwriter,
            resource_id=str(v.get("VolumeId")),
            name=str(v.get("VolumeId")),
            resource_type="EBSVolume",
            region=region,
            owner_id=config.ACCOUNT_ID,
            flags=["EBSVolumeUnencrypted"],
            estimated_cost=est,
            potential_saving=0.0,
            signals={
                "Region": region,
                "Type": v.get("VolumeType"),
                "AZ": v.get("AvailabilityZone"),
            },
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

    uwriter = _unified_writer(writer)
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
            for metric in (
                "VolumeReadBytes",
                "VolumeWriteBytes",
                "VolumeReadOps",
                "VolumeWriteOps",
            ):
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

    def _last(mid: str) -> float:
        series = results.get(mid)
        if isinstance(series, list) and series:
            try:
                return float(series[-1][1])
            except Exception:  # pylint: disable=broad-except
                return 0.0
        if isinstance(series, dict):
            vals = series.get("Values") or []
            return float(vals[-1]) if vals else 0.0
        return 0.0

    for v in vols:
        vid = str(v.get("VolumeId"))
        rb = _last(f"VolumeReadBytes_{vid}")
        wb = _last(f"VolumeWriteBytes_{vid}")
        ro = _last(f"VolumeReadOps_{vid}")
        wo = _last(f"VolumeWriteOps_{vid}")

        # Very low across board (simple heuristic)
        if rb + wb > 5 * 1024 * 1024 or ro + wo > 10:
            continue

        tags = tags_to_dict(v.get("Tags"))
        app_id, app, env = tag_triplet(tags)
        est = _volume_monthly_cost(v)

        config.WRITE_ROW(
            writer=uwriter,
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

    uwriter = _unified_writer(writer)
    region = getattr(getattr(ec2, "meta", None), "region_name", "") or ""
    snaps = _ensure_snapshots(ec2, log)
    subset = [s for s in snaps if s.get("SnapshotId") and s.get("State") == "completed"]
    if not subset:
        log.info("[ebs] No eligible snapshots for public/shared check")
        return

    sid_list = [str(s["SnapshotId"]) for s in subset]
    attrs = _ensure_snapshot_attrs(ec2, sid_list, log, max_workers)

    for s in subset:
        sid = str(s["SnapshotId"])
        perms = attrs.get(sid, [])
        is_public = (not bool(s.get("Encrypted"))) and any(
            p.get("Group") == "all" for p in perms
        )
        shared_to = [p.get("UserId") for p in perms if p.get("UserId")]
        shared_to = [x for x in shared_to if x and x != str(config.ACCOUNT_ID)]
        if not is_public and not shared_to:
            continue

        tags = tags_to_dict(s.get("Tags"))
        app_id, app, env = tag_triplet(tags)

        flags: List[str] = []
        if is_public:
            flags.append("EBSSnapshotPublic")
        if shared_to and not is_public:
            flags.append("EBSSnapshotShared")
        if is_public and "EBSSnapshotShared" in flags:
            flags = ["EBSSnapshotPublic"]

        config.WRITE_ROW(
            writer=uwriter,
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

    uwriter = _unified_writer(writer)
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
        est = _snapshot_monthly_cost_guesstimate(s)

        config.WRITE_ROW(
            writer=uwriter,
            resource_id=str(s.get("SnapshotId")),
            name=str(s.get("SnapshotId")),
            resource_type="EBSSnapshot",
            region=region,
            owner_id=config.ACCOUNT_ID,
            flags=["EBSSnapshotOld"],
            estimated_cost=est,
            potential_saving=est,
            signals={
                "Region": region,
                "AgeDays": int((datetime.now(timezone.utc) - st).days),
                "StorageTier": s.get("StorageTier") or "NULL",
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

    uwriter = _unified_writer(writer)
    region = getattr(getattr(ec2, "meta", None), "region_name", "") or ""
    used_ids = _ensure_ami_snapshot_ids(ec2, log)

    for s in _ensure_snapshots(ec2, log):
        sid = str(s.get("SnapshotId"))
        if not sid or sid in used_ids:
            continue

        tags = tags_to_dict(s.get("Tags"))
        app_id, app, env = tag_triplet(tags)
        est = _snapshot_monthly_cost_guesstimate(s)

        config.WRITE_ROW(
            writer=uwriter,
            resource_id=sid,
            name=sid,
            resource_type="EBSSnapshot",
            region=region,
            owner_id=config.ACCOUNT_ID,
            flags=["EBSSnapshotOrphan"],
            estimated_cost=est,
            potential_saving=est,
            signals={"Region": region},
            state=str(s.get("State") or ""),
            creation_date=_iso(s.get("StartTime")),
            storage_gb=float(s.get("VolumeSize") or 0.0),
            app_id=app_id,
            app=app,
            env=env,
            referenced_in="",
        )

    log.info("[ebs] Completed check_ebs_orphan_snapshots")
