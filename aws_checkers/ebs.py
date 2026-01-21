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


def _is_managed_snapshot(tags: Dict[str, str]) -> bool:
    # AWS Backup
    if any(k.startswith("aws:backup:") for k in tags):
        return True
    # AWS DLM (some orgs use aws:dlm:*, others dlm:*)
    if any(k.startswith("aws:dlm:") or k.startswith("dlm:") for k in tags):
        return True
    return False


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

_EBS_ALREADY_RAN: Set[Tuple[int, str, str]] = set()


def _writer_key(writer: Any) -> int:
    """Best-effort stable identity for the underlying output stream."""
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


def _merge_signals(
    existing: Dict[str, Any],
    incoming: Dict[str, Any],
) -> Dict[str, Any]:
    if not incoming:
        return existing
    if not existing:
        return dict(incoming)
    for k, v in incoming.items():
        if k not in existing:
            existing[k] = v
            continue
        if existing.get(k) in (None, "", "NULL") and v not in (None, "", "NULL"):
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
    """Collect/merge a finding row for unique output (one row per resource)."""
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
        list(existing.get("flags") or []), list(row.get("flags") or [])
    )
    existing["signals"] = _merge_signals(
        dict(existing.get("signals") or {}), dict(row.get("signals") or {})
    )
    existing["estimated_cost"] = _max_float(
        existing.get("estimated_cost"), row.get("estimated_cost")
    )
    existing["potential_saving"] = _max_float(
        existing.get("potential_saving"), row.get("potential_saving")
    )

    for k, v in row.items():
        if k in ("flags", "signals", "estimated_cost", "potential_saving"):
            continue
        cur = existing.get(k)
        if cur in (None, "", "NULL") and v not in (None, "", "NULL"):
            existing[k] = v


def _cw_low_util_rows(
    cloudwatch,
    vols: List[Dict[str, Any]],
    region: str,
    window_days: int,
    log: logging.Logger,
) -> List[Dict[str, Any]]:
    if CloudWatchBatcher is None or cloudwatch is None:
        return []

    in_use = [v for v in vols if str(v.get("State")) == "in-use"]
    if not in_use:
        return []

    start = datetime.now(timezone.utc) - timedelta(days=int(window_days))
    end = datetime.now(timezone.utc)

    try:
        batch = CloudWatchBatcher(region=region, client=cloudwatch)
        for v in in_use:
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
    except Exception as exc:  # pylint: disable=broad-except
        log.debug("[ebs] CloudWatch batch failed: %s", exc)
        return []

    def _last(mid: str) -> float:
        series = results.get(mid)
        if isinstance(series, list) and series:
            try:
                return float(series[-1][1])
            except Exception:  # pylint: disable=broad-except
                return 0.0
        if isinstance(series, dict):
            vals = series.get("Values") or []
            try:
                return float(vals[-1]) if vals else 0.0
            except Exception:  # pylint: disable=broad-except
                return 0.0
        return 0.0

    out: List[Dict[str, Any]] = []
    for v in in_use:
        vid = str(v.get("VolumeId"))
        rb = _last(f"VolumeReadBytes_{vid}")
        wb = _last(f"VolumeWriteBytes_{vid}")
        ro = _last(f"VolumeReadOps_{vid}")
        wo = _last(f"VolumeWriteOps_{vid}")

        # Same heuristic as before
        if rb + wb > 5 * 1024 * 1024 or ro + wo > 10:
            continue

        tags = tags_to_dict(v.get("Tags"))
        app_id, app, env = tag_triplet(tags)
        est = _volume_monthly_cost(v)

        out.append(
            {
                "resource_id": vid,
                "name": vid,
                "resource_type": "EBSVolume",
                "region": region,
                "owner_id": config.ACCOUNT_ID,
                "flags": ["EBSLowUtilization"],
                "estimated_cost": est,
                "potential_saving": 0.0,
                "signals": {
                    "Region": region,
                    "ReadBytes": int(rb),
                    "WriteBytes": int(wb),
                    "ReadOps": int(ro),
                    "WriteOps": int(wo),
                    "LookbackDays": int(window_days),
                },
                "state": str(v.get("State") or ""),
                "creation_date": _iso(v.get("CreateTime")),
                "storage_gb": float(v.get("Size") or 0.0),
                "app_id": app_id,
                "app": app,
                "env": env,
            }
        )
    return out


@retry_with_backoff(exceptions=(ClientError,))
def check_ebs_volumes_and_snapshots(  # pylint: disable=unused-argument
    *args,
    logger: Optional[logging.Logger] = None,
    lookback_days: int = 90,
    window_days: int = 7,
    max_workers: Optional[int] = None,
    **kwargs,
) -> None:
    """
    Global EBS checker (KMS-style): computes all EBS volume & snapshot flags
    and writes *one row per resource* (no duplicates across sub-checks).

    Preferred entrypoint.
    """
    log = _logger(kwargs.get("logger") or logger)

    try:
        writer, ec2, cloudwatch = _extract_writer_ec2_cw(args, kwargs)
    except TypeError:
        try:
            writer, ec2 = _extract_writer_ec2(args, kwargs)
            cloudwatch = kwargs.get("cloudwatch", None)
        except TypeError as exc:
            log.warning("[check_ebs_volumes_and_snapshots] Skipping: %s", exc)
            return

    if not (config.ACCOUNT_ID and config.WRITE_ROW):
        log.warning("[check_ebs_volumes_and_snapshots] Skipping: config not provided.")
        return

    region = getattr(getattr(ec2, "meta", None), "region_name", "") or ""
    run_key = (_writer_key(writer), region, str(config.ACCOUNT_ID))
    if run_key in _EBS_ALREADY_RAN:
        log.info("[ebs] Skipping duplicate EBS run for %s", region)
        return
    _EBS_ALREADY_RAN.add(run_key)

    rows: Dict[Tuple[str, str, str, str], Dict[str, Any]] = {}

    vols = _ensure_volumes(ec2, log)
    snaps = _ensure_snapshots(ec2, log)

    # ------------------------------ volume checks ------------------------------ #

    for v in vols:
        vid = str(v.get("VolumeId") or "")
        if not vid:
            continue

        tags = tags_to_dict(v.get("Tags"))
        app_id, app, env = tag_triplet(tags)
        est = _volume_monthly_cost(v)

        if str(v.get("State")) == "available":
            _collect_row(
                rows,
                {
                    "resource_id": vid,
                    "name": vid,
                    "resource_type": "EBSVolume",
                    "region": region,
                    "owner_id": config.ACCOUNT_ID,
                    "flags": ["EBSUnattachedVolume"],
                    "estimated_cost": est,
                    "potential_saving": est,
                    "signals": {
                        "Region": region,
                        "Type": v.get("VolumeType"),
                        "Encrypted": bool(v.get("Encrypted")),
                        "AZ": v.get("AvailabilityZone"),
                    },
                    "state": str(v.get("State") or ""),
                    "creation_date": _iso(v.get("CreateTime")),
                    "storage_gb": float(v.get("Size") or 0.0),
                    "app_id": app_id,
                    "app": app,
                    "env": env,
                },
            )

        if str(v.get("VolumeType") or "").lower() == "gp2":
            pot = _gp2_to_gp3_saving(v)
            _collect_row(
                rows,
                {
                    "resource_id": vid,
                    "name": vid,
                    "resource_type": "EBSVolume",
                    "region": region,
                    "owner_id": config.ACCOUNT_ID,
                    "flags": ["EBSGp2ToGp3Candidate"],
                    "estimated_cost": est,
                    "potential_saving": pot,
                    "signals": {
                        "Region": region,
                        "Type": v.get("VolumeType"),
                        "Encrypted": bool(v.get("Encrypted")),
                        "AZ": v.get("AvailabilityZone"),
                        "SavingPerGB": round(
                            max(0.0, _EBS_GB_MONTH["gp2"] - _EBS_GB_MONTH["gp3"]), 4
                        ),
                    },
                    "state": str(v.get("State") or ""),
                    "creation_date": _iso(v.get("CreateTime")),
                    "storage_gb": float(v.get("Size") or 0.0),
                    "app_id": app_id,
                    "app": app,
                    "env": env,
                },
            )

        if not bool(v.get("Encrypted")):
            _collect_row(
                rows,
                {
                    "resource_id": vid,
                    "name": vid,
                    "resource_type": "EBSVolume",
                    "region": region,
                    "owner_id": config.ACCOUNT_ID,
                    "flags": ["EBSVolumeUnencrypted"],
                    "estimated_cost": est,
                    "potential_saving": 0.0,
                    "signals": {
                        "Region": region,
                        "Type": v.get("VolumeType"),
                        "AZ": v.get("AvailabilityZone"),
                    },
                    "state": str(v.get("State") or ""),
                    "creation_date": _iso(v.get("CreateTime")),
                    "storage_gb": float(v.get("Size") or 0.0),
                    "app_id": app_id,
                    "app": app,
                    "env": env,
                },
            )

    # CW low util check (optional)
    for r in _cw_low_util_rows(cloudwatch, vols, region, window_days, log):
        _collect_row(rows, r)

    # ------------------------------ snapshot checks ---------------------------- #

    used_ids = _ensure_ami_snapshot_ids(ec2, log)

    eligible_snaps = [
        s for s in snaps
        if s.get("SnapshotId") and s.get("State") == "completed"
    ]
    sid_list = [str(s["SnapshotId"]) for s in eligible_snaps]
    attrs = _ensure_snapshot_attrs(ec2, sid_list, log, max_workers) if sid_list else {}

    cutoff = datetime.now(timezone.utc) - timedelta(days=int(lookback_days))

    for s in snaps:
        sid = str(s.get("SnapshotId") or "")
        if not sid:
            continue

        tags = tags_to_dict(s.get("Tags"))
        app_id, app, env = tag_triplet(tags)
        est = _snapshot_monthly_cost_guesstimate(s)

        st = s.get("StartTime")
        if isinstance(st, datetime):
            st_dt = st if st.tzinfo else st.replace(tzinfo=timezone.utc)
            if st_dt < cutoff:
                _collect_row(
                    rows,
                    {
                        "resource_id": sid,
                        "name": sid,
                        "resource_type": "EBSSnapshot",
                        "region": region,
                        "owner_id": config.ACCOUNT_ID,
                        "flags": ["EBSSnapshotOld"],
                        "estimated_cost": est,
                        "potential_saving": est,
                        "signals": {
                            "Region": region,
                            "AgeDays": int((datetime.now(timezone.utc) - st_dt).days),
                            "StorageTier": s.get("StorageTier") or "NULL",
                        },
                        "state": str(s.get("State") or ""),
                        "creation_date": _iso(s.get("StartTime")),
                        "storage_gb": float(s.get("VolumeSize") or 0.0),
                        "app_id": app_id,
                        "app": app,
                        "env": env,
                    },
                )

        if sid not in used_ids and not _is_managed_snapshot(tags):
            _collect_row(
                rows,
                {
                    "resource_id": sid,
                    "name": sid,
                    "resource_type": "EBSSnapshot",
                    "region": region,
                    "owner_id": config.ACCOUNT_ID,
                    "flags": ["EBSSnapshotOrphan"],
                    "estimated_cost": est,
                    "potential_saving": est,
                    "signals": {"Region": region},
                    "state": str(s.get("State") or ""),
                    "creation_date": _iso(s.get("StartTime")),
                    "storage_gb": float(s.get("VolumeSize") or 0.0),
                    "app_id": app_id,
                    "app": app,
                    "env": env,
                    "referenced_in": "",
                },
            )

        if s.get("State") == "completed":
            perms = attrs.get(sid, [])
            is_public = (not bool(s.get("Encrypted"))) and any(
                p.get("Group") == "all" for p in perms
            )
            shared_to = [p.get("UserId") for p in perms if p.get("UserId")]
            shared_to = [x for x in shared_to if x and x != str(config.ACCOUNT_ID)]
            if is_public or shared_to:
                flags: List[str] = []
                if is_public:
                    flags.append("EBSSnapshotPublic")
                if shared_to and not is_public:
                    flags.append("EBSSnapshotShared")
                if is_public and "EBSSnapshotShared" in flags:
                    flags = ["EBSSnapshotPublic"]

                _collect_row(
                    rows,
                    {
                        "resource_id": sid,
                        "name": sid,
                        "resource_type": "EBSSnapshot",
                        "region": region,
                        "owner_id": config.ACCOUNT_ID,
                        "flags": flags,
                        "estimated_cost": 0.0,
                        "potential_saving": 0.0,
                        "signals": {
                            "Region": region,
                            "KmsKeyId": s.get("KmsKeyId") or "NULL",
                            "VolumeSizeGiB": s.get("VolumeSize"),
                            "StorageTier": s.get("StorageTier") or "NULL",
                            "SharedCount": len(shared_to),
                            "SharedTo": ";".join(shared_to) if shared_to else "NULL",
                            "Public": is_public,
                        },
                        "state": str(s.get("State") or ""),
                        "creation_date": _iso(s.get("StartTime")),
                        "storage_gb": float(s.get("VolumeSize") or 0.0),
                        "app_id": app_id,
                        "app": app,
                        "env": env,
                    },
                )

    # ------------------------------- flush write ------------------------------- #

    ordered = sorted(
        rows.values(),
        key=lambda r: (str(r.get("resource_type") or ""), str(r.get("resource_id") or "")),
    )
    for row in ordered:
        try:
            # type: ignore[call-arg]
            config.WRITE_ROW(writer=writer, **row)
        except Exception as exc:  # pylint: disable=broad-except
            log.warning("[ebs] write_row failed for %s: %s", row.get("resource_id"), exc)

    log.info("[ebs] Completed check_ebs_volumes_and_snapshots (rows=%d)", len(rows))
