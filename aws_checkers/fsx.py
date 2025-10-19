"""Checkers: Amazon FSx.

Included:

  - check_fsx_low_activity_filesystems
      Very low IO over lookback window (DataReadBytes + DataWriteBytes).

  - check_fsx_high_free_capacity
      High free capacity (large headroom). Suggest right-sizing.

  - check_fsx_old_backups
      Backups older than N days. Estimates monthly backup storage cost.

Design:
  - Dependencies via finops_toolset.checkers.config.setup(...).
  - CloudWatch via finops_toolset.cloudwatch.CloudWatchBatcher.
  - Tolerant signatures; graceful skips; no return values.
  - UTC datetimes; pylint-friendly; lines ≤ 100 chars.

Pricebook keys used (safe defaults if absent):
  "FSX": {
      "LUSTRE_GB_MONTH": 0.0,
      "WINDOWS_GB_MONTH": 0.0,
      "ONTAP_GB_MONTH": 0.0,
      "OPENZFS_GB_MONTH": 0.0,
      "BACKUP_GB_MONTH": 0.0,
  }
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple

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


def _extract_writer_fsx_cw(
    args: Tuple[Any, ...],
    kwargs: Dict[str, Any],
) -> Tuple[Any, Any, Any]:
    """Accept writer/fsx/cloudwatch (positional or keyword)."""
    writer = kwargs.get("writer", args[0] if len(args) >= 1 else None)
    fsx = kwargs.get("fsx", args[1] if len(args) >= 2 else None)
    cloudwatch = kwargs.get("cloudwatch", args[2] if len(args) >= 3 else None)
    if writer is None or fsx is None or cloudwatch is None:
        raise TypeError(
            "Expected 'writer', 'fsx' and 'cloudwatch' "
            f"(got writer={writer!r}, fsx={fsx!r}, cloudwatch={cloudwatch!r})"
        )
    return writer, fsx, cloudwatch


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
            vals = [float(v) for _, v in res]
            return float(sum(vals) / len(vals)) if vals else 0.0
        except Exception:  # pylint: disable=broad-except
            return 0.0
    if isinstance(res, dict):
        vals = res.get("Values") or res.get("values") or []
        try:
            return float(sum(vals) / len(vals)) if vals else 0.0
        except Exception:  # pylint: disable=broad-except
            return 0.0
    return 0.0


def _price_per_gb(fsx_type: str) -> float:
    t = (fsx_type or "").upper()
    if "LUSTRE" in t:
        return float(config.safe_price("FSX", "LUSTRE_GB_MONTH", 0.0))
    if "WINDOWS" in t:
        return float(config.safe_price("FSX", "WINDOWS_GB_MONTH", 0.0))
    if "ONTAP" in t:
        return float(config.safe_price("FSX", "ONTAP_GB_MONTH", 0.0))
    if "OPENZFS" in t or "ZFS" in t:
        return float(config.safe_price("FSX", "OPENZFS_GB_MONTH", 0.0))
    return 0.0


def _price_backup_gb() -> float:
    return float(config.safe_price("FSX", "BACKUP_GB_MONTH", 0.0))


def _list_filesystems(fsx, log: logging.Logger) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    try:
        paginator = fsx.get_paginator("describe_file_systems")
        for page in paginator.paginate():
            out.extend(page.get("FileSystems", []) or [])
    except ClientError as exc:
        log.error("[fsx] describe_file_systems failed: %s", exc)
    return out


# -------------------- 1) Low activity (read+write bytes) ---------------- #

@retry_with_backoff(exceptions=(ClientError,))
def check_fsx_low_activity_filesystems(  # pylint: disable=unused-argument
    *args,
    logger: Optional[logging.Logger] = None,
    lookback_days: int = 14,
    io_threshold_bytes: float = 1_000_000_000.0,  # 1 GB over window
    **kwargs,
) -> None:
    """Flag FSx file systems with total IO below threshold over lookback window."""
    log = _logger(kwargs.get("logger") or logger)

    try:
        writer, fsx, cloudwatch = _extract_writer_fsx_cw(args, kwargs)
    except TypeError as exc:
        log.warning("[check_fsx_low_activity_filesystems] Skipping: %s", exc)
        return
    if not (config.ACCOUNT_ID and config.WRITE_ROW and config.GET_PRICE):
        log.warning("[check_fsx_low_activity_filesystems] Skipping: checker config not provided.")
        return

    region = getattr(getattr(fsx, "meta", None), "region_name", "") or ""
    fss = _list_filesystems(fsx, log)
    if not fss:
        return

    now_utc = datetime.now(timezone.utc).replace(microsecond=0)
    start = now_utc - timedelta(days=int(lookback_days))
    period = 300

    id_map: Dict[str, Dict[str, str]] = {}
    results: Dict[str, Any] = {}
    metrics_ok = True

    try:
        cw = CloudWatchBatcher(region=region, client=cloudwatch)
        for fsys in fss:
            fsid = fsys.get("FileSystemId")
            if not fsid:
                continue
            dims = [("FileSystemId", fsid)]

            id_rd = f"rd_{fsid}"
            id_wr = f"wr_{fsid}"
            cw.add_q(
                id_hint=id_rd,
                namespace="AWS/FSx",
                metric="DataReadBytes",
                dims=dims,
                stat="Sum",
                period=period,
            )
            cw.add_q(
                id_hint=id_wr,
                namespace="AWS/FSx",
                metric="DataWriteBytes",
                dims=dims,
                stat="Sum",
                period=period,
            )

            id_map[fsid] = {"rd": id_rd, "wr": id_wr}

        results = cw.execute(start=start, end=now_utc)
    except ClientError as exc:
        log.warning("[fsx] CloudWatch metrics unavailable: %s", exc)
        metrics_ok = False
    except Exception as exc:  # pylint: disable=broad-except
        log.warning("[fsx] CloudWatch batch error: %s", exc)
        metrics_ok = False

    if not metrics_ok:
        return

    for fsys in fss:
        fsid = fsys.get("FileSystemId") or ""
        if not fsid:
            continue

        rsum = _sum_from_result(results.get(id_map.get(fsid, {}).get("rd")))
        wsum = _sum_from_result(results.get(id_map.get(fsid, {}).get("wr")))
        total = float(rsum + wsum)

        if total > float(io_threshold_bytes):
            continue

        typ = fsys.get("FileSystemType") or ""
        cap_gib = float(fsys.get("StorageCapacity") or 0)
        p_gb = _price_per_gb(typ)
        est = cap_gib * p_gb
        potential = est  # heuristic: if deleted or moved to cheaper tier

        name = fsys.get("DNSName") or fsid  # Windows exposes DNSName; others may not

        signals = _signals_str(
            {
                "Region": region,
                "FileSystemId": fsid,
                "Type": typ,
                "StorageGiB": int(cap_gib),
                "IOBytesSum": int(total),
                "LookbackDays": lookback_days,
            }
        )

        try:
            # type: ignore[call-arg]
            config.WRITE_ROW(
                writer=writer,
                resource_id=fsid,
                name=name,
                owner_id=config.ACCOUNT_ID,  # type: ignore[arg-type]
                resource_type="FSxFileSystem",
                estimated_cost=est,
                potential_saving=potential,
                flags=["FSxFileSystemLowActivity"],
                confidence=100,
                signals=signals,
            )
        except Exception as exc:  # pylint: disable=broad-except
            log.warning("[fsx] write_row failed for %s: %s", fsid, exc)

        log.info("[fsx] Wrote low-activity: %s", fsid)


# ---------------------- 2) High free capacity (headroom) ----------------- #

@retry_with_backoff(exceptions=(ClientError,))
def check_fsx_high_free_capacity(  # pylint: disable=unused-argument
    *args,
    logger: Optional[logging.Logger] = None,
    lookback_days: int = 3,
    free_pct_threshold: float = 0.70,  # 70% free
    **kwargs,
) -> None:
    """
    Flag FSx file systems with high average FreeStorageCapacity%.
    Uses CloudWatch (Average FreeStorageCapacity) and StorageCapacity from API.
    """
    log = _logger(kwargs.get("logger") or logger)

    try:
        writer, fsx, cloudwatch = _extract_writer_fsx_cw(args, kwargs)
    except TypeError as exc:
        log.warning("[check_fsx_high_free_capacity] Skipping: %s", exc)
        return
    if not (config.ACCOUNT_ID and config.WRITE_ROW and config.GET_PRICE):
        log.warning("[check_fsx_high_free_capacity] Skipping: checker config not provided.")
        return

    region = getattr(getattr(fsx, "meta", None), "region_name", "") or ""
    fss = _list_filesystems(fsx, log)
    if not fss:
        return

    now_utc = datetime.now(timezone.utc).replace(microsecond=0)
    start = now_utc - timedelta(days=int(lookback_days))
    period = 300

    id_map: Dict[str, str] = {}
    results: Dict[str, Any] = {}
    metrics_ok = True

    try:
        cw = CloudWatchBatcher(region=region, client=cloudwatch)
        for fsys in fss:
            fsid = fsys.get("FileSystemId")
            if not fsid:
                continue
            dims = [("FileSystemId", fsid)]

            qid = f"free_{fsid}"
            cw.add_q(
                id_hint=qid,
                namespace="AWS/FSx",
                metric="FreeStorageCapacity",
                dims=dims,
                stat="Average",
                period=period,
            )
            id_map[fsid] = qid

        results = cw.execute(start=start, end=now_utc)
    except ClientError as exc:
        log.warning("[fsx] CloudWatch metrics unavailable: %s", exc)
        metrics_ok = False
    except Exception as exc:  # pylint: disable=broad-except
        log.warning("[fsx] CloudWatch batch error: %s", exc)
        metrics_ok = False

    if not metrics_ok:
        return

    for fsys in fss:
        fsid = fsys.get("FileSystemId") or ""
        if not fsid:
            continue

        cap_gib = float(fsys.get("StorageCapacity") or 0)
        free_gib_avg = _avg_from_result(results.get(id_map.get(fsid)))
        if cap_gib <= 0 or free_gib_avg <= 0:
            continue

        free_pct = min(1.0, float(free_gib_avg) / cap_gib)
        if free_pct < float(free_pct_threshold):
            continue

        typ = fsys.get("FileSystemType") or ""
        p_gb = _price_per_gb(typ)
        est = cap_gib * p_gb
        potential = free_gib_avg * p_gb  # rough: savings if downsized by the free amount

        name = fsys.get("DNSName") or fsid

        signals = _signals_str(
            {
                "Region": region,
                "FileSystemId": fsid,
                "Type": typ,
                "StorageGiB": int(cap_gib),
                "FreeGiB_Avg": int(free_gib_avg),
                "FreePct_Avg": round(free_pct, 3),
                "LookbackDays": lookback_days,
            }
        )

        try:
            # type: ignore[call-arg]
            config.WRITE_ROW(
                writer=writer,
                resource_id=fsid,
                name=name,
                owner_id=config.ACCOUNT_ID,  # type: ignore[arg-type]
                resource_type="FSxFileSystem",
                estimated_cost=est,
                potential_saving=potential,
                flags=["FSxFileSystemHighFreeCapacity"],
                confidence=100,
                signals=signals,
            )
        except Exception as exc:  # pylint: disable=broad-except
            log.warning("[fsx] write_row failed for %s: %s", fsid, exc)

        log.info("[fsx] Wrote high-free: %s", fsid)


# --------------------------- 3) Old backups ------------------------------ #

@retry_with_backoff(exceptions=(ClientError,))
def check_fsx_old_backups(  # pylint: disable=unused-argument
    *args,
    logger: Optional[logging.Logger] = None,
    stale_days: int = 30,
    **kwargs,
) -> None:
    """Flag FSx backups older than 'stale_days' (Lifecycle=AVAILABLE)."""
    log = _logger(kwargs.get("logger") or logger)

    try:
        writer, fsx, cloudwatch = _extract_writer_fsx_cw(args, kwargs)  # cloudwatch unused
    except TypeError as exc:
        log.warning("[check_fsx_old_backups] Skipping: %s", exc)
        return
    if not (config.ACCOUNT_ID and config.WRITE_ROW and config.GET_PRICE):
        log.warning("[check_fsx_old_backups] Skipping: checker config not provided.")
        return

    region = getattr(getattr(fsx, "meta", None), "region_name", "") or ""
    cutoff = (datetime.now(timezone.utc) - timedelta(days=int(stale_days))).replace(
        microsecond=0
    )

    try:
        paginator = fsx.get_paginator("describe_backups")
        for page in paginator.paginate():
            for b in page.get("Backups", []) or []:
                bid = b.get("BackupId") or ""
                if not bid:
                    continue
                life = (b.get("Lifecycle") or "").upper()
                if life != "AVAILABLE":
                    continue

                created = b.get("CreationTime")
                if not isinstance(created, datetime):
                    continue
                c_utc = created if created.tzinfo else created.replace(tzinfo=timezone.utc)
                if c_utc >= cutoff:
                    continue

                # Heuristic size in GiB (best effort from nested objects)
                size_gib = 0.0
                fs_info = b.get("FileSystem") or {}
                vol_info = b.get("Volume") or {}
                if "StorageCapacity" in fs_info:
                    size_gib = float(fs_info.get("StorageCapacity") or 0.0)
                elif "VolumeSizeInMegabytes" in vol_info:
                    size_gib = float(vol_info.get("VolumeSizeInMegabytes") or 0.0) / 1024.0

                price = _price_backup_gb()
                est = size_gib * price
                potential = est  # if deleted

                typ = fs_info.get("FileSystemType") or b.get("Type") or ""
                fsid = fs_info.get("FileSystemId") or vol_info.get("VolumeId") or ""

                signals = _signals_str(
                    {
                        "Region": region,
                        "BackupId": bid,
                        "FileSystemIdOrVolumeId": fsid,
                        "Type": typ,
                        "CreatedAt": _to_utc_iso(c_utc),
                        "SizeGiB_Est": int(size_gib),
                        "Lifecycle": life,
                        "StaleDays": stale_days,
                    }
                )

                try:
                    # type: ignore[call-arg]
                    config.WRITE_ROW(
                        writer=writer,
                        resource_id=bid,
                        name=bid,
                        owner_id=config.ACCOUNT_ID,  # type: ignore[arg-type]
                        resource_type="FSxBackup",
                        estimated_cost=est,
                        potential_saving=potential,
                        flags=["FSxBackupOld"],
                        confidence=100,
                        signals=signals,
                    )
                except Exception as exc:  # pylint: disable=broad-except
                    log.warning("[fsx] write_row failed for backup %s: %s", bid, exc)

                log.info("[fsx] Wrote old backup: %s", bid)

    except ClientError as exc:
        log.error("[fsx] describe_backups failed: %s", exc)
        raise
