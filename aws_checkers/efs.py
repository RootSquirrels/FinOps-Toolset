"""Checker: Unused Amazon EFS File Systems.

Identifies EFS file systems with no data-plane activity and no client connections
within a lookback window. Writes CSV rows with Flags, Estimated_Cost_USD,
Potential_Saving_USD, and a compact Signals string.

Design:
  - Dependencies (account_id, write_row, get_price, logger) via
    finops_toolset.checkers.config.setup(...).
  - Signature: (writer, efs, cloudwatch, logger=None, **_kwargs) — tolerant to
    positional/keyword/mixed calling styles used by run_check.
  - Uses finops_toolset.cloudwatch.CloudWatchBatcher:
      cw = CloudWatchBatcher(region=..., client=...)
      cw.add_q(id_hint=..., namespace=..., metric=..., dims=[(..., ...)], stat=..., period=...)
      results = cw.execute(start=..., end=...)
  - No return value (legacy behavior).
  - Retries handled by @retry_with_backoff on ClientError.
  - Logging uses lazy %s interpolation (pylint-friendly).
  - Time handling is timezone-aware (datetime.now(timezone.utc)).
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple

from botocore.exceptions import ClientError

from core.retry import retry_with_backoff
from aws_checkers import config
from core.cloudwatch import CloudWatchBatcher


# ----------------------------- helpers --------------------------------- #

def _require_config() -> None:
    if not (config.ACCOUNT_ID and config.WRITE_ROW and config.GET_PRICE):
        raise RuntimeError(
            "Checkers not configured. Call "
            "finops_toolset.checkers.config.setup(account_id=..., write_row=..., "
            "get_price=..., logger=...) first."
        )


def _logger(fallback: Optional[logging.Logger]) -> logging.Logger:
    return fallback or config.LOGGER or logging.getLogger(__name__)


def _safe_price(service: str, key: str) -> float:
    try:
        # type: ignore[arg-type]
        return float(config.GET_PRICE(service, key))  # pylint: disable=not-callable
    except Exception:  # pylint: disable=broad-except
        return 0.0


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


def _extract_writer_efs_cw(
    args: Tuple[Any, ...],
    kwargs: Dict[str, Any],
) -> Tuple[Any, Any, Any]:
    """Accept writer/efs/cloudwatch passed positionally or by keyword; prefer keywords."""
    writer = kwargs.get("writer", args[0] if len(args) >= 1 else None)
    efs = kwargs.get("efs", args[1] if len(args) >= 2 else None)
    cloudwatch = kwargs.get("cloudwatch", args[2] if len(args) >= 3 else None)
    if writer is None or efs is None or cloudwatch is None:
        raise TypeError(
            "check_unused_efs_filesystems expected 'writer', 'efs', and 'cloudwatch' "
            f"(got writer={writer!r}, efs={efs!r}, cloudwatch={cloudwatch!r})"
        )
    return writer, efs, cloudwatch


def _sum_from_result(res: Any) -> float:
    """Reduce CloudWatchBatcher result → sum of values."""
    if res is None:
        return 0.0
    # Batcher returns List[Tuple[datetime, float]]
    if isinstance(res, list) and res and isinstance(res[0], tuple):
        try:
            return float(sum(float(v) for _, v in res))  # type: ignore[misc]
        except Exception:  # pylint: disable=broad-except
            return 0.0
    if isinstance(res, dict):
        values = res.get("Values") or res.get("values") or []
        try:
            return float(sum(values))
        except Exception:  # pylint: disable=broad-except
            pass
        dps = res.get("Datapoints")
        if isinstance(dps, list):
            acc = 0.0
            for dp in dps:
                val = dp.get("Sum") or dp.get("Average") or dp.get("Maximum") or dp.get("Minimum") or dp.get("Value")
                if val is not None:
                    acc += float(val)
            return acc
    if isinstance(res, list):
        acc = 0.0
        for item in res:
            if isinstance(item, (int, float)):
                acc += float(item)
            elif isinstance(item, dict):
                val = item.get("y") or item.get("Sum") or item.get("Value")
                if val is not None:
                    acc += float(val)
        return acc
    return 0.0


def _max_from_result(res: Any) -> float:
    """Reduce CloudWatchBatcher result → max value."""
    if res is None:
        return 0.0
    # Batcher returns List[Tuple[datetime, float]]
    if isinstance(res, list) and res and isinstance(res[0], tuple):
        try:
            return float(max(float(v) for _, v in res))  # type: ignore[misc]
        except Exception:  # pylint: disable=broad-except
            return 0.0
    if isinstance(res, dict):
        values = res.get("Values") or res.get("values") or []
        try:
            return float(max(values)) if values else 0.0
        except Exception:  # pylint: disable=broad-except
            pass
        dps = res.get("Datapoints")
        if isinstance(dps, list):
            mx = 0.0
            for dp in dps:
                val = dp.get("Maximum") or dp.get("Average") or dp.get("Sum") or dp.get("Value")
                if val is not None:
                    mx = max(mx, float(val))
            return mx
    if isinstance(res, list):
        mx = 0.0
        for item in res:
            if isinstance(item, (int, float)):
                mx = max(mx, float(item))
            elif isinstance(item, dict):
                val = item.get("y") or item.get("Maximum") or item.get("Value")
                if val is not None:
                    mx = max(mx, float(val))
        return mx
    return 0.0


def _name_tag(efs, fs_id: str) -> Optional[str]:
    try:
        resp = efs.describe_tags(FileSystemId=fs_id)
        for t in resp.get("Tags", []) or []:
            if t.get("Key") == "Name":
                return t.get("Value")
    except ClientError:
        return None
    return None


def _mount_target_count(efs, fs_id: str) -> int:
    try:
        paginator = efs.get_paginator("describe_mount_targets")
        total = 0
        for page in paginator.paginate(FileSystemId=fs_id):
            total += len(page.get("MountTargets", []) or [])
        return total
    except ClientError:
        return 0


# ------------------------------ checker -------------------------------- #

@retry_with_backoff(exceptions=(ClientError,))
def check_unused_efs_filesystems(  # pylint: disable=unused-argument
    *args,
    logger: Optional[logging.Logger] = None,
    lookback_days: int = 30,
    io_threshold_bytes: int = 0,
    **kwargs,
) -> None:
    """
    Flag EFS file systems 'unused' across [now - lookback_days, now]:
      - Sum(TotalIOBytes) <= io_threshold_bytes  AND
      - Max(ClientConnections) == 0
    """
    _require_config()
    log = _logger(logger)

    writer, efs, cloudwatch = _extract_writer_efs_cw(args, kwargs)

    region = getattr(getattr(efs, "meta", None), "region_name", "") or ""
    now_utc = datetime.now(timezone.utc).replace(microsecond=0)
    start_time = now_utc - timedelta(days=lookback_days)
    period = 3600  # 1 hour buckets

    # Prepare CloudWatch batcher — ctor takes region and client
    cw_batch = CloudWatchBatcher(region=region, client=cloudwatch)

    # Collect file systems
    fs_list: List[Dict[str, Any]] = []
    fs_paginator = efs.get_paginator("describe_file_systems")
    for page in fs_paginator.paginate():
        fs_list.extend(page.get("FileSystems", []) or [])

    # Map fs_id -> metric query ids (the exact Id strings we pass to add_q)
    metric_ids: Dict[str, Dict[str, str]] = {}

    for fs in fs_list:
        fs_id = fs.get("FileSystemId")
        if not fs_id:
            continue

        total_id = f"totalio_{fs_id}"
        conn_id = f"conn_{fs_id}"

        # add_q requires keyword-only args
        cw_batch.add_q(
            id_hint=total_id,
            namespace="AWS/EFS",
            metric="TotalIOBytes",
            dims=[("FileSystemId", fs_id)],
            stat="Sum",
            period=period,
        )
        cw_batch.add_q(
            id_hint=conn_id,
            namespace="AWS/EFS",
            metric="ClientConnections",
            dims=[("FileSystemId", fs_id)],
            stat="Maximum",
            period=period,
        )

        metric_ids[fs_id] = {"total": total_id, "conn": conn_id}

    # Execute batched queries with the time window (API uses 'start'/'end')
    results: Dict[str, Any] = cw_batch.execute(start=start_time, end=now_utc)

    # Pricing per GB-month (fallbacks to 0.0 if not present in pricebook)
    price_std = _safe_price("EFS", "EFS_STANDARD_GB_MONTH")
    price_ia = _safe_price("EFS", "EFS_IA_GB_MONTH")

    for fs in fs_list:
        fs_id = fs.get("FileSystemId")
        if not fs_id:
            continue

        name = _name_tag(efs, fs_id) or fs.get("Name") or fs_id
        life = fs.get("LifeCycleState")
        perf_mode = fs.get("PerformanceMode")
        tp_mode = fs.get("ThroughputMode")
        prov_tp = fs.get("ProvisionedThroughputInMibps")
        encrypted = fs.get("Encrypted")
        created = _to_utc_iso(fs.get("CreationTime"))

        # Storage sizing
        sib = fs.get("SizeInBytes") or {}
        val_total = float(sib.get("Value") or 0)
        val_ia = float(sib.get("ValueInIA") or 0)
        val_std = float(sib.get("ValueInStandard") or (val_total - val_ia))
        gb_std = max(0.0, val_std / (1024 ** 3))
        gb_ia = max(0.0, val_ia / (1024 ** 3))

        est_cost = gb_std * price_std + gb_ia * price_ia

        # Mount targets (best-effort)
        mt_count = _mount_target_count(efs, fs_id)

        # Reduce metrics
        ids = metric_ids.get(fs_id, {})
        total_series = results.get(ids.get("total"))
        conn_series = results.get(ids.get("conn"))
        total_io_sum = _sum_from_result(total_series)
        max_conn = _max_from_result(conn_series)

        unused = (total_io_sum <= float(io_threshold_bytes)) and (max_conn <= 0.0)

        # Potential savings heuristic
        potential_saving = est_cost if unused else 0.0

        # Flags
        flags: List[str] = []
        if unused:
            flags.append("UnusedEFS")
        if mt_count == 0:
            flags.append("EFSMountTargetsZero")

        # Signals
        signals = _signals_str(
            {
                "Region": region,
                "FileSystemId": fs_id,
                "Name": name,
                "LifeCycleState": life,
                "PerformanceMode": perf_mode,
                "ThroughputMode": tp_mode,
                "ProvisionedTPMiBps": prov_tp,
                "Encrypted": encrypted,
                "CreationTime": created,
                "MountTargets": mt_count,
                "GB_Standard": round(gb_std, 3),
                "GB_IA": round(gb_ia, 3),
                "TotalIOBytesSum": int(total_io_sum),
                "MaxClientConnections": int(max_conn),
                "LookbackDays": lookback_days,
            }
        )

        if flags:
            # type: ignore[call-arg]
            config.WRITE_ROW(
                writer=writer,
                resource_id=fs_id,
                name=name,
                owner_id=config.ACCOUNT_ID,  # type: ignore[arg-type]
                resource_type="EFSFilesystem",
                estimated_cost=est_cost,
                potential_saving=potential_saving,
                flags=flags,
                confidence=100,
                signals=signals,
            )

        log.info(
            "[EFS] Processed EFS: %s (unused=%s io_sum=%s max_conn=%s mt=%s)",
            fs_id,
            unused,
            int(total_io_sum),
            int(max_conn),
            mt_count,
        )
