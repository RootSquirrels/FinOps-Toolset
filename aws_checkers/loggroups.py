"""Checkers: Amazon CloudWatch Logs – Log Groups.

Checks included:

  - check_loggroups_no_retention
  - check_loggroups_stale
  - check_loggroups_large_storage
  - check_loggroups_unencrypted

New checks included:

  - check_loggroups_high_ingestion
  - check_loggroups_high_ingestion_no_retention
  - check_loggroups_retention_too_long
"""

from __future__ import annotations

import hashlib
import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Set, Tuple

from botocore.exceptions import ClientError

from aws_checkers import config
from aws_checkers.common import _logger, _signals_str
from core.cloudwatch import CloudWatchBatcher
from core.retry import retry_with_backoff


# ------------------------------- helpers --------------------------------- #

_GB = 1024.0 ** 3
_DAYS_IN_MONTH = 30.4375


def _bytes_to_gb(b: Optional[int]) -> float:
    """Convert bytes to GB (GiB) safely."""
    return max(0.0, float(b or 0) / _GB)


def _extract_writer_logs_cw(
    args: Tuple[Any, ...],
    kwargs: Dict[str, Any],
) -> Tuple[Any, Any, Any]:
    """Accept writer/logs/cloudwatch (positional or keyword)."""
    writer = kwargs.get("writer", args[0] if len(args) >= 1 else None)
    logs = kwargs.get("logs", args[1] if len(args) >= 2 else None)
    cloudwatch = kwargs.get("cloudwatch", args[2] if len(args) >= 3 else None)
    if writer is None or logs is None or cloudwatch is None:
        raise TypeError(
            "Expected 'writer', 'logs' and 'cloudwatch' "
            f"(got writer={writer!r}, logs={logs!r}, cloudwatch={cloudwatch!r})"
        )
    return writer, logs, cloudwatch


def _list_log_groups(logs, log: logging.Logger) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    try:
        paginator = logs.get_paginator("describe_log_groups")
        for page in paginator.paginate():
            out.extend(page.get("logGroups", []) or [])
    except ClientError as exc:
        log.error("[logs] describe_log_groups failed: %s", exc)
    return out


def _cw_safe_id(prefix: str, name: str) -> str:
    """
    CloudWatch GetMetricData Id must match: [a-zA-Z][a-zA-Z0-9_]*.
    Log group names frequently include '/', so we generate a stable safe ID.
    """
    digest = hashlib.sha1(name.encode("utf-8")).hexdigest()[:12]  # nosec B324
    safe_prefix = "".join(ch if ch.isalnum() else "_" for ch in (prefix or "q"))
    if not safe_prefix or not safe_prefix[0].isalpha():
        safe_prefix = f"q_{safe_prefix}"
    return f"{safe_prefix}_{digest}"


def _writer_seen_set(writer: Any) -> Set[str]:
    """Attach per-run dedupe state to writer when possible."""
    attr = "_finops_seen_loggroups"
    seen = getattr(writer, attr, None)
    if isinstance(seen, set):
        return seen
    try:
        new_seen: Set[str] = set()
        setattr(writer, attr, new_seen)
        return new_seen
    except Exception:  # pylint: disable=broad-except
        # Fallback to a module static set (still prevents in-process duplicates)
        if not hasattr(_writer_seen_set, "_fallback"):  # type: ignore[attr-defined]
            setattr(_writer_seen_set, "_fallback", set())  # type: ignore[attr-defined]
        return getattr(_writer_seen_set, "_fallback")  # type: ignore[return-value]


def _dedupe_key(resource_id: str, flags: List[str], owner_id: Any, region: str) -> str:
    flags_key = ",".join(sorted([f for f in (flags or []) if f]))
    return f"{owner_id}|{region}|{resource_id}|{flags_key}"


def _write_row_once(
    *,
    writer: Any,
    log: logging.Logger,
    region: str,
    resource_id: str,
    flags: List[str],
    **row_kwargs: Any,
) -> bool:
    """Write via config.WRITE_ROW once per (account, region, resource_id, flags)."""
    if not config.WRITE_ROW:
        return False

    key = _dedupe_key(
        resource_id=resource_id,
        flags=flags,
        owner_id=config.ACCOUNT_ID,
        region=region,
    )
    seen = _writer_seen_set(writer)
    if key in seen:
        log.debug("[loggroups] Deduped row: %s (%s)", resource_id, flags)
        return False
    seen.add(key)

    try:
        config.WRITE_ROW(  # type: ignore[call-arg]
            writer=writer,
            resource_id=resource_id,
            flags=flags,
            **row_kwargs,
        )
        return True
    except Exception as exc:  # pylint: disable=broad-except
        log.warning("[loggroups] write_row %s %s: %s", resource_id, flags, exc)
        return False


def _incoming_cache(writer: Any) -> Dict[str, Dict[str, float]]:
    """
    Cache IncomingBytes sums per (region, lookback_days, period) so multiple checks
    don't re-query CloudWatch in the same run.
    """
    attr = "_finops_cwl_incoming_cache"
    cache = getattr(writer, attr, None)
    if isinstance(cache, dict):
        return cache
    try:
        new_cache: Dict[str, Dict[str, float]] = {}
        setattr(writer, attr, new_cache)
        return new_cache
    except Exception:  # pylint: disable=broad-except
        if not hasattr(_incoming_cache, "_fallback"):  # type: ignore[attr-defined]
            setattr(_incoming_cache, "_fallback", {})  # type: ignore[attr-defined]
        return getattr(_incoming_cache, "_fallback")  # type: ignore[return-value]


def _sum_series(series: Any) -> float:
    if series is None:
        return 0.0
    if isinstance(series, list):
        try:
            return float(sum(float(v) for _, v in series))
        except Exception:  # pylint: disable=broad-except
            return 0.0
    if isinstance(series, dict):
        vals = series.get("Values") or series.get("values") or []
        try:
            return float(sum(float(v) for v in vals))
        except Exception:  # pylint: disable=broad-except
            return 0.0
    return 0.0


def _fetch_incoming_bytes_sums(
    *,
    cloudwatch: Any,
    region: str,
    groups: List[Dict[str, Any]],
    start: datetime,
    end: datetime,
    period: int,
    log: logging.Logger,
) -> Dict[str, float]:
    """Batch fetch IncomingBytes sums for all groups."""
    id_map: Dict[str, str] = {}
    sums: Dict[str, float] = {}

    cw = CloudWatchBatcher(region=region, client=cloudwatch)
    for g in groups:
        name = g.get("logGroupName")
        if not name:
            continue
        qid = _cw_safe_id("in", name)
        cw.add_q(
            id_hint=qid,
            namespace="AWS/Logs",
            metric="IncomingBytes",
            dims=[("LogGroupName", name)],
            stat="Sum",
            period=period,
        )
        id_map[name] = qid

    results = cw.execute(start=start, end=end)
    for name, qid in id_map.items():
        sums[name] = _sum_series(results.get(qid))

    return sums


def _get_incoming_bytes_sums_cached(
    *,
    writer: Any,
    cloudwatch: Any,
    region: str,
    groups: List[Dict[str, Any]],
    lookback_days: int,
    period: int,
    log: logging.Logger,
) -> Tuple[datetime, datetime, Dict[str, float]]:
    now_utc = datetime.now(timezone.utc).replace(microsecond=0)
    start = now_utc - timedelta(days=int(lookback_days))
    cache_key = f"{region}|{lookback_days}|{period}"

    cache = _incoming_cache(writer)
    if cache_key in cache:
        return start, now_utc, cache[cache_key]

    try:
        sums = _fetch_incoming_bytes_sums(
            cloudwatch=cloudwatch,
            region=region,
            groups=groups,
            start=start,
            end=now_utc,
            period=period,
            log=log,
        )
        cache[cache_key] = sums
        return start, now_utc, sums
    except ClientError as exc:
        log.warning("[loggroups] CloudWatch metrics unavailable: %s", exc)
    except Exception as exc:  # pylint: disable=broad-except
        log.warning("[loggroups] CloudWatch batch error: %s", exc)

    return start, now_utc, {}


def _region_from_client(client: Any) -> str:
    return getattr(getattr(client, "meta", None), "region_name", "") or ""


# --------------------- 1) No retention policy (never expire) ------------- #

@retry_with_backoff(exceptions=(ClientError,))
def check_loggroups_no_retention(  # pylint: disable=unused-argument
    *args,
    logger: Optional[logging.Logger] = None,
    **kwargs,
) -> None:
    """Flag log groups without a retention policy (never expire)."""
    log = _logger(kwargs.get("logger") or logger)

    try:
        writer, logs, _cloudwatch = _extract_writer_logs_cw(args, kwargs)
    except TypeError as exc:
        log.warning("[check_loggroups_no_retention] Skipping: %s", exc)
        return
    if not (config.ACCOUNT_ID and config.WRITE_ROW and config.GET_PRICE):
        log.warning("[check_loggroups_no_retention] Skipping: checker config not provided.")
        return

    region = _region_from_client(logs)
    price_gb_mo = config.safe_price("CWL", "STORAGE_GB_MONTH", 0.03)

    groups = _list_log_groups(logs, log)
    for g in groups:
        name = g.get("logGroupName") or ""
        if not name or g.get("retentionInDays") is not None:
            continue

        stored_gb = _bytes_to_gb(g.get("storedBytes"))
        est = stored_gb * float(price_gb_mo)
        potential = est

        wrote = _write_row_once(
            writer=writer,
            log=log,
            region=region,
            resource_id=name,
            name=name,
            owner_id=config.ACCOUNT_ID,  # type: ignore[arg-type]
            resource_type="CloudWatchLogGroup",
            estimated_cost=est,
            potential_saving=potential,
            flags=["CWLLogGroupNoRetention"],
            confidence=100,
            signals=_signals_str(
                {
                    "Region": region,
                    "Group": name,
                    "StoredGB": round(stored_gb, 3),
                    "MetricFilters": g.get("metricFilterCount"),
                    "HasKMS": bool(g.get("kmsKeyId")),
                }
            ),
        )
        if wrote:
            log.info("[check_loggroups_no_retention] Wrote: %s", name)


# ---------------------- 2) Stale groups (no ingestion) ------------------- #

@retry_with_backoff(exceptions=(ClientError,))
def check_loggroups_stale(  # pylint: disable=unused-argument
    *args,
    logger: Optional[logging.Logger] = None,
    lookback_days: int = 14,
    **kwargs,
) -> None:
    """
    Flag log groups with zero IncomingBytes over the lookback window.
    Estimated cost uses storedBytes * price("CWL","STORAGE_GB_MONTH").
    """
    log = _logger(kwargs.get("logger") or logger)

    try:
        writer, logs, cloudwatch = _extract_writer_logs_cw(args, kwargs)
    except TypeError as exc:
        log.warning("[check_loggroups_stale] Skipping: %s", exc)
        return
    if not (config.ACCOUNT_ID and config.WRITE_ROW and config.GET_PRICE):
        log.warning("[check_loggroups_stale] Skipping: checker config not provided.")
        return

    region = _region_from_client(logs)
    groups = _list_log_groups(logs, log)
    if not groups:
        return

    period = 3600
    _start, _end, incoming_sums = _get_incoming_bytes_sums_cached(
        writer=writer,
        cloudwatch=cloudwatch,
        region=region,
        groups=groups,
        lookback_days=int(lookback_days),
        period=period,
        log=log,
    )
    if not incoming_sums:
        return

    price_gb_mo = config.safe_price("CWL", "STORAGE_GB_MONTH", 0.03)

    for g in groups:
        name = g.get("logGroupName") or ""
        if not name:
            continue

        incoming = float(incoming_sums.get(name, 0.0))
        if incoming > 0.0:
            continue

        stored_gb = _bytes_to_gb(g.get("storedBytes"))
        est = stored_gb * float(price_gb_mo)
        potential = est

        wrote = _write_row_once(
            writer=writer,
            log=log,
            region=region,
            resource_id=name,
            name=name,
            owner_id=config.ACCOUNT_ID,  # type: ignore[arg-type]
            resource_type="CloudWatchLogGroup",
            estimated_cost=est,
            potential_saving=potential,
            flags=["CWLLogGroupStale"],
            confidence=100,
            signals=_signals_str(
                {
                    "Region": region,
                    "Group": name,
                    "IncomingBytesSum": int(incoming),
                    "StoredGB": round(stored_gb, 3),
                    "RetentionDays": g.get("retentionInDays"),
                }
            ),
        )
        if wrote:
            log.info("[check_loggroups_stale] Wrote: %s", name)


# --------------------- 3) Large storage (storedBytes) -------------------- #

@retry_with_backoff(exceptions=(ClientError,))
def check_loggroups_large_storage(  # pylint: disable=unused-argument
    *args,
    logger: Optional[logging.Logger] = None,
    min_gb: float = 50.0,
    **kwargs,
) -> None:
    """
    Flag log groups with storedBytes >= min_gb (approximate).
    Estimated cost uses price("CWL","STORAGE_GB_MONTH").
    """
    log = _logger(kwargs.get("logger") or logger)

    try:
        writer, logs, _cloudwatch = _extract_writer_logs_cw(args, kwargs)
    except TypeError as exc:
        log.warning("[check_loggroups_large_storage] Skipping: %s", exc)
        return
    if not (config.ACCOUNT_ID and config.WRITE_ROW and config.GET_PRICE):
        log.warning("[check_loggroups_large_storage] Skipping: checker config not provided.")
        return

    region = _region_from_client(logs)
    groups = _list_log_groups(logs, log)
    price_gb_mo = config.safe_price("CWL", "STORAGE_GB_MONTH", 0.03)

    for g in groups:
        name = g.get("logGroupName") or ""
        if not name:
            continue

        stored_gb = _bytes_to_gb(g.get("storedBytes"))
        if stored_gb < float(min_gb):
            continue

        est = stored_gb * float(price_gb_mo)
        potential = est

        wrote = _write_row_once(
            writer=writer,
            log=log,
            region=region,
            resource_id=name,
            name=name,
            owner_id=config.ACCOUNT_ID,  # type: ignore[arg-type]
            resource_type="CloudWatchLogGroup",
            estimated_cost=est,
            potential_saving=potential,
            flags=["CWLLogGroupLargeStorage"],
            confidence=100,
            signals=_signals_str(
                {
                    "Region": region,
                    "Group": name,
                    "StoredGB": round(stored_gb, 3),
                    "RetentionDays": g.get("retentionInDays"),
                }
            ),
        )
        if wrote:
            log.info("[check_loggroups_large_storage] Wrote: %s (%.2f GB)", name, stored_gb)


# ------------------------ 4) Unencrypted (no KMS) ------------------------ #

@retry_with_backoff(exceptions=(ClientError,))
def check_loggroups_unencrypted(  # pylint: disable=unused-argument
    *args,
    logger: Optional[logging.Logger] = None,
    **kwargs,
) -> None:
    """Flag log groups without a KMS key (hygiene)."""
    log = _logger(kwargs.get("logger") or logger)

    try:
        writer, logs, _cloudwatch = _extract_writer_logs_cw(args, kwargs)
    except TypeError as exc:
        log.warning("[check_loggroups_unencrypted] Skipping: %s", exc)
        return
    if not (config.ACCOUNT_ID and config.WRITE_ROW):
        log.warning("[check_loggroups_unencrypted] Skipping: checker config not provided.")
        return

    region = _region_from_client(logs)
    groups = _list_log_groups(logs, log)

    for g in groups:
        name = g.get("logGroupName") or ""
        if not name or g.get("kmsKeyId"):
            continue

        wrote = _write_row_once(
            writer=writer,
            log=log,
            region=region,
            resource_id=name,
            name=name,
            owner_id=config.ACCOUNT_ID,  # type: ignore[arg-type]
            resource_type="CloudWatchLogGroup",
            estimated_cost=0.0,
            potential_saving=0.0,
            flags=["CWLLogGroupUnencrypted"],
            confidence=100,
            signals=_signals_str({"Region": region, "Group": name}),
        )
        if wrote:
            log.info("[check_loggroups_unencrypted] Wrote: %s", name)


# --------------------- 5) High ingestion (IncomingBytes) ----------------- #

@retry_with_backoff(exceptions=(ClientError,))
def check_loggroups_high_ingestion(  # pylint: disable=unused-argument
    *args,
    logger: Optional[logging.Logger] = None,
    lookback_days: int = 7,
    min_gb_per_day: float = 1.0,
    **kwargs,
) -> None:
    """
    Flag log groups with high ingestion (IncomingBytes) in the lookback window.

    We estimate a monthly run-rate:
      monthly_gb = (ingested_gb / lookback_days) * ~30.44

    Estimated cost uses price("CWL","INGEST_GB"). Defaults to 0.50 USD/GB.
    """
    log = _logger(kwargs.get("logger") or logger)

    try:
        writer, logs, cloudwatch = _extract_writer_logs_cw(args, kwargs)
    except TypeError as exc:
        log.warning("[check_loggroups_high_ingestion] Skipping: %s", exc)
        return
    if not (config.ACCOUNT_ID and config.WRITE_ROW and config.GET_PRICE):
        log.warning("[check_loggroups_high_ingestion] Skipping: checker config not provided.")
        return

    region = _region_from_client(logs)
    groups = _list_log_groups(logs, log)
    if not groups:
        return

    period = 3600
    start, end, incoming_sums = _get_incoming_bytes_sums_cached(
        writer=writer,
        cloudwatch=cloudwatch,
        region=region,
        groups=groups,
        lookback_days=int(lookback_days),
        period=period,
        log=log,
    )
    if not incoming_sums:
        return

    price_ingest_gb = config.safe_price("CWL", "INGEST_GB", 0.50)
    price_storage_gb_mo = config.safe_price("CWL", "STORAGE_GB_MONTH", 0.03)

    for g in groups:
        name = g.get("logGroupName") or ""
        if not name:
            continue

        ingested_bytes = float(incoming_sums.get(name, 0.0))
        ingested_gb = ingested_bytes / _GB
        gb_per_day = ingested_gb / max(1.0, float(lookback_days))
        if gb_per_day < float(min_gb_per_day):
            continue

        monthly_gb = gb_per_day * _DAYS_IN_MONTH
        ingest_cost = monthly_gb * float(price_ingest_gb)

        stored_gb = _bytes_to_gb(g.get("storedBytes"))
        storage_cost = stored_gb * float(price_storage_gb_mo)

        # This is a run-rate estimate (ingestion) + current storage; still useful as a baseline.
        est = float(ingest_cost + storage_cost)
        potential = est

        wrote = _write_row_once(
            writer=writer,
            log=log,
            region=region,
            resource_id=name,
            name=name,
            owner_id=config.ACCOUNT_ID,  # type: ignore[arg-type]
            resource_type="CloudWatchLogGroup",
            estimated_cost=est,
            potential_saving=potential,
            flags=["CWLLogGroupHighIngestion"],
            confidence=90,
            signals=_signals_str(
                {
                    "Region": region,
                    "Group": name,
                    "WindowStart": start.isoformat(),
                    "WindowEnd": end.isoformat(),
                    "IngestedGB": round(ingested_gb, 3),
                    "GBPerDay": round(gb_per_day, 3),
                    "MonthlyGBRunRate": round(monthly_gb, 1),
                    "RetentionDays": g.get("retentionInDays"),
                    "StoredGB": round(stored_gb, 3),
                }
            ),
        )
        if wrote:
            log.info(
                "[check_loggroups_high_ingestion] Wrote: %s (%.2f GB/day)",
                name,
                gb_per_day,
            )


# ----------- 6) High ingestion + no retention (combined signal) ---------- #

@retry_with_backoff(exceptions=(ClientError,))
def check_loggroups_high_ingestion_no_retention(  # pylint: disable=unused-argument
    *args,
    logger: Optional[logging.Logger] = None,
    lookback_days: int = 7,
    min_gb_per_day: float = 1.0,
    **kwargs,
) -> None:
    """Flag log groups that combine high ingestion with missing retention."""
    log = _logger(kwargs.get("logger") or logger)

    try:
        writer, logs, cloudwatch = _extract_writer_logs_cw(args, kwargs)
    except TypeError as exc:
        log.warning("[check_loggroups_high_ingestion_no_retention] Skipping: %s", exc)
        return
    if not (config.ACCOUNT_ID and config.WRITE_ROW and config.GET_PRICE):
        log.warning(
            "[check_loggroups_high_ingestion_no_retention] Skipping: checker config not provided."
        )
        return

    region = _region_from_client(logs)
    groups = _list_log_groups(logs, log)
    if not groups:
        return

    period = 3600
    start, end, incoming_sums = _get_incoming_bytes_sums_cached(
        writer=writer,
        cloudwatch=cloudwatch,
        region=region,
        groups=groups,
        lookback_days=int(lookback_days),
        period=period,
        log=log,
    )
    if not incoming_sums:
        return

    price_ingest_gb = config.safe_price("CWL", "INGEST_GB", 0.50)
    price_storage_gb_mo = config.safe_price("CWL", "STORAGE_GB_MONTH", 0.03)

    for g in groups:
        name = g.get("logGroupName") or ""
        if not name or g.get("retentionInDays") is not None:
            continue

        ingested_bytes = float(incoming_sums.get(name, 0.0))
        ingested_gb = ingested_bytes / _GB
        gb_per_day = ingested_gb / max(1.0, float(lookback_days))
        if gb_per_day < float(min_gb_per_day):
            continue

        monthly_gb = gb_per_day * _DAYS_IN_MONTH
        ingest_cost = monthly_gb * float(price_ingest_gb)

        stored_gb = _bytes_to_gb(g.get("storedBytes"))
        storage_cost = stored_gb * float(price_storage_gb_mo)

        est = float(ingest_cost + storage_cost)
        potential = est

        wrote = _write_row_once(
            writer=writer,
            log=log,
            region=region,
            resource_id=name,
            name=name,
            owner_id=config.ACCOUNT_ID,  # type: ignore[arg-type]
            resource_type="CloudWatchLogGroup",
            estimated_cost=est,
            potential_saving=potential,
            flags=["CWLLogGroupHighIngestionNoRetention"],
            confidence=95,
            signals=_signals_str(
                {
                    "Region": region,
                    "Group": name,
                    "WindowStart": start.isoformat(),
                    "WindowEnd": end.isoformat(),
                    "IngestedGB": round(ingested_gb, 3),
                    "GBPerDay": round(gb_per_day, 3),
                    "MonthlyGBRunRate": round(monthly_gb, 1),
                    "StoredGB": round(stored_gb, 3),
                    "RetentionDays": None,
                }
            ),
        )
        if wrote:
            log.info(
                "[check_loggroups_high_ingestion_no_retention] Wrote: %s (%.2f GB/day)",
                name,
                gb_per_day,
            )


# --------------------- 7) Retention too long (heuristic) ----------------- #

@retry_with_backoff(exceptions=(ClientError,))
def check_loggroups_retention_too_long(  # pylint: disable=unused-argument
    *args,
    logger: Optional[logging.Logger] = None,
    max_retention_days: int = 90,
    min_stored_gb: float = 5.0,
    **kwargs,
) -> None:
    """
    Flag log groups with a retention policy that is likely longer than necessary.

    Heuristic:
      - retentionInDays > max_retention_days
      - storedBytes >= min_stored_gb

    Estimated cost is current monthly storage cost.
    Potential saving is proportional to how much retention could be reduced:
      (retention - max) / retention
    """
    log = _logger(kwargs.get("logger") or logger)

    try:
        writer, logs, _cloudwatch = _extract_writer_logs_cw(args, kwargs)
    except TypeError as exc:
        log.warning("[check_loggroups_retention_too_long] Skipping: %s", exc)
        return
    if not (config.ACCOUNT_ID and config.WRITE_ROW and config.GET_PRICE):
        log.warning("[check_loggroups_retention_too_long] Skipping: checker config not provided.")
        return

    region = _region_from_client(logs)
    price_gb_mo = config.safe_price("CWL", "STORAGE_GB_MONTH", 0.03)

    groups = _list_log_groups(logs, log)
    for g in groups:
        name = g.get("logGroupName") or ""
        if not name:
            continue

        retention = g.get("retentionInDays")
        if retention is None:
            continue
        try:
            retention_i = int(retention)
        except (TypeError, ValueError):
            continue
        if retention_i <= int(max_retention_days):
            continue

        stored_gb = _bytes_to_gb(g.get("storedBytes"))
        if stored_gb < float(min_stored_gb):
            continue

        est = stored_gb * float(price_gb_mo)
        ratio = (float(retention_i) - float(max_retention_days)) / max(1.0, float(retention_i))
        potential = est * max(0.0, min(1.0, ratio))

        wrote = _write_row_once(
            writer=writer,
            log=log,
            region=region,
            resource_id=name,
            name=name,
            owner_id=config.ACCOUNT_ID,  # type: ignore[arg-type]
            resource_type="CloudWatchLogGroup",
            estimated_cost=est,
            potential_saving=potential,
            flags=["CWLLogGroupRetentionTooLong"],
            confidence=80,
            signals=_signals_str(
                {
                    "Region": region,
                    "Group": name,
                    "RetentionDays": retention_i,
                    "SuggestedMaxRetentionDays": int(max_retention_days),
                    "StoredGB": round(stored_gb, 3),
                }
            ),
        )
        if wrote:
            log.info(
                "[check_loggroups_retention_too_long] Wrote: %s (retention=%s days)",
                name,
                retention_i,
            )
