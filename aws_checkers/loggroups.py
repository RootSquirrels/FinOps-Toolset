"""Checkers: Amazon CloudWatch Logs – Log Groups.

  - check_loggroups_no_retention
  - check_loggroups_stale
  - check_loggroups_large_storage
  - check_loggroups_unencrypted
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
from aws_checkers.common import _logger
from core.cloudwatch import CloudWatchBatcher
from core.retry import retry_with_backoff


# ------------------------------- constants -------------------------------- #

_GB = 1024.0 ** 3
_DAYS_IN_MONTH = 30.4375


# ------------------------------- helpers --------------------------------- #

def _bytes_to_gb(b: Optional[int]) -> float:
    """Convert bytes to GB (GiB) safely."""
    return max(0.0, float(b or 0) / _GB)


def _region_from_client(client: Any) -> str:
    return getattr(getattr(client, "meta", None), "region_name", "") or ""


def _extract_writer_logs_cloudwatch(
    args: Tuple[Any, ...],
    kwargs: Dict[str, Any],
) -> Tuple[Any, Any, Optional[Any]]:
    """
    Extract (writer, logs, cloudwatch) in a run_check-compatible way.

    - writer can be positional args[0] or kw 'writer'
    - logs should be kw 'logs' (preferred), fallback args[1]
    - cloudwatch is optional (kw 'cloudwatch', fallback args[2])
    """
    writer = kwargs.get("writer")
    if writer is None and args:
        writer = args[0]

    logs = kwargs.get("logs")
    if logs is None and len(args) >= 2:
        logs = args[1]

    cloudwatch = kwargs.get("cloudwatch")
    if cloudwatch is None and len(args) >= 3:
        cloudwatch = args[2]

    if writer is None or logs is None:
        raise TypeError(
            "Expected 'writer' and 'logs' "
            f"(got writer={writer!r}, logs={logs!r})"
        )
    return writer, logs, cloudwatch


def _list_log_groups(logs, log: logging.Logger) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    try:
        paginator = logs.get_paginator("describe_log_groups")
        for page in paginator.paginate():
            out.extend(page.get("logGroups", []) or [])
    except ClientError as exc:
        log.error("[loggroups] describe_log_groups failed: %s", exc)
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


def _sum_series(series: Any) -> float:
    """Sum a series returned by CloudWatchBatcher (supports list or dict styles)."""
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


def _merge_flags(existing: List[str], incoming: List[str]) -> List[str]:
    if not incoming:
        return existing
    if not existing:
        return list(incoming)
    seen = set(existing)
    for f in incoming:
        if f and f not in seen:
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
            continue
        cur = existing.get(k)
        if cur in (None, "", "NULL") and v not in (None, "", "NULL"):
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


def _dedupe_key(row: Dict[str, Any]) -> Tuple[str, str, str, str]:
    return (
        str(row.get("resource_id") or ""),
        str(row.get("resource_type") or ""),
        str(row.get("region") or ""),
        str(row.get("owner_id") or ""),
    )


def _collect_row(
    rows: Dict[Tuple[str, str, str, str], Dict[str, Any]],
    row: Dict[str, Any],
) -> None:
    """Collect/merge a finding row for unique output (one row per log group)."""
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

    # Keep conservative: for a resource hit by multiple checks, keep max values.
    existing["estimated_cost"] = _max_float(
        existing.get("estimated_cost"), row.get("estimated_cost")
    )
    existing["potential_saving"] = _max_float(
        existing.get("potential_saving"), row.get("potential_saving")
    )
    existing["confidence"] = int(
        max(int(existing.get("confidence") or 0), int(row.get("confidence") or 0))
    )

    # Fill any missing fields
    for k, v in row.items():
        if k in ("flags", "signals", "estimated_cost", "potential_saving", "confidence"):
            continue
        cur = existing.get(k)
        if cur in (None, "", "NULL") and v not in (None, "", "NULL"):
            existing[k] = v


# ----------------------- global run guard (per run) ----------------------- #

_LOGGROUPS_ALREADY_RAN: Set[Tuple[int, str, str]] = set()


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


# --------------------------------- checker -------------------------------- #

@retry_with_backoff(exceptions=(ClientError,))
def check_loggroups(  # pylint: disable=unused-argument
    *args: Any,
    logger: Optional[logging.Logger] = None,
    # thresholds / knobs (keep current defaults)
    stale_lookback_days: int = 14,
    high_ingestion_lookback_days: int = 7,
    high_ingestion_min_gb_per_day: float = 1.0,
    large_storage_min_gb: float = 50.0,
    retention_max_days: int = 90,
    retention_min_stored_gb: float = 5.0,
    **kwargs: Any,
) -> None:
    """
    Global CloudWatch Log Groups checker. Writes ONE row per log group, merging flags.

    This removes duplicate CSV rows when a log group is flagged by multiple checks.
    """
    log = _logger(kwargs.get("logger") or logger)

    try:
        writer, logs, cloudwatch = _extract_writer_logs_cloudwatch(args, kwargs)
    except TypeError as exc:
        log.warning("[check_loggroups] Skipping: %s", exc)
        return

    if not (config.ACCOUNT_ID and config.WRITE_ROW):
        log.warning("[check_loggroups] Skipping: checker config not provided.")
        return

    region = _region_from_client(logs)
    owner = str(config.ACCOUNT_ID)

    run_key = (_writer_key(writer), region, owner)
    if run_key in _LOGGROUPS_ALREADY_RAN:
        log.info("[loggroups] Skipping duplicate run for %s", region)
        return
    _LOGGROUPS_ALREADY_RAN.add(run_key)

    groups = _list_log_groups(logs, log)
    if not groups:
        log.info("[loggroups] No log groups found in %s", region)
        return

    # Pricing (best-effort)
    price_storage_gb_mo = float(config.safe_price("CWL", "STORAGE_GB_MONTH", 0.03))
    price_ingest_gb = float(config.safe_price("CWL", "INGEST_GB", 0.50))

    # Precompute ingestion sums for needed windows if CloudWatch is available
    incoming_7d: Dict[str, float] = {}
    incoming_14d: Dict[str, float] = {}
    period = 3600

    now_utc = datetime.now(timezone.utc).replace(microsecond=0)

    if cloudwatch is not None:
        try:
            start_7 = now_utc - timedelta(days=int(high_ingestion_lookback_days))
            incoming_7d = _fetch_incoming_bytes_sums(
                cloudwatch=cloudwatch,
                region=region,
                groups=groups,
                start=start_7,
                end=now_utc,
                period=period,
                log=log,
            )
        except Exception as exc:  # pylint: disable=broad-except
            log.warning("[loggroups] Failed to fetch %sd ingestion: %s", high_ingestion_lookback_days, exc)
            incoming_7d = {}

        try:
            start_14 = now_utc - timedelta(days=int(stale_lookback_days))
            incoming_14d = _fetch_incoming_bytes_sums(
                cloudwatch=cloudwatch,
                region=region,
                groups=groups,
                start=start_14,
                end=now_utc,
                period=period,
                log=log,
            )
        except Exception as exc:  # pylint: disable=broad-except
            log.warning("[loggroups] Failed to fetch %sd ingestion: %s", stale_lookback_days, exc)
            incoming_14d = {}

    rows: Dict[Tuple[str, str, str, str], Dict[str, Any]] = {}

    for g in groups:
        name = g.get("logGroupName") or ""
        if not name:
            continue

        stored_gb = _bytes_to_gb(g.get("storedBytes"))
        retention = g.get("retentionInDays")
        kms_key = g.get("kmsKeyId")

        base_signals = {
            "Region": region,
            "Group": name,
            "StoredGB": round(stored_gb, 3),
            "RetentionDays": retention,
            "HasKMS": bool(kms_key),
            "MetricFilters": g.get("metricFilterCount"),
        }

        # 1) No retention
        if retention is None:
            est = stored_gb * price_storage_gb_mo
            _collect_row(
                rows,
                {
                    "resource_id": name,
                    "name": name,
                    "resource_type": "CloudWatchLogGroup",
                    "region": region,
                    "owner_id": owner,
                    "flags": ["CWLLogGroupNoRetention"],
                    "estimated_cost": est,
                    "potential_saving": est,
                    "confidence": 100,
                    "signals": dict(base_signals),
                },
            )

        # 2) Stale (zero ingestion over lookback)
        if incoming_14d:
            incoming = float(incoming_14d.get(name, 0.0))
            if incoming <= 0.0:
                est = stored_gb * price_storage_gb_mo
                sig = dict(base_signals)
                sig.update(
                    {
                        "IncomingBytesSum": int(incoming),
                        "StaleLookbackDays": int(stale_lookback_days),
                    }
                )
                _collect_row(
                    rows,
                    {
                        "resource_id": name,
                        "name": name,
                        "resource_type": "CloudWatchLogGroup",
                        "region": region,
                        "owner_id": owner,
                        "flags": ["CWLLogGroupStale"],
                        "estimated_cost": est,
                        "potential_saving": est,
                        "confidence": 100,
                        "signals": sig,
                    },
                )

        # 3) Large storage
        if stored_gb >= float(large_storage_min_gb):
            est = stored_gb * price_storage_gb_mo
            sig = dict(base_signals)
            sig.update({"LargeStorageMinGB": float(large_storage_min_gb)})
            _collect_row(
                rows,
                {
                    "resource_id": name,
                    "name": name,
                    "resource_type": "CloudWatchLogGroup",
                    "region": region,
                    "owner_id": owner,
                    "flags": ["CWLLogGroupLargeStorage"],
                    "estimated_cost": est,
                    "potential_saving": est,
                    "confidence": 100,
                    "signals": sig,
                },
            )

        # 4) Unencrypted (hygiene)
        if not kms_key:
            _collect_row(
                rows,
                {
                    "resource_id": name,
                    "name": name,
                    "resource_type": "CloudWatchLogGroup",
                    "region": region,
                    "owner_id": owner,
                    "flags": ["CWLLogGroupUnencrypted"],
                    "estimated_cost": 0.0,
                    "potential_saving": 0.0,
                    "confidence": 100,
                    "signals": dict(base_signals),
                },
            )

        # 5) High ingestion
        if incoming_7d:
            ingested_bytes = float(incoming_7d.get(name, 0.0))
            ingested_gb = ingested_bytes / _GB
            gb_per_day = ingested_gb / max(1.0, float(high_ingestion_lookback_days))
            if gb_per_day >= float(high_ingestion_min_gb_per_day):
                monthly_gb = gb_per_day * _DAYS_IN_MONTH
                ingest_cost = monthly_gb * price_ingest_gb
                storage_cost = stored_gb * price_storage_gb_mo
                est = float(ingest_cost + storage_cost)

                sig = dict(base_signals)
                sig.update(
                    {
                        "IngestLookbackDays": int(high_ingestion_lookback_days),
                        "IngestedGB": round(ingested_gb, 3),
                        "GBPerDay": round(gb_per_day, 3),
                        "MonthlyGBRunRate": round(monthly_gb, 1),
                        "IngestPricePerGB": round(price_ingest_gb, 4),
                        "StoragePricePerGBMonth": round(price_storage_gb_mo, 4),
                    }
                )

                _collect_row(
                    rows,
                    {
                        "resource_id": name,
                        "name": name,
                        "resource_type": "CloudWatchLogGroup",
                        "region": region,
                        "owner_id": owner,
                        "flags": ["CWLLogGroupHighIngestion"],
                        "estimated_cost": est,
                        "potential_saving": est,
                        "confidence": 90,
                        "signals": sig,
                    },
                )

                # 6) High ingestion + no retention
                if retention is None:
                    _collect_row(
                        rows,
                        {
                            "resource_id": name,
                            "name": name,
                            "resource_type": "CloudWatchLogGroup",
                            "region": region,
                            "owner_id": owner,
                            "flags": ["CWLLogGroupHighIngestionNoRetention"],
                            "estimated_cost": est,
                            "potential_saving": est,
                            "confidence": 95,
                            "signals": sig,
                        },
                    )

        # 7) Retention too long (heuristic)
        if retention is not None:
            try:
                retention_i = int(retention)
            except (TypeError, ValueError):
                retention_i = 0

            if (
                retention_i > int(retention_max_days)
                and stored_gb >= float(retention_min_stored_gb)
            ):
                est = stored_gb * price_storage_gb_mo
                ratio = (float(retention_i) - float(retention_max_days)) / max(1.0, float(retention_i))
                potential = est * max(0.0, min(1.0, ratio))

                sig = dict(base_signals)
                sig.update(
                    {
                        "SuggestedMaxRetentionDays": int(retention_max_days),
                        "RetentionMinStoredGB": float(retention_min_stored_gb),
                        "RetentionReductionRatio": round(max(0.0, min(1.0, ratio)), 3),
                    }
                )

                _collect_row(
                    rows,
                    {
                        "resource_id": name,
                        "name": name,
                        "resource_type": "CloudWatchLogGroup",
                        "region": region,
                        "owner_id": owner,
                        "flags": ["CWLLogGroupRetentionTooLong"],
                        "estimated_cost": est,
                        "potential_saving": potential,
                        "confidence": 80,
                        "signals": sig,
                    },
                )

    ordered = sorted(
        rows.values(),
        key=lambda r: (str(r.get("resource_type") or ""), str(r.get("resource_id") or "")),
    )

    wrote = 0
    for row in ordered:
        try:
            config.WRITE_ROW(  # type: ignore[call-arg]
                writer=writer,
                resource_id=row.get("resource_id"),
                name=row.get("name"),
                resource_type=row.get("resource_type"),
                region=row.get("region"),
                owner_id=row.get("owner_id"),
                flags=row.get("flags") or [],
                estimated_cost=float(row.get("estimated_cost") or 0.0),
                potential_saving=float(row.get("potential_saving") or 0.0),
                confidence=int(row.get("confidence") or 0),
                signals=row.get("signals") or {},
            )
            wrote += 1
        except Exception as exc:  # pylint: disable=broad-except
            log.warning("[loggroups] failed to write %s: %s", row.get("resource_id"), exc)

    log.info("[loggroups] Completed check_loggroups in %s (rows=%d)", region, wrote)
