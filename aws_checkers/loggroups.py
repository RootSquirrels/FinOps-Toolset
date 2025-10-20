"""Checkers: Amazon CloudWatch Logs – Log Groups.

Checks included:

  - check_loggroups_no_retention
      Log groups with "Never expire" (no retention policy). Estimates storage cost.

  - check_loggroups_stale
      No IncomingBytes in the lookback window but still storing data.

  - check_loggroups_large_storage
      Log groups with big storedBytes (threshold). Highlights high storage cost.

  - check_loggroups_unencrypted
      Log groups without a KMS key (hygiene).

Design:
  - Dependencies via finops_toolset.checkers.config.setup(...).
  - CloudWatch via finops_toolset.cloudwatch.CloudWatchBatcher.
  - Tolerant signatures; graceful skips; no return values.
  - UTC datetimes; pylint-friendly; lines ≤ 100 chars.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple

from botocore.exceptions import ClientError

from aws_checkers import config
from aws_checkers.common import (
    _logger,
    _signals_str,
)
from core.retry import retry_with_backoff
from core.cloudwatch import CloudWatchBatcher


# -------------------------------- helpers -------------------------------- #

def _bytes_to_gb(b: Optional[int]) -> float:
    return max(0.0, float(b or 0) / (1024.0 ** 3))


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
        writer, logs, cloudwatch = _extract_writer_logs_cw(args, kwargs)  # cloudwatch unused
    except TypeError as exc:
        log.warning("[check_loggroups_no_retention] Skipping: %s", exc)
        return
    if not (config.ACCOUNT_ID and config.WRITE_ROW and config.GET_PRICE):
        log.warning("[check_loggroups_no_retention] Skipping: checker config not provided.")
        return

    region = getattr(getattr(logs, "meta", None), "region_name", "") or ""
    price_gb_mo = config.safe_price("CWL", "STORAGE_GB_MONTH", 0.03)

    groups = _list_log_groups(logs, log)
    for g in groups:
        name = g.get("logGroupName") or ""
        if not name or g.get("retentionInDays") is not None:
            continue

        stored_gb = _bytes_to_gb(g.get("storedBytes"))
        est = stored_gb * float(price_gb_mo)
        potential = est  # heuristic if you applied sensible retention

        try:
            # type: ignore[call-arg]
            config.WRITE_ROW(
                writer=writer,
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
        except Exception as exc:  # pylint: disable=broad-except
            log.warning("[check_loggroups_no_retention] write_row %s: %s", name, exc)

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

    region = getattr(getattr(logs, "meta", None), "region_name", "") or ""
    groups = _list_log_groups(logs, log)
    if not groups:
        return

    now_utc = datetime.now(timezone.utc).replace(microsecond=0)
    start = now_utc - timedelta(days=int(lookback_days))
    period = 3600

    id_map: Dict[str, str] = {}
    results: Dict[str, Any] = {}
    metrics_ok = True

    try:
        cw = CloudWatchBatcher(region=region, client=cloudwatch)
        for g in groups:
            name = g.get("logGroupName")
            if not name:
                continue
            qid = f"in_{name}"
            dims = [("LogGroupName", name)]
            cw.add_q(
                id_hint=qid,
                namespace="AWS/Logs",
                metric="IncomingBytes",
                dims=dims,
                stat="Sum",
                period=period,
            )
            id_map[name] = qid
        results = cw.execute(start=start, end=now_utc)
    except ClientError as exc:
        log.warning("[check_loggroups_stale] CloudWatch metrics unavailable: %s", exc)
        metrics_ok = False
    except Exception as exc:  # pylint: disable=broad-except
        log.warning("[check_loggroups_stale] CloudWatch batch error: %s", exc)
        metrics_ok = False

    if not metrics_ok:
        return

    price_gb_mo = config.safe_price("CWL", "STORAGE_GB_MONTH", 0.03)

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
                return float(sum(vals))
            except Exception:  # pylint: disable=broad-except
                return 0.0
        return 0.0

    for g in groups:
        name = g.get("logGroupName") or ""
        if not name:
            continue

        incoming = _sum_series(results.get(id_map.get(name)))
        if incoming > 0.0:
            continue

        stored_gb = _bytes_to_gb(g.get("storedBytes"))
        est = stored_gb * float(price_gb_mo)
        potential = est  # if you delete the stale group

        try:
            # type: ignore[call-arg]
            config.WRITE_ROW(
                writer=writer,
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
        except Exception as exc:  # pylint: disable=broad-except
            log.warning("[check_loggroups_stale] write_row %s: %s", name, exc)

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
        writer, logs, cloudwatch = _extract_writer_logs_cw(args, kwargs)  # cloudwatch unused
    except TypeError as exc:
        log.warning("[check_loggroups_large_storage] Skipping: %s", exc)
        return
    if not (config.ACCOUNT_ID and config.WRITE_ROW and config.GET_PRICE):
        log.warning("[check_loggroups_large_storage] Skipping: checker config not provided.")
        return

    region = getattr(getattr(logs, "meta", None), "region_name", "") or ""
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
        potential = est  # if you prune via retention/export

        try:
            # type: ignore[call-arg]
            config.WRITE_ROW(
                writer=writer,
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
        except Exception as exc:  # pylint: disable=broad-except
            log.warning("[check_loggroups_large_storage] write_row %s: %s", name, exc)

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
        writer, logs, cloudwatch = _extract_writer_logs_cw(args, kwargs)  # cloudwatch unused
    except TypeError as exc:
        log.warning("[check_loggroups_unencrypted] Skipping: %s", exc)
        return
    if not (config.ACCOUNT_ID and config.WRITE_ROW):
        log.warning("[check_loggroups_unencrypted] Skipping: checker config not provided.")
        return

    region = getattr(getattr(logs, "meta", None), "region_name", "") or ""
    groups = _list_log_groups(logs, log)

    for g in groups:
        name = g.get("logGroupName") or ""
        if not name or g.get("kmsKeyId"):
            continue

        try:
            # type: ignore[call-arg]
            config.WRITE_ROW(
                writer=writer,
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
        except Exception as exc:  # pylint: disable=broad-except
            log.warning("[check_loggroups_unencrypted] write_row %s: %s", name, exc)

        log.info("[check_loggroups_unencrypted] Wrote: %s", name)
