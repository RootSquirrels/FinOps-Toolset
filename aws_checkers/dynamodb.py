"""Checkers: Amazon DynamoDB — performance, cost signals, and hygiene.

Highlights
- Concurrent DescribeTable, ListTagsOfResource, and DescribeTimeToLive (adaptive workers).
- CloudWatchBatcher metrics for consumed capacity (optional, region-aware).
- Cost estimation (provisioned capacity + storage) and potential savings heuristics.
- Tags go to CSV columns (app_id/app/env), not in signals.
- f-strings, ≤100-char lines, pylint friendly. No redundant API calls.

CSV writer signature (from core):
    writer: csv.writer,
    resource_id: str,
    name: str,
    resource_type: str,
    owner_id: str = "",
    state: str = "",
    creation_date: str = "",
    storage_gb: Union[float, str] = 0.0,
    estimated_cost: Union[float, str] = 0.0,
    app_id: str = "",
    app: str = "",
    env: str = "",
    referenced_in: str = "",
    flags: Union[str, List[str]] = "",
    object_count: Union[int, str, None] = "",
    potential_saving: Union[float, str, None] = None,
    confidence: Optional[int] = None,
    signals: Union[str, Dict[str, Any], List[str], None] = None,
"""

from __future__ import annotations

import concurrent.futures as cf
import logging
from datetime import datetime, timedelta, timezone
from math import ceil
from typing import Any, Dict, List, Optional, Tuple

from botocore.exceptions import ClientError

from aws_checkers import config
from aws_checkers.common import (
    _logger,
    tag_triplet,
    _safe_workers,
    iter_chunks,
    tags_to_dict
)
from core.retry import retry_with_backoff
from core.cloudwatch import CloudWatchBatcher  # type: ignore


# ------------------------------ pricing knobs ------------------------------ #

def _p(service: str, key: str, default: float) -> float:
    return float(config.safe_price(service, key, default))


# Heuristic prices (defaults, region-agnostic). Override via pricing map if needed.
# Provisioned capacity ($/unit-hour)
_DDB_RCU_HR = _p("DDB", "RCU_PER_HOUR", 0.000065)   # ~ $0.065 per 1000 hours
_DDB_WCU_HR = _p("DDB", "WCU_PER_HOUR", 0.00013)
# On-demand ($/million requests)
_DDB_OD_RCU_M = _p("DDB", "OD_RCU_PER_MILLION", 0.25)
_DDB_OD_WCU_M = _p("DDB", "OD_WCU_PER_MILLION", 1.25)
# Storage ($/GB-month)
_DDB_STORAGE_GB_MO = _p("DDB", "STORAGE_GB_MONTH", 0.25)

# Savings heuristics
_UTIL_THRESHOLD = float(_p("DDB", "LOW_UTIL_THRESHOLD", 0.10))  # 10% avg util
_HEADROOM = float(_p("DDB", "PROV_HEADROOM_FACTOR", 1.5))       # 50% headroom


# ------------------------------- tiny helpers ------------------------------ #

def _iso(dt: Optional[datetime]) -> str:
    if not isinstance(dt, datetime):
        return ""
    d = dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    return d.replace(microsecond=0).isoformat()

# ------------------------------- inventories ------------------------------- #

@retry_with_backoff(exceptions=(ClientError,))
def _list_tables(dynamodb, log: logging.Logger) -> List[str]:
    names: List[str] = []
    try:
        paginator = dynamodb.get_paginator("list_tables")
        for page in paginator.paginate():
            for n in page.get("TableNames", []) or []:
                names.append(str(n))
    except ClientError as exc:
        log.error(f"[ddb] list_tables failed: {exc}")
    return names


@retry_with_backoff(exceptions=(ClientError,))
def _describe_table(dynamodb, name: str) -> Dict[str, Any]:
    return dynamodb.describe_table(TableName=name).get("Table", {})  # type: ignore


def _describe_tables_concurrent(
    dynamodb, names: List[str], log: logging.Logger, max_workers: Optional[int]
) -> Dict[str, Dict[str, Any]]:
    out: Dict[str, Dict[str, Any]] = {}
    if not names:
        return out
    workers = _safe_workers(dynamodb, max_workers)
    # Keep in-flight bounded to avoid task storms on large fleets.
    chunk_size = workers * 8
    for chunk in iter_chunks(names, chunk_size):
        with cf.ThreadPoolExecutor(max_workers=workers) as pool:
            futs = {pool.submit(_describe_table, dynamodb, n): n for n in chunk}
            for fut in cf.as_completed(futs):
                n = futs[fut]
                try:
                    out[n] = dict(fut.result())
                except ClientError as exc:
                    log.debug(f"[ddb] describe_table {n} failed: {exc}")
                except Exception as exc:  # pylint: disable=broad-except
                    log.debug(f"[ddb] describe worker {n} error: {exc}")
    return out


@retry_with_backoff(exceptions=(ClientError,))
def _list_tags(dynamodb, table_arn: str) -> List[Dict[str, str]]:
    resp = dynamodb.list_tags_of_resource(ResourceArn=table_arn)
    return resp.get("Tags", []) or []


def _tags_concurrent(
    dynamodb, arns: List[str], log: logging.Logger, max_workers: Optional[int]
) -> Dict[str, List[Dict[str, str]]]:
    out: Dict[str, List[Dict[str, str]]] = {}
    if not arns:
        return out
    workers = _safe_workers(dynamodb, max_workers)
    chunk_size = workers * 8
    for chunk in iter_chunks(arns, chunk_size):
        with cf.ThreadPoolExecutor(max_workers=workers) as pool:
            futs = {pool.submit(_list_tags, dynamodb, arn): arn for arn in chunk}
            for fut in cf.as_completed(futs):
                arn = futs[fut]
                try:
                    out[arn] = list(fut.result())
                except ClientError as exc:
                    log.debug(f"[ddb] list_tags_of_resource {arn} failed: {exc}")
                    out[arn] = []
                except Exception as exc:  # pylint: disable=broad-except
                    log.debug(f"[ddb] tags worker {arn} error: {exc}")
                    out[arn] = []
    return out


@retry_with_backoff(exceptions=(ClientError,))
def _describe_ttl(dynamodb, name: str) -> Dict[str, Any]:
    return dynamodb.describe_time_to_live(TableName=name)  # type: ignore


def _ttl_concurrent(
    dynamodb, names: List[str], log: logging.Logger, max_workers: Optional[int]
) -> Dict[str, Dict[str, Any]]:
    out: Dict[str, Dict[str, Any]] = {}
    if not names:
        return out
    workers = _safe_workers(dynamodb, max_workers)
    chunk_size = workers * 8
    for chunk in iter_chunks(names, chunk_size):
        with cf.ThreadPoolExecutor(max_workers=workers) as pool:
            futs = {pool.submit(_describe_ttl, dynamodb, n): n for n in chunk}
            for fut in cf.as_completed(futs):
                n = futs[fut]
                try:
                    out[n] = dict(fut.result())
                except ClientError as exc:
                    log.debug(f"[ddb] describe_time_to_live {n} failed: {exc}")
                    out[n] = {}
                except Exception as exc:  # pylint: disable=broad-except
                    log.debug(f"[ddb] ttl worker {n} error: {exc}")
                    out[n] = {}
    return out


# ------------------------- CloudWatch (consumed R/W) ----------------------- #

def _cw_region(cloudwatch) -> str:
    return getattr(getattr(cloudwatch, "meta", None), "region_name", "") or ""


def _cw_consumed_capacity(
    cloudwatch,
    region: str,
    names: List[str],
    start: datetime,
    end: datetime,
    log: logging.Logger,
) -> Dict[str, Dict[str, float]]:
    """
    Return { table: {rcu_sum: float, wcu_sum: float} } over [start, end).
    If CloudWatchBatcher is unavailable or region mismatch, return {}.
    """
    out: Dict[str, Dict[str, float]] = {}
    if CloudWatchBatcher is None or not cloudwatch:
        return out
    if _cw_region(cloudwatch) != region:
        return out
    if not names:
        return out

    try:
        batch = CloudWatchBatcher(region=region, client=cloudwatch)
        for n in names:
            dims = [("TableName", n)]
            for metric in ("ConsumedReadCapacityUnits", "ConsumedWriteCapacityUnits"):
                batch.add_q(
                    id_hint=f"{metric}_{n}",
                    namespace="AWS/DynamoDB",
                    metric=metric,
                    dims=dims,
                    stat="Sum",
                    period=300,
                )
        results = batch.execute(start=start, end=end)
    except ClientError as exc:
        log.debug(f"[ddb] CloudWatch metrics failed: {exc}")
        return out
    except Exception as exc:  # pylint: disable=broad-except
        log.debug(f"[ddb] CloudWatch batch error: {exc}")
        return out

    def _sum_series(series: Any) -> float:
        if isinstance(series, list):
            try:
                return float(sum(v for _, v in series))
            except Exception:  # pylint: disable=broad-except
                return 0.0
        if isinstance(series, dict):
            vals = series.get("Values") or []
            try:
                return float(sum(vals))
            except Exception:  # pylint: disable=broad-except
                return 0.0
        return 0.0

    for n in names:
        r = _sum_series(results.get(f"ConsumedReadCapacityUnits_{n}"))
        w = _sum_series(results.get(f"ConsumedWriteCapacityUnits_{n}"))
        out[n] = {"rcu_sum": r, "wcu_sum": w}

    return out


# --------------------------- cost/saving calculators ----------------------- #

def _monthly_storage_cost(bytes_val: int | float) -> float:
    gb = float(bytes_val) / (1024.0 ** 3)
    return gb * _DDB_STORAGE_GB_MO


def _monthly_provisioned_cost(rcu: int, wcu: int) -> float:
    # 730 hours/month approximation
    return float(rcu) * _DDB_RCU_HR * 730.0 + float(wcu) * _DDB_WCU_HR * 730.0


def _monthly_ondemand_cost(rcu_sum: float, wcu_sum: float) -> float:
    # sums are measured in capacity units; convert to "per million requests" pricing
    return (rcu_sum / 1_000_000.0) * _DDB_OD_RCU_M + (wcu_sum / 1_000_000.0) * _DDB_OD_WCU_M


# ------------------------------- extract args ------------------------------ #

def _extract_writer_ddb(*args, **kwargs) -> Tuple[Any, Any]:
    writer = kwargs.get("writer", args[0] if len(args) >= 1 else None)
    dynamodb = kwargs.get("dynamodb", args[1] if len(args) >= 2 else None)
    if writer is None or dynamodb is None:
        raise TypeError(f"Expected 'writer' and 'dynamodb' (got {writer!r}, {dynamodb!r})")
    return writer, dynamodb


def _extract_writer_ddb_cw(*args, **kwargs) -> Tuple[Any, Any, Optional[Any]]:
    writer, dynamodb = _extract_writer_ddb(*args, **kwargs)
    cloudwatch = kwargs.get("cloudwatch", args[2] if len(args) >= 3 else None)
    return writer, dynamodb, cloudwatch


# --------------------------------- checkers -------------------------------- #

@retry_with_backoff(exceptions=(ClientError,))
def check_dynamodb_tables_no_pitr(  # pylint: disable=unused-argument
    *args,
    logger: Optional[logging.Logger] = None,
    max_workers: Optional[int] = None,
    **kwargs,
) -> None:
    """Flag tables with Point-in-Time Recovery disabled (hygiene)."""
    log = _logger(kwargs.get("logger") or logger)
    try:
        writer, dynamodb = _extract_writer_ddb(*args, **kwargs)
    except TypeError as exc:
        log.warning(f"[check_dynamodb_tables_no_pitr] Skipping: {exc}")
        return
    if not (config.ACCOUNT_ID and config.WRITE_ROW):
        log.warning("[check_dynamodb_tables_no_pitr] Skipping: checker config not provided.")
        return

    region = getattr(getattr(dynamodb, "meta", None), "region_name", "") or ""
    names = _list_tables(dynamodb, log)
    desc = _describe_tables_concurrent(dynamodb, names, log, max_workers)
    # Tags
    arns = [t.get("TableArn") for t in desc.values() if t.get("TableArn")]
    tags_map = _tags_concurrent(dynamodb, arns, log, max_workers)
    arn_to_tags = {arn: tags_to_dict(tags) for arn, tags in tags_map.items()}

    for name, tab in desc.items():
        arn = tab.get("TableArn", "")
        pitrd = (tab.get("PointInTimeRecoverySummary") or {}).get("PointInTimeRecoveryStatus")
        pitr_on = str(pitrd).upper() == "ENABLED"
        if pitr_on:
            continue

        tags = arn_to_tags.get(arn, {})
        app_id, app, env = tag_triplet(tags)

        config.WRITE_ROW(
            writer=writer,
            resource_id=name,
            name=name,
            region=region,
            resource_type="Dynamo_DB",
            flags=["DDBPITRDisabled"],
            state=str(tab.get("TableStatus") or ""),
            creation_date=_iso(tab.get("CreationDateTime")),
            storage_gb=round(float(tab.get("TableSizeBytes") or 0.0) / (1024**3), 3),
            object_count=int(tab.get("ItemCount") or 0),
            estimated_cost=0.0,
            potential_saving=0.0,
            app_id=app_id,
            app=app,
            env=env,
            signals={
                "Region": region,
                "BillingMode": (tab.get("BillingModeSummary") or {}).get("BillingMode", "PROVISIONED"),
            },
        )
        log.info(f"[ddb] Wrote PITR disabled: {name}")


@retry_with_backoff(exceptions=(ClientError,))
def check_dynamodb_tables_no_ttl(  # pylint: disable=unused-argument
    *args,
    logger: Optional[logging.Logger] = None,
    max_workers: Optional[int] = None,
    **kwargs,
) -> None:
    """Flag tables with TTL disabled (hygiene)."""
    log = _logger(kwargs.get("logger") or logger)
    try:
        writer, dynamodb = _extract_writer_ddb(*args, **kwargs)
    except TypeError as exc:
        log.warning(f"[check_dynamodb_tables_no_ttl] Skipping: {exc}")
        return
    if not (config.ACCOUNT_ID and config.WRITE_ROW):
        log.warning("[check_dynamodb_tables_no_ttl] Skipping: checker config not provided.")
        return

    region = getattr(getattr(dynamodb, "meta", None), "region_name", "") or ""
    names = _list_tables(dynamodb, log)
    desc = _describe_tables_concurrent(dynamodb, names, log, max_workers)
    # TTL (parallel)
    ttl_map = _ttl_concurrent(dynamodb, names, log, max_workers)
    # Tags
    arns = [t.get("TableArn") for t in desc.values() if t.get("TableArn")]
    tags_map = _tags_concurrent(dynamodb, arns, log, max_workers)
    arn_to_tags = {arn: tags_to_dict(tags) for arn, tags in tags_map.items()}

    for name, tab in desc.items():
        status = (ttl_map.get(name) or {}).get("TimeToLiveDescription") or {}
        ttl_on = str(status.get("TimeToLiveStatus", "")).upper() == "ENABLED"
        if ttl_on:
            continue

        tags = arn_to_tags.get(tab.get("TableArn", ""), {})
        app_id, app, env = tag_triplet(tags)

        config.WRITE_ROW(
            writer=writer,
            resource_id=name,
            name=name,
            region=region,
            resource_type="Dynamo_DB",
            flags=["DDBTTLDisabled"],
            state=str(tab.get("TableStatus") or ""),
            creation_date=_iso(tab.get("CreationDateTime")),
            storage_gb=round(float(tab.get("TableSizeBytes") or 0.0) / (1024**3), 3),
            object_count=int(tab.get("ItemCount") or 0),
            estimated_cost=0.0,
            potential_saving=0.0,
            app_id=app_id,
            app=app,
            env=env,
            signals={
                "Region": region,
                "BillingMode": (tab.get("BillingModeSummary") or {}).get("BillingMode", "PROVISIONED"),
            },
        )
        log.info(f"[ddb] Wrote TTL disabled: {name}")


@retry_with_backoff(exceptions=(ClientError,))
def check_dynamodb_tables_unused(  # pylint: disable=unused-argument
    *args,
    logger: Optional[logging.Logger] = None,
    lookback_days: int = 14,
    max_workers: Optional[int] = None,
    **kwargs,
) -> None:
    """
    Flag tables with no traffic in the last `lookback_days`.

    Potential saving:
      - Provisioned: monthly provisioned capacity cost (assumes delete or switch to OD).
      - On-demand: 0 (no capacity to reduce).
    """
    log = _logger(kwargs.get("logger") or logger)
    try:
        writer, dynamodb, cloudwatch = _extract_writer_ddb_cw(*args, **kwargs)
    except TypeError as exc:
        log.warning(f"[check_dynamodb_tables_unused] Skipping: {exc}")
        return
    if not (config.ACCOUNT_ID and config.WRITE_ROW):
        log.warning("[check_dynamodb_tables_unused] Skipping: checker config not provided.")
        return

    region = getattr(getattr(dynamodb, "meta", None), "region_name", "") or ""
    names = _list_tables(dynamodb, log)
    desc = _describe_tables_concurrent(dynamodb, names, log, max_workers)
    arns = [t.get("TableArn") for t in desc.values() if t.get("TableArn")]
    tags_map = _tags_concurrent(dynamodb, arns, log, max_workers)
    arn_to_tags = {arn: tags_to_dict(tags) for arn, tags in tags_map.items()}

    start = datetime.now(timezone.utc) - timedelta(days=int(lookback_days))
    end = datetime.now(timezone.utc)
    cw = _cw_consumed_capacity(cloudwatch, region, names, start, end, log)

    for name, tab in desc.items():
        rcu_sum = float((cw.get(name) or {}).get("rcu_sum") or 0.0)
        wcu_sum = float((cw.get(name) or {}).get("wcu_sum") or 0.0)
        if rcu_sum > 0.0 or wcu_sum > 0.0:
            continue

        billing = (tab.get("BillingModeSummary") or {}).get("BillingMode", "PROVISIONED")
        prov = tab.get("ProvisionedThroughput") or {}
        rcu = int(prov.get("ReadCapacityUnits") or 0)
        wcu = int(prov.get("WriteCapacityUnits") or 0)

        est_storage = _monthly_storage_cost(float(tab.get("TableSizeBytes") or 0.0))
        est_prov = 0.0 if billing == "PAY_PER_REQUEST" else _monthly_provisioned_cost(rcu, wcu)
        pot = est_prov  # storage remains even if unused

        tags = arn_to_tags.get(tab.get("TableArn", ""), {})
        app_id, app, env = tag_triplet(tags)

        config.WRITE_ROW(
            writer=writer,
            resource_id=name,
            name=name,
            resource_type="Dynamo_DB",
            region=region,
            flags=["DDBTableNoTraffic"],
            state=str(tab.get("TableStatus") or ""),
            creation_date=_iso(tab.get("CreationDateTime")),
            storage_gb=round(float(tab.get("TableSizeBytes") or 0.0) / (1024**3), 3),
            object_count=int(tab.get("ItemCount") or 0),
            estimated_cost=round(est_storage + est_prov, 4),
            potential_saving=round(pot, 4),
            app_id=app_id,
            app=app,
            env=env,
            signals={
                "Region": region,
                "BillingMode": billing,
                "RCU": rcu,
                "WCU": wcu,
                "LookbackDays": int(lookback_days),
                "ConsumedRCU": rcu_sum,
                "ConsumedWCU": wcu_sum,
            },
        )
        log.info(f"[ddb] Wrote table no-traffic: {name}")


@retry_with_backoff(exceptions=(ClientError,))
def check_dynamodb_tables_overprovisioned(  # pylint: disable=unused-argument
    *args,
    logger: Optional[logging.Logger] = None,
    lookback_days: int = 14,
    max_workers: Optional[int] = None,
    **kwargs,
) -> None:
    """
    Flag PROVISIONED tables with low utilization (avg < threshold).

    Recommendation: reduce provisioned capacity or switch to on-demand.
    Potential saving: current monthly provisioned cost minus recommended capacity cost.
    """
    log = _logger(kwargs.get("logger") or logger)
    try:
        writer, dynamodb, cloudwatch = _extract_writer_ddb_cw(*args, **kwargs)
    except TypeError as exc:
        log.warning(f"[check_dynamodb_tables_overprovisioned] Skipping: {exc}")
        return
    if not (config.ACCOUNT_ID and config.WRITE_ROW):
        log.warning(
            "[check_dynamodb_tables_overprovisioned] Skipping: checker config not provided."
        )
        return

    region = getattr(getattr(dynamodb, "meta", None), "region_name", "") or ""
    names = _list_tables(dynamodb, log)
    desc = _describe_tables_concurrent(dynamodb, names, log, max_workers)
    arns = [t.get("TableArn") for t in desc.values() if t.get("TableArn")]
    tags_map = _tags_concurrent(dynamodb, arns, log, max_workers)
    arn_to_tags = {arn: tags_to_dict(tags) for arn, tags in tags_map.items()}

    start = datetime.now(timezone.utc) - timedelta(days=int(lookback_days))
    end = datetime.now(timezone.utc)
    cw = _cw_consumed_capacity(cloudwatch, region, names, start, end, log)
    window_secs = (end - start).total_seconds() or 1.0

    for name, tab in desc.items():
        billing = (tab.get("BillingModeSummary") or {}).get("BillingMode", "PROVISIONED")
        if billing == "PAY_PER_REQUEST":
            continue  # OD tables cannot be overprovisioned by definition

        prov = tab.get("ProvisionedThroughput") or {}
        rcu = int(prov.get("ReadCapacityUnits") or 0)
        wcu = int(prov.get("WriteCapacityUnits") or 0)
        if rcu <= 0 and wcu <= 0:
            continue

        r_sum = float((cw.get(name) or {}).get("rcu_sum") or 0.0)
        w_sum = float((cw.get(name) or {}).get("wcu_sum") or 0.0)
        r_avg_sec = r_sum / window_secs
        w_avg_sec = w_sum / window_secs

        r_util = (r_avg_sec / max(1, rcu)) if rcu else 0.0
        w_util = (w_avg_sec / max(1, wcu)) if wcu else 0.0
        low_util = (r_util < _UTIL_THRESHOLD) and (w_util < _UTIL_THRESHOLD)
        if not low_util:
            continue

        # Recommended new capacity: headroom over observed avg
        rec_rcu = max(1, int(ceil(r_avg_sec * _HEADROOM)))
        rec_wcu = max(1, int(ceil(w_avg_sec * _HEADROOM)))

        cur_cost = _monthly_provisioned_cost(rcu, wcu)
        rec_cost = _monthly_provisioned_cost(rec_rcu, rec_wcu)
        saving = max(0.0, cur_cost - rec_cost)

        tags = arn_to_tags.get(tab.get("TableArn", ""), {})
        app_id, app, env = tag_triplet(tags)

        config.WRITE_ROW(
            writer=writer,
            resource_id=name,
            resource_type="Dynamo_DB",
            name=name,
            region=region,
            flags=["DDBOverprovisioned"],
            state=str(tab.get("TableStatus") or ""),
            creation_date=_iso(tab.get("CreationDateTime")),
            storage_gb=round(float(tab.get("TableSizeBytes") or 0.0) / (1024**3), 3),
            object_count=int(tab.get("ItemCount") or 0),
            estimated_cost=round(cur_cost + _monthly_storage_cost(float(tab.get("TableSizeBytes") or 0.0)), 4),  # noqa: E501
            potential_saving=round(saving, 4),
            app_id=app_id,
            app=app,
            env=env,
            signals={
                "Region": region,
                "RCU": rcu,
                "WCU": wcu,
                "AvgRCUps": round(r_avg_sec, 4),
                "AvgWCUps": round(w_avg_sec, 4),
                "RecRCU": rec_rcu,
                "RecWCU": rec_wcu,
                "UtilR": round(r_util, 4),
                "UtilW": round(w_util, 4),
                "LookbackDays": int(lookback_days),
            },
        )
        log.info(f"[ddb] Wrote overprovisioned table: {name}")
