"""Checkers: Amazon DynamoDB.

Contains:
  - check_dynamodb_unused_tables
  - check_dynamodb_underutilized_provisioned
  - check_dynamodb_continuous_backups
  - check_dynamodb_gsi_underutilized
  - check_dynamodb_streams_enabled_no_consumers
  - check_dynamodb_ttl_disabled
  - check_dynamodb_table_class_mismatch
  - check_dynamodb_global_tables_low_activity

Design:
  - Shared deps via finops_toolset.checkers.config.setup(...)
  - CloudWatch via finops_toolset.cloudwatch.CloudWatchBatcher
  - Tolerant signatures; graceful skips if clients/config missing
  - Emits Flags, Signals (compact k=v), Estimated_Cost_USD, Potential_Saving_USD
  - Timezone-aware (datetime.now(timezone.utc)), lazy %s logging
"""

from __future__ import annotations

import math
import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple

from botocore.exceptions import ClientError

from aws_checkers import config
from core.retry import retry_with_backoff
from core.cloudwatch import CloudWatchBatcher


# ----------------------------- helpers --------------------------------- #

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


def _sum_from_result(res: Any) -> float:
    """Reduce CloudWatchBatcher result → sum of values; supports [(ts, val)] or {Values:[...] }."""
    if res is None:
        return 0.0
    if isinstance(res, list) and res and isinstance(res[0], tuple):
        try:
            return float(sum(float(v) for _, v in res))
        except Exception:  # pylint: disable=broad-except
            return 0.0
    if isinstance(res, dict):
        values = res.get("Values") or res.get("values") or []
        try:
            return float(sum(values))
        except Exception:  # pylint: disable=broad-except
            return 0.0
    return 0.0


def _max_from_result(res: Any) -> float:
    """Reduce CloudWatchBatcher result → max value; supports [(ts, val)] or {Values:[...] }."""
    if res is None:
        return 0.0
    if isinstance(res, list) and res and isinstance(res[0], tuple):
        try:
            return float(max(float(v) for _, v in res))
        except Exception:  # pylint: disable=broad-except
            return 0.0
    if isinstance(res, dict):
        values = res.get("Values") or res.get("values") or []
        try:
            return float(max(values)) if values else 0.0
        except Exception:  # pylint: disable=broad-except
            return 0.0
    return 0.0


def _extract_writer_ddb_cw(
    args: Tuple[Any, ...],
    kwargs: Dict[str, Any],
) -> Tuple[Any, Any, Any]:
    """Accept writer/dynamodb/cloudwatch passed positionally or by keyword; prefer keywords."""
    writer = kwargs.get("writer", args[0] if len(args) >= 1 else None)
    dynamodb = kwargs.get("dynamodb", args[1] if len(args) >= 2 else None)
    cloudwatch = kwargs.get("cloudwatch", args[2] if len(args) >= 3 else None)
    if writer is None or dynamodb is None or cloudwatch is None:
        raise TypeError(
            "Expected 'writer', 'dynamodb', and 'cloudwatch' "
            f"(got writer={writer!r}, dynamodb={dynamodb!r}, cloudwatch={cloudwatch!r})"
        )
    return writer, dynamodb, cloudwatch


def _list_tables(dynamodb, log: logging.Logger) -> List[str]:
    names: List[str] = []
    try:
        last: Optional[str] = None
        while True:
            params: Dict[str, Any] = {}
            if last:
                params["ExclusiveStartTableName"] = last
            resp = dynamodb.list_tables(**params)
            for n in resp.get("TableNames", []) or []:
                names.append(n)
            last = resp.get("LastEvaluatedTableName")
            if not last:
                break
    except ClientError as exc:
        log.error("[dynamodb] list_tables failed: %s", exc)
    return names


def _describe_table(dynamodb, name: str, log: logging.Logger) -> Dict[str, Any]:
    try:
        resp = dynamodb.describe_table(TableName=name)
        return resp.get("Table", {}) or {}
    except ClientError as exc:
        log.debug("[dynamodb] describe_table failed for %s: %s", name, exc)
        return {}


def _pitr_status(dynamodb, name: str, log: logging.Logger) -> Dict[str, Any]:
    """Best-effort PITR status via describe_continuous_backups."""
    try:
        resp = dynamodb.describe_continuous_backups(TableName=name)
        return resp.get("ContinuousBackupsDescription", {}) or {}
    except ClientError as exc:
        log.debug("[dynamodb] describe_continuous_backups failed for %s: %s", name, exc)
        return {}


def _table_storage_gb(table: Dict[str, Any]) -> float:
    size_bytes = float(table.get("TableSizeBytes") or 0)
    return max(0.0, size_bytes / (1024.0 ** 3))


def _provisioned_monthly_cost(rcu: float, wcu: float) -> float:
    """Heuristic monthly cost from provisioned capacity."""
    price_rcu_hr = config.safe_price("DynamoDB", "PROV_RCU_HR", 0.00013)
    price_wcu_hr = config.safe_price("DynamoDB", "PROV_WCU_HR", 0.00065)
    hours = 730.0
    return hours * (rcu * price_rcu_hr + wcu * price_wcu_hr)


# ============================ 1) Unused tables ============================ #

@retry_with_backoff(exceptions=(ClientError,))
def check_dynamodb_unused_tables(  # pylint: disable=unused-argument
    *args,
    logger: Optional[logging.Logger] = None,
    lookback_days: int = 30,
    **kwargs,
) -> None:
    """
    Flag tables whose Sum(ConsumedReadCapacityUnits) + Sum(ConsumedWriteCapacityUnits) == 0
    over the lookback window. Estimate cost = storage + (if PROVISIONED) current throughput.
    """
    log = _logger(kwargs.get("logger") or logger)

    try:
        writer, dynamodb, cloudwatch = _extract_writer_ddb_cw(args, kwargs)
    except TypeError as exc:
        log.warning("[check_dynamodb_unused_tables] Skipping: %s", exc)
        return
    if not (config.ACCOUNT_ID and config.WRITE_ROW and config.GET_PRICE):
        log.warning("[check_dynamodb_unused_tables] Skipping: checker config not provided.")
        return

    region = getattr(getattr(dynamodb, "meta", None), "region_name", "") or ""
    now_utc = datetime.now(timezone.utc).replace(microsecond=0)
    start_time = now_utc - timedelta(days=lookback_days)
    period = 3600  # 1h

    names = _list_tables(dynamodb, log)
    if not names:
        log.info("[check_dynamodb_unused_tables] No tables in %s", region)
        return

    metrics_ok = True
    results: Dict[str, Any] = {}
    id_map: Dict[str, Dict[str, str]] = {}

    try:
        cw_region = getattr(getattr(cloudwatch, "meta", None), "region_name", "") or region
        cw_batch = CloudWatchBatcher(region=cw_region, client=cloudwatch)
        for name in names:
            dims = [("TableName", name)]
            rid = f"rcu_{name}"
            wid = f"wcu_{name}"
            cw_batch.add_q(id_hint=rid, namespace="AWS/DynamoDB", metric="ConsumedReadCapacityUnits",
                           dims=dims, stat="Sum", period=period)
            cw_batch.add_q(id_hint=wid, namespace="AWS/DynamoDB", metric="ConsumedWriteCapacityUnits",
                           dims=dims, stat="Sum", period=period)
            id_map[name] = {"rcu": rid, "wcu": wid}
        results = cw_batch.execute(start=start_time, end=now_utc)
    except ClientError as exc:
        log.warning("[check_dynamodb_unused_tables] CloudWatch metrics unavailable: %s", exc)
        metrics_ok = False
    except Exception as exc:  # pylint: disable=broad-except
        log.warning("[check_dynamodb_unused_tables] CloudWatch batch error: %s", exc)
        metrics_ok = False

    if not metrics_ok:
        return

    price_storage = config.safe_price("DynamoDB", "STORAGE_GB_MONTH", 0.25)

    for name in names:
        rsum = _sum_from_result(results.get(id_map.get(name, {}).get("rcu")))
        wsum = _sum_from_result(results.get(id_map.get(name, {}).get("wcu")))
        if (rsum + wsum) > 0.0:
            continue

        tbl = _describe_table(dynamodb, name, log)
        arn = tbl.get("TableArn") or name
        billing_mode = (tbl.get("BillingModeSummary", {}).get("BillingMode") or "PROVISIONED").upper()
        rcu = float(tbl.get("ProvisionedThroughput", {}).get("ReadCapacityUnits") or 0)
        wcu = float(tbl.get("ProvisionedThroughput", {}).get("WriteCapacityUnits") or 0)
        storage_gb = _table_storage_gb(tbl)

        est_storage = storage_gb * price_storage
        est_prov = _provisioned_monthly_cost(rcu, wcu) if billing_mode == "PROVISIONED" else 0.0
        estimated_cost = est_storage + est_prov
        potential_saving = estimated_cost

        flags = ["DynamoDBTableUnused"]

        signals = _signals_str(
            {
                "Region": region,
                "TableName": name,
                "ARN": arn,
                "BillingMode": billing_mode,
                "RCU": int(rcu),
                "WCU": int(wcu),
                "StorageGB": round(storage_gb, 3),
                "ConsumedRCUSum": int(rsum),
                "ConsumedWCUSum": int(wsum),
                "LookbackDays": lookback_days,
            }
        )

        try:
            # type: ignore[call-arg]
            config.WRITE_ROW(
                writer=writer,
                resource_id=arn,
                name=name,
                owner_id=config.ACCOUNT_ID,  # type: ignore[arg-type]
                resource_type="DynamoDBTable",
                estimated_cost=estimated_cost,
                potential_saving=potential_saving,
                flags=flags,
                confidence=100,
                signals=signals,
            )
        except Exception as exc:  # pylint: disable=broad-except
            log.warning("[check_dynamodb_unused_tables] write_row failed for %s: %s", name, exc)

        log.info("[check_dynamodb_unused_tables] Wrote unused table: %s (storage=%.3fGB mode=%s)", name, storage_gb, billing_mode)


# =========== 2) Provisioned mode – underutilized throughput ============== #

@retry_with_backoff(exceptions=(ClientError,))
def check_dynamodb_underutilized_provisioned(  # pylint: disable=unused-argument
    *args,
    logger: Optional[logging.Logger] = None,
    lookback_days: int = 30,
    utilization_threshold: float = 0.10,
    headroom: float = 0.20,
    **kwargs,
) -> None:
    """
    Flag PROVISIONED tables where avg consumed RCU/WCU << current provisioned.

    avg_rcu_per_s = Sum(ConsumedRCU) / seconds_in_window
    avg_wcu_per_s = Sum(ConsumedWCU) / seconds_in_window
    utilization_read  = avg_rcu_per_s / RCU
    utilization_write = avg_wcu_per_s / WCU
    If both utilizations < utilization_threshold (default 10%), flag.

    Savings (heuristic):
      current_cost  = monthly(provisioned RCU/WCU)
      recommended   = ceil(avg_per_sec * (1 + headroom))
      potential_saving = max(0, current_cost - monthly(recommended))
    """
    log = _logger(kwargs.get("logger") or logger)

    try:
        writer, dynamodb, cloudwatch = _extract_writer_ddb_cw(args, kwargs)
    except TypeError as exc:
        log.warning("[check_dynamodb_underutilized_provisioned] Skipping: %s", exc)
        return
    if not (config.ACCOUNT_ID and config.WRITE_ROW and config.GET_PRICE):
        log.warning("[check_dynamodb_underutilized_provisioned] Skipping: checker config not provided.")
        return

    region = getattr(getattr(dynamodb, "meta", None), "region_name", "") or ""
    now_utc = datetime.now(timezone.utc).replace(microsecond=0)
    start_time = now_utc - timedelta(days=lookback_days)
    period = 300  # 5m
    seconds = float(lookback_days) * 86400.0 if lookback_days > 0 else 1.0

    names = _list_tables(dynamodb, log)
    if not names:
        return

    prov_names: List[str] = []
    table_meta: Dict[str, Dict[str, Any]] = {}
    for name in names:
        t = _describe_table(dynamodb, name, log)
        mode = (t.get("BillingModeSummary", {}).get("BillingMode") or "PROVISIONED").upper()
        if mode != "PROVISIONED":
            continue
        rcu = float(t.get("ProvisionedThroughput", {}).get("ReadCapacityUnits") or 0)
        wcu = float(t.get("ProvisionedThroughput", {}).get("WriteCapacityUnits") or 0)
        table_meta[name] = {"arn": t.get("TableArn") or name, "rcu": rcu, "wcu": wcu}
        prov_names.append(name)

    if not prov_names:
        log.info("[check_dynamodb_underutilized_provisioned] No PROVISIONED tables in %s", region)
        return

    metrics_ok = True
    results: Dict[str, Any] = {}
    id_map: Dict[str, Dict[str, str]] = {}
    try:
        cw_region = getattr(getattr(cloudwatch, "meta", None), "region_name", "") or region
        cw_batch = CloudWatchBatcher(region=cw_region, client=cloudwatch)
        for name in prov_names:
            dims = [("TableName", name)]
            rid = f"rcu_{name}"
            wid = f"wcu_{name}"
            cw_batch.add_q(id_hint=rid, namespace="AWS/DynamoDB", metric="ConsumedReadCapacityUnits",
                           dims=dims, stat="Sum", period=period)
            cw_batch.add_q(id_hint=wid, namespace="AWS/DynamoDB", metric="ConsumedWriteCapacityUnits",
                           dims=dims, stat="Sum", period=period)
            id_map[name] = {"rcu": rid, "wcu": wid}
        results = cw_batch.execute(start=start_time, end=now_utc)
    except ClientError as exc:
        log.warning("[check_dynamodb_underutilized_provisioned] CloudWatch metrics unavailable: %s", exc)
        metrics_ok = False
    except Exception as exc:  # pylint: disable=broad-except
        log.warning("[check_dynamodb_underutilized_provisioned] CloudWatch batch error: %s", exc)
        metrics_ok = False

    if not metrics_ok:
        return

    for name in prov_names:
        meta = table_meta.get(name, {})
        rcu = float(meta.get("rcu") or 0.0)
        wcu = float(meta.get("wcu") or 0.0)
        arn = meta.get("arn") or name

        rsum = _sum_from_result(results.get(id_map.get(name, {}).get("rcu")))
        wsum = _sum_from_result(results.get(id_map.get(name, {}).get("wcu")))

        avg_rcu_ps = (rsum / seconds) if seconds > 0 else 0.0
        avg_wcu_ps = (wsum / seconds) if seconds > 0 else 0.0

        util_r = (avg_rcu_ps / rcu) if rcu > 0 else 0.0
        util_w = (avg_wcu_ps / wcu) if wcu > 0 else 0.0

        if (rcu <= 0 and wcu <= 0) or (util_r >= utilization_threshold or util_w >= utilization_threshold):
            continue

        current_cost = _provisioned_monthly_cost(rcu, wcu)
        rec_rcu = max(1, int(math.ceil(avg_rcu_ps * (1.0 + headroom))))
        rec_wcu = max(1, int(math.ceil(avg_wcu_ps * (1.0 + headroom))))
        rec_cost = _provisioned_monthly_cost(rec_rcu, rec_wcu)
        potential_saving = max(0.0, current_cost - rec_cost)

        tbl = _describe_table(dynamodb, name, log)
        storage_gb = _table_storage_gb(tbl)

        flags = ["DynamoDBProvisionedUnderutilized"]

        signals = _signals_str(
            {
                "Region": region,
                "TableName": name,
                "ARN": arn,
                "RCU": int(rcu),
                "WCU": int(wcu),
                "AvgRCU_per_s": round(avg_rcu_ps, 3),
                "AvgWCU_per_s": round(avg_wcu_ps, 3),
                "UtilRead": round(util_r, 3),
                "UtilWrite": round(util_w, 3),
                "SuggestedRCU": rec_rcu,
                "SuggestedWCU": rec_wcu,
                "StorageGB": round(storage_gb, 3),
                "LookbackDays": lookback_days,
                "Threshold": utilization_threshold,
                "Headroom": headroom,
            }
        )

        try:
            # type: ignore[call-arg]
            config.WRITE_ROW(
                writer=writer,
                resource_id=arn,
                name=name,
                owner_id=config.ACCOUNT_ID,  # type: ignore[arg-type]
                resource_type="DynamoDBTable",
                estimated_cost=current_cost,
                potential_saving=potential_saving,
                flags=flags,
                confidence=100,
                signals=signals,
            )
        except Exception as exc:  # pylint: disable=broad-except
            log.warning("[check_dynamodb_underutilized_provisioned] write_row failed for %s: %s", name, exc)

        log.info(
            "[check_dynamodb_underutilized_provisioned] Wrote: %s (rcu=%d wcu=%d util_r=%.3f util_w=%.3f)",
            name, rcu, wcu, util_r, util_w,
        )


# =================== 3) PITR / Continuous backups cost =================== #

@retry_with_backoff(exceptions=(ClientError,))
def check_dynamodb_continuous_backups(  # pylint: disable=unused-argument
    *args,
    logger: Optional[logging.Logger] = None,
    **kwargs,
) -> None:
    """Surface PITR-enabled tables and estimate backup storage cost (heuristic)."""
    log = _logger(kwargs.get("logger") or logger)

    try:
        writer, dynamodb, cloudwatch = _extract_writer_ddb_cw(args, kwargs)  # cloudwatch unused
    except TypeError as exc:
        log.warning("[check_dynamodb_continuous_backups] Skipping: %s", exc)
        return
    if not (config.ACCOUNT_ID and config.WRITE_ROW and config.GET_PRICE):
        log.warning("[check_dynamodb_continuous_backups] Skipping: checker config not provided.")
        return

    region = getattr(getattr(dynamodb, "meta", None), "region_name", "") or ""
    price_pitr_gb = config.safe_price("DynamoDB", "PITR_GB_MONTH", 0.20)

    names = _list_tables(dynamodb, log)
    if not names:
        return

    for name in names:
        tbl = _describe_table(dynamodb, name, log)
        arn = tbl.get("TableArn") or name
        storage_gb = _table_storage_gb(tbl)

        cbd = _pitr_status(dynamodb, name, log)
        pitr = (cbd.get("PointInTimeRecoveryDescription", {}) or {})
        status = (pitr.get("PointInTimeRecoveryStatus") or "DISABLED").upper()
        enabled = (status == "ENABLED")
        last_restorable = pitr.get("LatestRestorableDateTime")

        if not enabled:
            continue

        est = storage_gb * price_pitr_gb
        potential_saving = est  # heuristic

        signals = _signals_str(
            {
                "Region": region,
                "TableName": name,
                "ARN": arn,
                "PITRStatus": status,
                "StorageGB": round(storage_gb, 3),
                "LatestRestorable": _to_utc_iso(last_restorable) if isinstance(last_restorable, datetime) else None,
            }
        )

        try:
            # type: ignore[call-arg]
            config.WRITE_ROW(
                writer=writer,
                resource_id=arn,
                name=name,
                owner_id=config.ACCOUNT_ID,  # type: ignore[arg-type]
                resource_type="DynamoDBTable",
                estimated_cost=est,
                potential_saving=potential_saving,
                flags=["DynamoDBPITREnabled"],
                confidence=100,
                signals=signals,
            )
        except Exception as exc:  # pylint: disable=broad-except
            log.warning("[check_dynamodb_continuous_backups] write_row failed for %s: %s", name, exc)

        log.info("[check_dynamodb_continuous_backups] Wrote PITR: %s (storage=%.3fGB)", name, storage_gb)


# ======================= 4) GSI underutilization ========================= #

@retry_with_backoff(exceptions=(ClientError,))
def check_dynamodb_gsi_underutilized(  # pylint: disable=unused-argument
    *args,
    logger: Optional[logging.Logger] = None,
    lookback_days: int = 30,
    utilization_threshold: float = 0.10,
    headroom: float = 0.20,
    **kwargs,
) -> None:
    """
    Flag PROVISIONED GSIs where avg consumed RCU/WCU is << provisioned.

    Savings (heuristic) = monthly(current RCU/WCU) - monthly(recommended with headroom).
    """
    log = _logger(kwargs.get("logger") or logger)

    try:
        writer, dynamodb, cloudwatch = _extract_writer_ddb_cw(args, kwargs)
    except TypeError as exc:
        log.warning("[check_dynamodb_gsi_underutilized] Skipping: %s", exc)
        return
    if not (config.ACCOUNT_ID and config.WRITE_ROW and config.GET_PRICE):
        log.warning("[check_dynamodb_gsi_underutilized] Skipping: checker config not provided.")
        return

    region = getattr(getattr(dynamodb, "meta", None), "region_name", "") or ""
    now_utc = datetime.now(timezone.utc).replace(microsecond=0)
    start_time = now_utc - timedelta(days=lookback_days)
    period = 300
    seconds = float(lookback_days) * 86400.0 if lookback_days > 0 else 1.0

    names = _list_tables(dynamodb, log)
    if not names:
        return

    # Build list of (table, gsi) with provisioned capacity
    gsi_meta: List[Tuple[str, str, float, float]] = []
    for name in names:
        t = _describe_table(dynamodb, name, log)
        for gsi in t.get("GlobalSecondaryIndexes", []) or []:
            proj = gsi.get("ProvisionedThroughput") or {}
            rcu = float(proj.get("ReadCapacityUnits") or 0)
            wcu = float(proj.get("WriteCapacityUnits") or 0)
            if rcu > 0 or wcu > 0:
                gsi_meta.append((name, gsi.get("IndexName") or "", rcu, wcu))

    if not gsi_meta:
        log.info("[check_dynamodb_gsi_underutilized] No provisioned GSIs in %s", region)
        return

    # Batch metrics per (table, gsi)
    metrics_ok = True
    results: Dict[str, Any] = {}
    id_map: Dict[Tuple[str, str], Dict[str, str]] = {}

    try:
        cw_region = getattr(getattr(cloudwatch, "meta", None), "region_name", "") or region
        cw_batch = CloudWatchBatcher(region=cw_region, client=cloudwatch)
        for table, gsi_name, _, _ in gsi_meta:
            dims = [("TableName", table), ("GlobalSecondaryIndexName", gsi_name)]
            rid = f"rcu_{table}_{gsi_name}"
            wid = f"wcu_{table}_{gsi_name}"
            cw_batch.add_q(id_hint=rid, namespace="AWS/DynamoDB", metric="ConsumedReadCapacityUnits",
                           dims=dims, stat="Sum", period=period)
            cw_batch.add_q(id_hint=wid, namespace="AWS/DynamoDB", metric="ConsumedWriteCapacityUnits",
                           dims=dims, stat="Sum", period=period)
            id_map[(table, gsi_name)] = {"rcu": rid, "wcu": wid}
        results = cw_batch.execute(start=start_time, end=now_utc)
    except ClientError as exc:
        log.warning("[check_dynamodb_gsi_underutilized] CloudWatch metrics unavailable: %s", exc)
        metrics_ok = False
    except Exception as exc:  # pylint: disable=broad-except
        log.warning("[check_dynamodb_gsi_underutilized] CloudWatch batch error: %s", exc)
        metrics_ok = False

    if not metrics_ok:
        return

    for table, gsi_name, rcu, wcu in gsi_meta:
        rsum = _sum_from_result(results.get(id_map.get((table, gsi_name), {}).get("rcu")))
        wsum = _sum_from_result(results.get(id_map.get((table, gsi_name), {}).get("wcu")))
        avg_r = (rsum / seconds) if seconds > 0 else 0.0
        avg_w = (wsum / seconds) if seconds > 0 else 0.0

        util_r = (avg_r / rcu) if rcu > 0 else 0.0
        util_w = (avg_w / wcu) if wcu > 0 else 0.0

        if (rcu <= 0 and wcu <= 0) or (util_r >= utilization_threshold or util_w >= utilization_threshold):
            continue

        current_cost = _provisioned_monthly_cost(rcu, wcu)
        rec_rcu = max(1, int(math.ceil(avg_r * (1.0 + headroom))))
        rec_wcu = max(1, int(math.ceil(avg_w * (1.0 + headroom))))
        rec_cost = _provisioned_monthly_cost(rec_rcu, rec_wcu)
        potential_saving = max(0.0, current_cost - rec_cost)

        signals = _signals_str(
            {
                "Region": region,
                "TableName": table,
                "GSI": gsi_name,
                "RCU": int(rcu),
                "WCU": int(wcu),
                "AvgRCU_per_s": round(avg_r, 3),
                "AvgWCU_per_s": round(avg_w, 3),
                "UtilRead": round(util_r, 3),
                "UtilWrite": round(util_w, 3),
                "SuggestedRCU": rec_rcu,
                "SuggestedWCU": rec_wcu,
                "LookbackDays": lookback_days,
            }
        )

        try:
            # type: ignore[call-arg]
            config.WRITE_ROW(
                writer=writer,
                resource_id=f"{table}/{gsi_name}",
                name=f"{table}:{gsi_name}",
                owner_id=config.ACCOUNT_ID,  # type: ignore[arg-type]
                resource_type="DynamoDBGSI",
                estimated_cost=current_cost,
                potential_saving=potential_saving,
                flags=["DynamoDBGSIUnderutilized"],
                confidence=100,
                signals=signals,
            )
        except Exception as exc:  # pylint: disable=broad-except
            log.warning("[check_dynamodb_gsi_underutilized] write_row failed for %s:%s: %s", table, gsi_name, exc)

        log.info("[check_dynamodb_gsi_underutilized] Wrote GSI: %s:%s", table, gsi_name)


# ================= Streams enabled but no consumers (best-effort) ======== #

@retry_with_backoff(exceptions=(ClientError,))
def check_dynamodb_streams_enabled_no_consumers(  # pylint: disable=unused-argument
    *args,
    logger: Optional[logging.Logger] = None,
    **kwargs,
) -> None:
    """
    If Streams are enabled but there are no registered stream consumers,
    flag 'DynamoDBStreamNoConsumers'. Requires a 'dynamodbstreams' client.
    """
    log = _logger(kwargs.get("logger") or logger)

    # Accept an optional 'dynamodbstreams' client in kwargs
    streams_client = kwargs.get("dynamodbstreams")
    try:
        writer, dynamodb, _cloudwatch = _extract_writer_ddb_cw(args, kwargs)
    except TypeError as exc:
        log.warning("[check_dynamodb_streams_enabled_no_consumers] Skipping: %s", exc)
        return
    if streams_client is None:
        log.warning("[check_dynamodb_streams_enabled_no_consumers] Skipping: no 'dynamodbstreams' client provided.")
        return
    if not (config.ACCOUNT_ID and config.WRITE_ROW):
        log.warning("[check_dynamodb_streams_enabled_no_consumers] Skipping: checker config not provided.")
        return

    region = getattr(getattr(dynamodb, "meta", None), "region_name", "") or ""
    names = _list_tables(dynamodb, log)
    if not names:
        return

    for name in names:
        t = _describe_table(dynamodb, name, log)
        arn = t.get("TableArn") or name
        spec = t.get("StreamSpecification") or {}
        if not spec.get("StreamEnabled"):
            continue
        latest_arn = t.get("LatestStreamArn")
        if not latest_arn:
            continue

        # list_stream_consumers best-effort
        try:
            resp = streams_client.list_stream_consumers(StreamARN=latest_arn)
            consumers = resp.get("Consumers", []) or []
            if not consumers:
                # type: ignore[call-arg]
                config.WRITE_ROW(
                    writer=writer,
                    resource_id=arn,
                    name=name,
                    owner_id=config.ACCOUNT_ID,  # type: ignore[arg-type]
                    resource_type="DynamoDBTable",
                    estimated_cost=0.0,
                    potential_saving=0.0,
                    flags=["DynamoDBStreamNoConsumers"],
                    confidence=100,
                    signals=_signals_str({"Region": region, "TableName": name, "StreamEnabled": True}),
                )
                log.info("[check_dynamodb_streams_enabled_no_consumers] Wrote: %s (no consumers)", name)
        except ClientError as exc:
            log.debug("[dynamodb streams] list_stream_consumers failed for %s: %s", name, exc)


# ============================= TTL disabled ============================== #

@retry_with_backoff(exceptions=(ClientError,))
def check_dynamodb_ttl_disabled(  # pylint: disable=unused-argument
    *args,
    logger: Optional[logging.Logger] = None,
    **kwargs,
) -> None:
    """Flag tables without TTL enabled (hygiene; no cost estimate)."""
    log = _logger(kwargs.get("logger") or logger)

    try:
        writer, dynamodb, _cloudwatch = _extract_writer_ddb_cw(args, kwargs)
    except TypeError as exc:
        log.warning("[check_dynamodb_ttl_disabled] Skipping: %s", exc)
        return
    if not (config.ACCOUNT_ID and config.WRITE_ROW):
        log.warning("[check_dynamodb_ttl_disabled] Skipping: checker config not provided.")
        return

    region = getattr(getattr(dynamodb, "meta", None), "region_name", "") or ""
    names = _list_tables(dynamodb, log)
    if not names:
        return

    for name in names:
        try:
            ttl = dynamodb.describe_time_to_live(TableName=name).get("TimeToLiveDescription", {}) or {}
            status = (ttl.get("TimeToLiveStatus") or "DISABLED").upper()
            if status != "ENABLED":
                # type: ignore[call-arg]
                config.WRITE_ROW(
                    writer=writer,
                    resource_id=name,
                    name=name,
                    owner_id=config.ACCOUNT_ID,  # type: ignore[arg-type]
                    resource_type="DynamoDBTable",
                    estimated_cost=0.0,
                    potential_saving=0.0,
                    flags=["DynamoDBTTLOff"],
                    confidence=100,
                    signals=_signals_str({"Region": region, "TableName": name, "TTLStatus": status}),
                )
                log.info("[check_dynamodb_ttl_disabled] Wrote: %s (TTL=%s)", name, status)
        except ClientError as exc:
            log.debug("[dynamodb] describe_time_to_live failed for %s: %s", name, exc)


# ======================= Table class mismatch (IA) ======================= #

@retry_with_backoff(exceptions=(ClientError,))
def check_dynamodb_table_class_mismatch(  # pylint: disable=unused-argument
    *args,
    logger: Optional[logging.Logger] = None,
    lookback_days: int = 30,
    access_per_gb_threshold: float = 0.001,
    **kwargs,
) -> None:
    """
    Suggest switching Standard ↔ Standard-IA based on traffic/storage heuristic.

    Heuristic:
      - Compute (ConsumedRCU+ConsumedWCU) / StorageGB over window.
      - If TableClass=STANDARD and ratio <= threshold → candidate for IA.
      - If TableClass=STANDARD_INFREQUENT_ACCESS and ratio >> threshold → candidate for STANDARD.

    Potential saving (if Standard→IA):
      storage_gb * (price_std - price_ia)  [if price keys exist]
    """
    log = _logger(kwargs.get("logger") or logger)

    try:
        writer, dynamodb, cloudwatch = _extract_writer_ddb_cw(args, kwargs)
    except TypeError as exc:
        log.warning("[check_dynamodb_table_class_mismatch] Skipping: %s", exc)
        return
    if not (config.ACCOUNT_ID and config.WRITE_ROW and config.GET_PRICE):
        log.warning("[check_dynamodb_table_class_mismatch] Skipping: checker config not provided.")
        return

    region = getattr(getattr(dynamodb, "meta", None), "region_name", "") or ""
    now_utc = datetime.now(timezone.utc).replace(microsecond=0)
    start_time = now_utc - timedelta(days=lookback_days)
    period = 3600

    names = _list_tables(dynamodb, log)
    if not names:
        return

    metrics_ok = True
    results: Dict[str, Any] = {}
    id_map: Dict[str, Dict[str, str]] = {}
    try:
        cw_region = getattr(getattr(cloudwatch, "meta", None), "region_name", "") or region
        cw_batch = CloudWatchBatcher(region=cw_region, client=cloudwatch)
        for name in names:
            dims = [("TableName", name)]
            rid = f"rcu_{name}"
            wid = f"wcu_{name}"
            cw_batch.add_q(id_hint=rid, namespace="AWS/DynamoDB", metric="ConsumedReadCapacityUnits",
                           dims=dims, stat="Sum", period=period)
            cw_batch.add_q(id_hint=wid, namespace="AWS/DynamoDB", metric="ConsumedWriteCapacityUnits",
                           dims=dims, stat="Sum", period=period)
            id_map[name] = {"rcu": rid, "wcu": wid}
        results = cw_batch.execute(start=start_time, end=now_utc)
    except ClientError as exc:
        log.warning("[check_dynamodb_table_class_mismatch] CloudWatch metrics unavailable: %s", exc)
        metrics_ok = False
    except Exception as exc:  # pylint: disable=broad-except
        log.warning("[check_dynamodb_table_class_mismatch] CloudWatch batch error: %s", exc)
        metrics_ok = False

    if not metrics_ok:
        return

    price_std = config.safe_price("DynamoDB", "STORAGE_GB_MONTH", 0.25)
    price_ia = config.safe_price("DynamoDB", "STORAGE_IA_GB_MONTH", 0.10)

    for name in names:
        tbl = _describe_table(dynamodb, name, log)
        arn = tbl.get("TableArn") or name
        storage_gb = _table_storage_gb(tbl)
        cls = (tbl.get("TableClassSummary", {}).get("TableClass") or "STANDARD").upper()

        rsum = _sum_from_result(results.get(id_map.get(name, {}).get("rcu")))
        wsum = _sum_from_result(results.get(id_map.get(name, {}).get("wcu")))
        ratio = ((rsum + wsum) / storage_gb) if storage_gb > 0 else 0.0

        flags: List[str] = []
        potential_saving = 0.0

        if cls == "STANDARD" and ratio <= access_per_gb_threshold:
            flags.append("DynamoDBTableClassConsiderIA")
            potential_saving = max(0.0, (price_std - price_ia) * storage_gb)
        elif cls == "STANDARD_INFREQUENT_ACCESS" and ratio > access_per_gb_threshold * 10:
            flags.append("DynamoDBTableClassConsiderStandard")

        if not flags:
            continue

        signals = _signals_str(
            {
                "Region": region,
                "TableName": name,
                "ARN": arn,
                "TableClass": cls,
                "StorageGB": round(storage_gb, 3),
                "ConsumedRCUSum": int(rsum),
                "ConsumedWCUSum": int(wsum),
                "AccessPerGB": round(ratio, 6),
                "Threshold": access_per_gb_threshold,
                "LookbackDays": lookback_days,
            }
        )

        try:
            # type: ignore[call-arg]
            config.WRITE_ROW(
                writer=writer,
                resource_id=arn,
                name=name,
                owner_id=config.ACCOUNT_ID,  # type: ignore[arg-type]
                resource_type="DynamoDBTable",
                estimated_cost=0.0 if "ConsiderStandard" in flags else potential_saving,
                potential_saving=potential_saving,
                flags=flags,
                confidence=100,
                signals=signals,
            )
        except Exception as exc:  # pylint: disable=broad-except
            log.warning("[check_dynamodb_table_class_mismatch] write_row failed for %s: %s", name, exc)

        log.info("[check_dynamodb_table_class_mismatch] Wrote: %s (class=%s ratio=%.6f flags=%s)", name, cls, ratio, flags)


# =================== Global tables: low activity (info) ================== #

@retry_with_backoff(exceptions=(ClientError,))
def check_dynamodb_global_tables_low_activity(  # pylint: disable=unused-argument
    *args,
    logger: Optional[logging.Logger] = None,
    lookback_days: int = 30,
    **kwargs,
) -> None:
    """
    For global tables (replicas > 1), flag very low overall consumption in the window.
    This is informational; savings depend on whether a replica can be removed.
    """
    log = _logger(kwargs.get("logger") or logger)

    try:
        writer, dynamodb, cloudwatch = _extract_writer_ddb_cw(args, kwargs)
    except TypeError as exc:
        log.warning("[check_dynamodb_global_tables_low_activity] Skipping: %s", exc)
        return
    if not (config.ACCOUNT_ID and config.WRITE_ROW):
        log.warning("[check_dynamodb_global_tables_low_activity] Skipping: checker config not provided.")
        return

    region = getattr(getattr(dynamodb, "meta", None), "region_name", "") or ""
    now_utc = datetime.now(timezone.utc).replace(microsecond=0)
    start_time = now_utc - timedelta(days=lookback_days)
    period = 3600

    names = _list_tables(dynamodb, log)
    if not names:
        return

    # Identify global tables (replicas > 1)
    globals_: List[str] = []
    for name in names:
        t = _describe_table(dynamodb, name, log)
        replicas = (t.get("Replicas", []) or [])  # 2019 GT version
        if replicas and len(replicas) > 1:
            globals_.append(name)

    if not globals_:
        return

    # Batch metrics for those tables
    metrics_ok = True
    results: Dict[str, Any] = {}
    id_map: Dict[str, Dict[str, str]] = {}
    try:
        cw_region = getattr(getattr(cloudwatch, "meta", None), "region_name", "") or region
        cw_batch = CloudWatchBatcher(region=cw_region, client=cloudwatch)
        for name in globals_:
            dims = [("TableName", name)]
            rid = f"rcu_{name}"
            wid = f"wcu_{name}"
            cw_batch.add_q(id_hint=rid, namespace="AWS/DynamoDB", metric="ConsumedReadCapacityUnits",
                           dims=dims, stat="Sum", period=period)
            cw_batch.add_q(id_hint=wid, namespace="AWS/DynamoDB", metric="ConsumedWriteCapacityUnits",
                           dims=dims, stat="Sum", period=period)
            id_map[name] = {"rcu": rid, "wcu": wid}
        results = cw_batch.execute(start=start_time, end=now_utc)
    except ClientError as exc:
        log.warning("[check_dynamodb_global_tables_low_activity] CloudWatch metrics unavailable: %s", exc)
        metrics_ok = False
    except Exception as exc:  # pylint: disable=broad-except
        log.warning("[check_dynamodb_global_tables_low_activity] CloudWatch batch error: %s", exc)
        metrics_ok = False

    if not metrics_ok:
        return

    for name in globals_:
        rsum = _sum_from_result(results.get(id_map.get(name, {}).get("rcu")))
        wsum = _sum_from_result(results.get(id_map.get(name, {}).get("wcu")))
        if (rsum + wsum) > 0.0:
            # very low activity threshold; tune as you like
            continue

        t = _describe_table(dynamodb, name, log)
        arn = t.get("TableArn") or name
        replica_regions = [r.get("RegionName") for r in (t.get("Replicas", []) or []) if r.get("RegionName")]

        # type: ignore[call-arg]
        try:
            config.WRITE_ROW(
                writer=writer,
                resource_id=arn,
                name=name,
                owner_id=config.ACCOUNT_ID,  # type: ignore[arg-type]
                resource_type="DynamoDBTable",
                estimated_cost=0.0,
                potential_saving=0.0,
                flags=["DynamoDBGlobalTableLowActivity"],
                confidence=100,
                signals=_signals_str(
                    {
                        "Region": region,
                        "TableName": name,
                        "ARN": arn,
                        "ReplicaRegions": ",".join(replica_regions),
                        "ConsumedRCUSum": int(rsum),
                        "ConsumedWCUSum": int(wsum),
                        "LookbackDays": lookback_days,
                    }
                ),
            )
        except Exception as exc:  # pylint: disable=broad-except
            log.warning("[check_dynamodb_global_tables_low_activity] write_row failed for %s: %s", name, exc)

        log.info("[check_dynamodb_global_tables_low_activity] Wrote: %s", name)
