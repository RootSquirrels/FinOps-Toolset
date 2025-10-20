"""Checkers: Amazon Kinesis (Data Streams + Firehose).

Contains:
  - check_kinesis_data_streams: flags unused/disabled Kinesis Data Streams and
    estimates monthly shard cost (heuristic). Uses CloudWatch metrics to decide
    "unused" status; never hard-fails on AWS errors.
  - check_firehose_delivery_streams: flags Firehose delivery streams with no
    incoming traffic in the lookback window (best-effort).

Design:
  - Dependencies (account_id, write_row, get_price, logger) injected via
    finops_toolset.checkers.config.setup(...).
  - Uses finops_toolset.cloudwatch.CloudWatchBatcher:
      cw = CloudWatchBatcher(region=..., client=...)
      cw.add_q(id_hint=..., namespace=..., metric=..., dims=[(..., ...)], stat=..., period=...)
      results = cw.execute(start=..., end=...)
  - Tolerant signatures (positional or keyword) for run_check.
  - Timezone-aware datetimes (datetime.now(timezone.utc)), lazy %s logging.
  - Retries via @retry_with_backoff(exceptions=(ClientError,)), while individual
    AWS calls are guarded and will not crash the whole check.
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


# ----------------------------- helpers --------------------------------- #


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


def _extract_writer_kinesis_cw(
    args: Tuple[Any, ...],
    kwargs: Dict[str, Any],
) -> Tuple[Any, Any, Any]:
    """Accept writer/kinesis/cloudwatch positionally or by keyword; prefer keywords."""
    writer = kwargs.get("writer", args[0] if len(args) >= 1 else None)
    kinesis = kwargs.get("kinesis", args[1] if len(args) >= 2 else None)
    cloudwatch = kwargs.get("cloudwatch", args[2] if len(args) >= 3 else None)
    if writer is None or kinesis is None or cloudwatch is None:
        raise TypeError(
            "check_kinesis_data_streams expected 'writer', 'kinesis', and 'cloudwatch' "
            f"(got writer={writer!r}, kinesis={kinesis!r}, cloudwatch={cloudwatch!r})"
        )
    return writer, kinesis, cloudwatch


def _extract_writer_firehose_cw(
    args: Tuple[Any, ...],
    kwargs: Dict[str, Any],
) -> Tuple[Any, Any, Any]:
    """Accept writer/firehose/cloudwatch positionally or by keyword; prefer keywords."""
    writer = kwargs.get("writer", args[0] if len(args) >= 1 else None)
    firehose = kwargs.get("firehose", args[1] if len(args) >= 2 else None)
    cloudwatch = kwargs.get("cloudwatch", args[2] if len(args) >= 3 else None)
    if writer is None or firehose is None or cloudwatch is None:
        raise TypeError(
            "check_firehose_delivery_streams expected 'writer', 'firehose', and 'cloudwatch' "
            f"(got writer={writer!r}, firehose={firehose!r}, cloudwatch={cloudwatch!r})"
        )
    return writer, firehose, cloudwatch


# ------------------------- Kinesis Data Streams -------------------------- #

@retry_with_backoff(exceptions=(ClientError,))
def check_kinesis_data_streams(  # pylint: disable=unused-argument
    *args,
    logger: Optional[logging.Logger] = None,
    lookback_days: int = 30,
    **kwargs,
) -> None:
    """
    Enumerate Kinesis Data Streams and flag:
      - 'KinesisStreamUnused'  : Sum(IncomingBytes)==0 AND Sum(IncomingRecords)==0 in window
      - 'KinesisStreamDisabled': StreamStatus not 'ACTIVE'

    Estimated monthly cost (heuristic):
      - shards * price("Kinesis","STREAM_SHARD_MONTH")
      - (ignores per-request/data costs to keep estimate simple)
      - potential_saving = estimated_cost if Unused else 0.0
    """
    log = _logger(kwargs.get("logger") or logger)

    # Resolve clients/args
    try:
        writer, kinesis, cloudwatch = _extract_writer_kinesis_cw(args, kwargs)
    except TypeError as exc:
        log.warning("[check_kinesis_data_streams] Skipping: %s", exc)
        return
    if not (config.ACCOUNT_ID and config.WRITE_ROW and config.GET_PRICE):
        log.warning("[check_kinesis_data_streams] Skipping: checker config not provided.")
        return

    region = getattr(getattr(kinesis, "meta", None), "region_name", "") or ""
    cw_region = getattr(getattr(cloudwatch, "meta", None), "region_name", "") or region
    now_utc = datetime.now(timezone.utc).replace(microsecond=0)
    start_time = now_utc - timedelta(days=lookback_days)
    period = 3600  # 1h buckets

    # List stream names
    stream_names: List[str] = []
    try:
        has_more = True
        exclusive_start: Optional[str] = None
        while has_more:
            params: Dict[str, Any] = {}
            if exclusive_start:
                params["ExclusiveStartStreamName"] = exclusive_start
            resp = kinesis.list_streams(**params)
            stream_names.extend(resp.get("StreamNames", []) or [])
            has_more = bool(resp.get("HasMoreStreams"))
            if has_more and stream_names:
                exclusive_start = stream_names[-1]
    except ClientError as exc:
        log.error("[check_kinesis_data_streams] list_streams failed: %s", exc)
        return

    if not stream_names:
        log.info("[check_kinesis_data_streams] No Kinesis streams found in %s", region)
        return

    # Describe streams (summary) for shard counts/status
    meta: Dict[str, Dict[str, Any]] = {}
    for name in stream_names:
        try:
            d = kinesis.describe_stream_summary(StreamName=name)
            s = d.get("StreamDescriptionSummary", {}) or {}
            meta[name] = {
                "StreamARN": s.get("StreamARN"),
                "StreamStatus": s.get("StreamStatus"),
                "OpenShardCount": int(s.get("OpenShardCount") or 0),
                "RetentionHours": s.get("RetentionPeriodHours"),
                "EncryptionType": s.get("EncryptionType"),
                "KeyId": s.get("KeyId"),
                "StreamCreationTimestamp": s.get("StreamCreationTimestamp"),
            }
        except ClientError as exc:
            log.debug("[check_kinesis_data_streams] describe_stream_summary failed for %s: %s", name, exc)
            meta[name] = {
                "StreamStatus": "UNKNOWN",
                "OpenShardCount": 0,
            }

    # CloudWatch batch for Requests/Bytes + IteratorAge (best-effort)
    metrics_ok = True
    results: Dict[str, Any] = {}
    id_map: Dict[str, Dict[str, str]] = {}

    try:
        cw_batch = CloudWatchBatcher(region=cw_region, client=cloudwatch)
        for name in stream_names:
            dims = [("StreamName", name)]
            id_inb = f"kds_inb_{name}"
            id_inr = f"kds_inr_{name}"
            id_age = f"kds_age_{name}"

            cw_batch.add_q(id_hint=id_inb, namespace="AWS/Kinesis", metric="IncomingBytes",   dims=dims, stat="Sum",     period=period)
            cw_batch.add_q(id_hint=id_inr, namespace="AWS/Kinesis", metric="IncomingRecords", dims=dims, stat="Sum",     period=period)
            cw_batch.add_q(id_hint=id_age, namespace="AWS/Kinesis", metric="GetRecords.IteratorAgeMilliseconds",
                           dims=dims, stat="Maximum", period=period)

            id_map[name] = {"inb": id_inb, "inr": id_inr, "age": id_age}

        results = cw_batch.execute(start=start_time, end=now_utc)
    except ClientError as exc:
        log.warning("[check_kinesis_data_streams] CloudWatch metrics unavailable: %s", exc)
        metrics_ok = False
    except Exception as exc:  # pylint: disable=broad-except
        log.warning("[check_kinesis_data_streams] CloudWatch batch error: %s", exc)
        metrics_ok = False

    price_shard_month = config.safe_price("Kinesis", "STREAM_SHARD_MONTH", default=10.95)

    # Emit rows
    for name in stream_names:
        m = meta.get(name, {})
        shard_count = int(m.get("OpenShardCount") or 0)
        status = m.get("StreamStatus") or "UNKNOWN"
        arn = m.get("StreamARN") or name

        # Metrics
        inb_sum = 0.0
        inr_sum = 0.0
        age_max = 0.0
        if metrics_ok:
            ids = id_map.get(name, {})
            inb_sum = _sum_from_result(results.get(ids.get("inb")))
            inr_sum = _sum_from_result(results.get(ids.get("inr")))
            age_max = _max_from_result(results.get(ids.get("age")))

        # Flags
        flags: List[str] = []
        if status != "ACTIVE":
            flags.append("KinesisStreamDisabled")
        if metrics_ok and inb_sum <= 0.0 and inr_sum <= 0.0:
            flags.append("KinesisStreamUnused")

        if not flags:
            log.info(
                "[check_kinesis_data_streams] Processed: %s (status=%s shards=%d inB=%d inR=%d)",
                name, status, shard_count, int(inb_sum), int(inr_sum),
            )
            continue

        # Heuristic cost: shard fixed price only
        estimated_cost = float(shard_count) * price_shard_month
        potential_saving = estimated_cost if "KinesisStreamUnused" in flags else 0.0

        signals = _signals_str(
            {
                "Region": region,
                "StreamName": name,
                "ARN": arn,
                "Status": status,
                "OpenShards": shard_count,
                "RetentionHours": m.get("RetentionHours"),
                "EncryptionType": m.get("EncryptionType"),
                "IteratorAgeMaxMs": int(age_max),
                "IncomingBytesSum": int(inb_sum),
                "IncomingRecordsSum": int(inr_sum),
                "LookbackDays": lookback_days,
                "MetricsAvailable": metrics_ok,
            }
        )

        try:
            # type: ignore[call-arg]
            config.WRITE_ROW(
                writer=writer,
                resource_id=arn,
                name=name,
                owner_id=config.ACCOUNT_ID,  # type: ignore[arg-type]
                resource_type="KinesisDataStream",
                estimated_cost=estimated_cost,
                potential_saving=potential_saving,
                flags=flags,
                confidence=100,
                signals=signals,
            )
        except Exception as exc:  # pylint: disable=broad-except
            log.warning("[check_kinesis_data_streams] write_row failed for %s: %s", name, exc)

        log.info(
            "[check_kinesis_data_streams] Wrote: %s (flags=%s est=%.2f save=%.2f)",
            name, flags, estimated_cost, potential_saving,
        )


# ----------------------- Kinesis Data Firehose --------------------------- #

@retry_with_backoff(exceptions=(ClientError,))
def check_firehose_delivery_streams(  # pylint: disable=unused-argument
    *args,
    logger: Optional[logging.Logger] = None,
    lookback_days: int = 30,
    **kwargs,
) -> None:
    """
    Enumerate Kinesis Data Firehose delivery streams and flag:
      - 'FirehoseDeliveryStreamUnused' when Sum(IncomingBytes)==0 in window
      - 'FirehoseDeliveryStreamDisabled' when DeliveryStreamStatus != 'ACTIVE'

    Firehose has no fixed monthly base; we estimate cost as 0 for unused streams
    and set potential_saving=0.0 (the value is in cleanup).
    """
    log = _logger(kwargs.get("logger") or logger)

    try:
        writer, firehose, cloudwatch = _extract_writer_firehose_cw(args, kwargs)
    except TypeError as exc:
        log.warning("[check_firehose_delivery_streams] Skipping: %s", exc)
        return
    if not (config.ACCOUNT_ID and config.WRITE_ROW and config.GET_PRICE):
        log.warning("[check_firehose_delivery_streams] Skipping: checker config not provided.")
        return

    region = getattr(getattr(firehose, "meta", None), "region_name", "") or ""
    cw_region = getattr(getattr(cloudwatch, "meta", None), "region_name", "") or region
    now_utc = datetime.now(timezone.utc).replace(microsecond=0)
    start_time = now_utc - timedelta(days=lookback_days)
    period = 3600

    # List delivery stream names
    names: List[str] = []
    try:
        has_more = True
        exclusive_start: Optional[str] = None
        while has_more:
            params: Dict[str, Any] = {}
            if exclusive_start:
                params["ExclusiveStartDeliveryStreamName"] = exclusive_start
            resp = firehose.list_delivery_streams(**params)
            names.extend(resp.get("DeliveryStreamNames", []) or [])
            has_more = bool(resp.get("HasMoreDeliveryStreams"))
            if has_more and names:
                exclusive_start = names[-1]
    except ClientError as exc:
        log.error("[check_firehose_delivery_streams] list_delivery_streams failed: %s", exc)
        return

    if not names:
        log.info("[check_firehose_delivery_streams] No Firehose delivery streams in %s", region)
        return

    # Describe stream for status/destinations
    meta: Dict[str, Dict[str, Any]] = {}
    for name in names:
        try:
            d = firehose.describe_delivery_stream(DeliveryStreamName=name)
            desc = d.get("DeliveryStreamDescription", {}) or {}
            meta[name] = {
                "ARN": desc.get("DeliveryStreamARN"),
                "Status": desc.get("DeliveryStreamStatus"),
                "DestinationsCount": len(desc.get("Destinations", []) or []),
                "CreateTimestamp": desc.get("CreateTimestamp"),
            }
        except ClientError as exc:
            log.debug("[check_firehose_delivery_streams] describe_delivery_stream failed for %s: %s", name, exc)
            meta[name] = {"Status": "UNKNOWN", "DestinationsCount": 0}

    # CloudWatch metrics (IncomingBytes)
    metrics_ok = True
    results: Dict[str, Any] = {}
    id_map: Dict[str, str] = {}

    try:
        cw_batch = CloudWatchBatcher(region=cw_region, client=cloudwatch)
        for name in names:
            dims = [("DeliveryStreamName", name)]
            qid = f"fh_inb_{name}"
            cw_batch.add_q(
                id_hint=qid,
                namespace="AWS/Firehose",
                metric="IncomingBytes",
                dims=dims,
                stat="Sum",
                period=period,
            )
            id_map[name] = qid
        results = cw_batch.execute(start=start_time, end=now_utc)
    except ClientError as exc:
        log.warning("[check_firehose_delivery_streams] CloudWatch metrics unavailable: %s", exc)
        metrics_ok = False
    except Exception as exc:  # pylint: disable=broad-except
        log.warning("[check_firehose_delivery_streams] CloudWatch batch error: %s", exc)
        metrics_ok = False

    # Emit rows
    for name in names:
        m = meta.get(name, {})
        arn = m.get("ARN") or name
        status = m.get("Status") or "UNKNOWN"
        dest_count = int(m.get("DestinationsCount") or 0)

        inb_sum = 0.0
        if metrics_ok:
            inb_sum = _sum_from_result(results.get(id_map.get(name)))

        flags: List[str] = []
        if status != "ACTIVE":
            flags.append("FirehoseDeliveryStreamDisabled")
        if metrics_ok and inb_sum <= 0.0:
            flags.append("FirehoseDeliveryStreamUnused")

        if not flags:
            log.info(
                "[check_firehose_delivery_streams] Processed: %s (status=%s inB=%d)",
                name, status, int(inb_sum),
            )
            continue

        # No fixed monthly base for unused Firehose → set to 0
        estimated_cost = 0.0
        potential_saving = 0.0 if "FirehoseDeliveryStreamUnused" in flags else 0.0

        signals = _signals_str(
            {
                "Region": region,
                "Name": name,
                "ARN": arn,
                "Status": status,
                "Destinations": dest_count,
                "IncomingBytesSum": int(inb_sum),
                "LookbackDays": lookback_days,
                "MetricsAvailable": metrics_ok,
            }
        )

        try:
            # type: ignore[call-arg]
            config.WRITE_ROW(
                writer=writer,
                resource_id=arn,
                name=name,
                owner_id=config.ACCOUNT_ID,  # type: ignore[arg-type]
                resource_type="FirehoseDeliveryStream",
                estimated_cost=estimated_cost,
                potential_saving=potential_saving,
                flags=flags,
                confidence=100,
                signals=signals,
            )
        except Exception as exc:  # pylint: disable=broad-except
            log.warning("[check_firehose_delivery_streams] write_row failed for %s: %s", name, exc)

        log.info(
            "[check_firehose_delivery_streams] Wrote: %s (flags=%s)",
            name, flags,
        )
