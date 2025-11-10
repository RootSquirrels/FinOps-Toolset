"""Kinesis savings checkers (idle streams & overprovisioned shards).

This module follows the repository's checker conventions:
- Orchestrator-friendly functions (no main).
- Uses CloudWatchBatcher (with legacy add_q/execute API).
- Uses config.safe_price and config.ACCOUNT_ID.
- Emits CSV rows via write_resource_to_csv (or exact fallback order).
- Performance: batches all GetMetricData calls, minimal API round-trips.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from logging import Logger
from typing import Any, Dict, List, Mapping, Optional, Sequence

try:
    import config as CONF  # type: ignore
except Exception:  # pragma: no cover
    import core.config as CONF  # type: ignore

from botocore.client import BaseClient
from botocore.exceptions import BotoCoreError, ClientError

from core.cloudwatch import CloudWatchBatcher
from aws_checkers.common import _logger, _signals_str, _to_utc_iso

# Optional orchestrator writer; fall back to raw CSV ordering if absent
# Try to import the orchestrator's unified CSV writer
WRITE_ROW = None
try:  # newest layout (orchestrator helper)
    from FinOps_Toolset_V2_profiler import (  # type: ignore
        write_resource_to_csv as WRITE_ROW,  # noqa: N816 - keep name for clarity
    )
except Exception:  # pragma: no cover - alternate config entry point
    WRITE_ROW = None  # fall back to raw writer

LOGGER: Logger = _logger(__name__)

# ---------------------------------------------------------------------------
# Constants & pricing helpers
# ---------------------------------------------------------------------------

# One shard priced hourly; enhanced metrics (per shard) is optional in some regions.
# Keys are looked up via config.safe_price, returning 0.0 if missing.
PRICE_KEYS = {
    "shard_hour": [
        "kinesis.shard_hour",
        "aws.kinesis.shard.hour",
        "kinesis.shard.hour",
    ],
    "enhanced_metrics_hour": [
        "kinesis.enhanced_metrics_hour",
        "aws.kinesis.enhanced_metrics.hour",
    ],
}


def _safe_price(key_candidates: Sequence[str], default: float = 0.0) -> float:
    """Resolve a price using config.safe_price with safe fallbacks."""
    for key in key_candidates:
        try:
            try:
                val = CONF.safe_price(key)  # type: ignore[attr-defined]
            except TypeError:
                val = CONF.safe_price(key, default)  # type: ignore[attr-defined]
            if val is not None:
                return float(val)
        except Exception:  # pragma: no cover
            continue
    return float(default)


_PER_SHARD_HOURLY = _safe_price(PRICE_KEYS["shard_hour"], 0.0)
_PER_SHARD_ENHANCED_HOURLY = _safe_price(PRICE_KEYS["enhanced_metrics_hour"], 0.0)
_HOURS_PER_MONTH = 730.0

# ---------------------------------------------------------------------------
# Small utilities
# ---------------------------------------------------------------------------


def _paginate_streams(kinesis: BaseClient) -> List[str]:
    """List all Kinesis streams (names) with simple pagination."""
    names: List[str] = []
    exclusive_start: Optional[str] = None
    while True:
        params: Dict[str, Any] = {}
        if exclusive_start:
            params["ExclusiveStartStreamName"] = exclusive_start
        try:
            page = kinesis.list_streams(**params)
        except (BotoCoreError, ClientError) as err:  # pragma: no cover
            LOGGER.warning("list_streams failed: %s", err)
            break
        for n in page.get("StreamNames", []) or []:
            names.append(n)
        if not page.get("HasMoreStreams"):
            break
        exclusive_start = names[-1] if names else None
        if not exclusive_start:
            break
    return names


def _cw_build_queries_for_streams(names: Sequence[str]) -> List[Dict[str, Any]]:
    """Build MetricDataQueries for a set of streams (sum/avg style metrics)."""
    queries: List[Dict[str, Any]] = []
    for idx, name in enumerate(names):
        dims = [{"Name": "StreamName", "Value": name}]
        for metric, stat, unit, prefix in (
            ("IncomingBytes", "Sum", "Bytes", "inb"),
            ("OutgoingBytes", "Sum", "Bytes", "outb"),
            ("PutRecords.Success", "Sum", "Count", "put_s"),
            ("GetRecords.Success", "Sum", "Count", "get_s"),
            ("ReadProvisionedThroughputExceeded", "Sum", "Count", "rpte"),
            ("WriteProvisionedThroughputExceeded", "Sum", "Count", "wpte"),
        ):
            queries.append(
                {
                    "Id": f"{prefix}_{idx}",
                    "MetricStat": {
                        "Metric": {
                            "Namespace": "AWS/Kinesis",
                            "MetricName": metric,
                            "Dimensions": dims,
                        },
                        "Period": 3600,
                        "Stat": stat,
                        "Unit": unit,
                    },
                    "ReturnData": True,
                }
            )
    return queries


def _cw_summarize(names: Sequence[str], results: Sequence[Mapping[str, Any]]) -> Dict[str, Dict[str, float]]:
    """Summarize MetricDataResults into a per-stream compact dict."""
    summary: Dict[str, Dict[str, float]] = {
        n: {"in_bytes": 0.0, "out_bytes": 0.0, "put_s": 0.0, "get_s": 0.0, "rpte": 0.0, "wpte": 0.0}
        for n in names
    }
    for item in results:
        rid = str(item.get("Id") or "")
        vals = [float(v) for v in (item.get("Values") or [])]
        if not rid or not vals:
            continue
        try:
            idx = int(rid.split("_")[-1])
        except (ValueError, IndexError):
            continue
        if idx < 0 or idx >= len(names):
            continue
        key = names[idx]
        total = float(sum(vals))
        if rid.startswith("inb_"):
            summary[key]["in_bytes"] = total
        elif rid.startswith("outb_"):
            summary[key]["out_bytes"] = total
        elif rid.startswith("put_s_"):
            summary[key]["put_s"] = total
        elif rid.startswith("get_s_"):
            summary[key]["get_s"] = total
        elif rid.startswith("rpte_"):
            summary[key]["rpte"] = total
        elif rid.startswith("wpte_"):
            summary[key]["wpte"] = total
    return summary


def _describe_stream_summaries(kinesis: BaseClient, names: Sequence[str]) -> Dict[str, Mapping[str, Any]]:
    """Return a map name->summary (ShardCount, Retention, Status, Enhanced monitoring)."""
    info: Dict[str, Mapping[str, Any]] = {}
    for name in names:
        try:
            resp = kinesis.describe_stream_summary(StreamName=name)
        except (BotoCoreError, ClientError):  # pragma: no cover
            continue
        s = resp.get("StreamDescriptionSummary", {}) or {}
        info[name] = {
            "arn": s.get("StreamARN", name),
            "status": s.get("StreamStatus", ""),
            "shards": int(s.get("OpenShardCount", 0) or 0),
            "retention": int(s.get("RetentionPeriodHours", 24) or 24),
            "enhanced": bool(s.get("EnhancedMonitoring", [])),
            "creation": _to_utc_iso(s.get("StreamCreationTimestamp")),
        }
    return info


def _emit(writer: Any, row: Mapping[str, Any]) -> None:
    """Emit a row using the orchestrator writer or raw fallback order."""
    if callable(WRITE_ROW):  # type: ignore[truthy-bool]
        try:
            WRITE_ROW(  # type: ignore[misc]
                writer,
                row.get("Resource_ID", ""),
                row.get("Name", ""),
                row.get("ResourceType", ""),
                row.get("OwnerId", ""),
                row.get("Region", ""),
                row.get("State", ""),
                row.get("Creation_Date", ""),
                row.get("Storage_GB", 0.0),
                row.get("Estimated_Cost_USD", 0.0),
                row.get("ApplicationID", ""),
                row.get("Application", ""),
                row.get("Environment", ""),
                row.get("ReferencedIn", ""),
                row.get("Flags", ""),
                row.get("Object_Count", ""),
                row.get("Potential_Saving_USD", None),
                row.get("Confidence", None),
                row.get("Signals", None),
            )
            return
        except Exception:  # pragma: no cover
            pass

    ordered = [
        row.get("Resource_ID", ""),
        row.get("Name", ""),
        row.get("ResourceType", ""),
        row.get("OwnerId", ""),
        row.get("Region", ""),
        row.get("State", ""),
        row.get("Creation_Date", ""),
        row.get("Storage_GB", 0.0),
        row.get("Object_Count", ""),
        row.get("Estimated_Cost_USD", 0.0),
        row.get("Potential_Saving_USD", ""),
        row.get("ApplicationID", ""),
        row.get("Application", ""),
        row.get("Environment", ""),
        row.get("ReferencedIn", ""),
        row.get("Flags", ""),
        row.get("Confidence", ""),
        _signals_str(row.get("Signals", "")),
    ]
    if hasattr(writer, "writerow"):
        writer.writerow(ordered)
    elif hasattr(writer, "write"):
        writer.write(ordered)
    elif callable(writer):
        writer(ordered)


def _owner_id(account_id: Optional[str]) -> str:
    """Resolve OwnerId: param takes precedence, else config.ACCOUNT_ID."""
    return str(account_id or getattr(CONF, "ACCOUNT_ID", ""))


# ---------------------------------------------------------------------------
# Check: Idle streams (delete/stop)
# ---------------------------------------------------------------------------


def check_kinesis_idle_streams(
    *,
    region: str,
    writer: Any,
    cloudwatch: BaseClient,
    kinesis: BaseClient,
    lookback_days: int = 30,
    bytes_threshold: int = 10 * 1024 * 1024,  # 10 MB over lookback
    account_id: Optional[str] = None,
    run_id: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Flag streams with near-zero traffic over the lookback window.

    Potential saving ≈ (shard_count × shard_hourly × 730) [+ enhanced metrics].
    """
    start = datetime.now(timezone.utc) - timedelta(days=lookback_days)
    end = datetime.now(timezone.utc)
    owner = _owner_id(account_id)

    names = _paginate_streams(kinesis)
    if not names:
        return []

    # One batched CW call: build all queries, execute once
    queries = _cw_build_queries_for_streams(names)
    batcher = CloudWatchBatcher(cloudwatch)  # do not pass 'region' kw
    # legacy add_q/execute usage to keep older style working
    for q in queries:
        batcher.add_q(query=q)
    results = batcher.execute(start, end)

    summary = _cw_summarize(names, results)
    info = _describe_stream_summaries(kinesis, names)

    rows: List[Dict[str, Any]] = []
    for name in names:
        s = summary.get(name, {})
        meta = info.get(name, {})
        in_b = float(s.get("in_bytes", 0.0))
        out_b = float(s.get("out_bytes", 0.0))
        total_b = in_b + out_b
        shards = int(meta.get("shards", 0))
        enhanced = bool(meta.get("enhanced", False))

        monthly = shards * _PER_SHARD_HOURLY * _HOURS_PER_MONTH
        if enhanced and _PER_SHARD_ENHANCED_HOURLY > 0.0:
            monthly += shards * _PER_SHARD_ENHANCED_HOURLY * _HOURS_PER_MONTH

        is_idle = total_b < float(bytes_threshold)
        potential = monthly if is_idle else 0.0

        flags: List[str] = []
        if is_idle:
            flags.append("Idle")
        if enhanced:
            flags.append("EnhancedMonitoring")

        row: Dict[str, Any] = {
            "Resource_ID": meta.get("arn", name),
            "Name": name,
            "ResourceType": "KinesisStream",
            "OwnerId": owner,
            "Region": region,
            "State": meta.get("status", ""),
            "Creation_Date": meta.get("creation", ""),
            "Storage_GB": "",
            "Object_Count": shards,
            "Estimated_Cost_USD": round(monthly, 2),
            "Potential_Saving_USD": round(potential, 2) if potential else None,
            "ApplicationID": "",
            "Application": "",
            "Environment": "",
            "ReferencedIn": "",
            "Flags": ", ".join(flags),
            "Confidence": 85 if is_idle else 60,
            "Signals": {
                "in_bytes_sum": int(in_b),
                "out_bytes_sum": int(out_b),
                "shards": shards,
                "enhanced": enhanced,
                "retention_h": int(meta.get("retention", 24)),
            },
        }
        _emit(writer, row)
        rows.append(row)

    return rows


# ---------------------------------------------------------------------------
# Check: Overprovisioned shards (rightsizing)
# ---------------------------------------------------------------------------


def _shard_rightsize_advice(
    bytes_in_sum: float,
    bytes_out_sum: float,
    shards: int,
    lookback_days: int,
    utilization_threshold: float,
) -> int:
    """Return suggested shard reduction count (>= 0) based on avg throughput.

    Each shard supports ~1 MB/s ingest and ~2 MB/s egress. We use a simple
    utilization proxy (avg over hours) to estimate how many shards could be
    removed while staying under `utilization_threshold`.
    """
    hours = max(1.0, float(lookback_days) * 24.0)
    avg_in_bps = (bytes_in_sum / hours) / 3600.0
    avg_out_bps = (bytes_out_sum / hours) / 3600.0

    cap_in_bps = 1_000_000.0 * shards
    cap_out_bps = 2_000_000.0 * shards

    util_in = avg_in_bps / max(1.0, cap_in_bps)
    util_out = avg_out_bps / max(1.0, cap_out_bps)
    worst = max(util_in, util_out)

    if worst >= utilization_threshold or shards <= 1:
        return 0

    # naive step-down: reduce until worst_util >= threshold (one step only)
    target_util = max(worst, 1e-6)
    new_shards = max(1, int(shards * target_util / max(utilization_threshold, 1e-6)))
    reduce_by = max(0, shards - new_shards)
    return reduce_by


def check_kinesis_overprovisioned_shards(
    *,
    region: str,
    writer: Any,
    cloudwatch: BaseClient,
    kinesis: BaseClient,
    lookback_days: int = 30,
    utilization_threshold: float = 0.25,
    account_id: Optional[str] = None,
    run_id: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Flag streams whose average throughput suggests fewer shards are sufficient.

    Potential saving ≈ (reduce_by × shard_hourly × 730) [+ enhanced metrics].
    """
    start = datetime.now(timezone.utc) - timedelta(days=lookback_days)
    end = datetime.now(timezone.utc)
    owner = _owner_id(account_id)

    names = _paginate_streams(kinesis)
    if not names:
        return []

    queries = _cw_build_queries_for_streams(names)
    batcher = CloudWatchBatcher(cloudwatch)  # no 'region' kw
    for q in queries:
        batcher.add_q(query=q)
    results = batcher.execute(start, end)

    summary = _cw_summarize(names, results)
    info = _describe_stream_summaries(kinesis, names)

    rows: List[Dict[str, Any]] = []
    for name in names:
        s = summary.get(name, {})
        meta = info.get(name, {})
        in_b = float(s.get("in_bytes", 0.0))
        out_b = float(s.get("out_bytes", 0.0))
        shards = int(meta.get("shards", 0))
        enhanced = bool(meta.get("enhanced", False))

        reduce_by = _shard_rightsize_advice(
            bytes_in_sum=in_b,
            bytes_out_sum=out_b,
            shards=shards,
            lookback_days=lookback_days,
            utilization_threshold=utilization_threshold,
        )
        if reduce_by <= 0:
            continue

        per_shard = _PER_SHARD_HOURLY * _HOURS_PER_MONTH
        if enhanced and _PER_SHARD_ENHANCED_HOURLY > 0.0:
            per_shard += _PER_SHARD_ENHANCED_HOURLY * _HOURS_PER_MONTH
        potential = per_shard * float(reduce_by)

        row: Dict[str, Any] = {
            "Resource_ID": meta.get("arn", name),
            "Name": name,
            "ResourceType": "KinesisStream",
            "OwnerId": owner,
            "Region": region,
            "State": meta.get("status", ""),
            "Creation_Date": meta.get("creation", ""),
            "Storage_GB": "",
            "Object_Count": shards,
            "Estimated_Cost_USD": round(per_shard * shards, 2),
            "Potential_Saving_USD": round(potential, 2),
            "ApplicationID": "",
            "Application": "",
            "Environment": "",
            "ReferencedIn": "",
            "Flags": f"RightsizeShards→-{reduce_by}",
            "Confidence": 80,
            "Signals": {
                "in_bytes_sum": int(in_b),
                "out_bytes_sum": int(out_b),
                "shards": shards,
                "enhanced": enhanced,
                "util_threshold": utilization_threshold,
            },
        }
        _emit(writer, row)
        rows.append(row)

    return rows
