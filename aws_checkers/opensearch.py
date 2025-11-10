"""Savings-focused checker for ElastiCache and OpenSearch.

This module follows **FinOps-Toolset checker conventions** so it can be
invoked by the orchestrator via `run_check(...)` just like existing checks.

Key points:
- **No main()**. Exported functions are called by the orchestrator:
  - :func:`check_elasticache_idle_clusters`
  - :func:`check_opensearch_idle_domains`
- **Use repo helpers**: `core.cloudwatch.CloudWatchBatcher` and `get_price()`.
- **No client creation**: service clients are provided by the orchestrator
  via keyword arguments (e.g., `elasticache=clients["elasticache"]`,
  `opensearch=clients["opensearch"]` or `es=clients["es"]`, and
  `cloudwatch=clients["cloudwatch"]`).
- **Writer compatibility**: accepts a `writer` and emits rows using a
  tolerant `_emit(writer, row)` helper (supports `writer.writerow`,
  `writer.write`, callable writers, etc.).

The checks identify **idle** clusters/domains only (safe, high-confidence
savings). Rightsizing logic can be layered later without changing the
contract.

Requirements: boto3/botocore, core.cloudwatch.CloudWatchBatcher, get_price().
"""
from __future__ import annotations

from dataclasses import dataclass, asdict
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple
import concurrent.futures as futures
import logging
import aws_checkers.config as CONF  # type: ignore

try:
    from botocore.client import BaseClient
    from botocore.exceptions import BotoCoreError, ClientError
except Exception as exc:  # pragma: no cover - import guard for lintable module
    raise RuntimeError(
        "botocore is required for elasticache_opensearch_checker"
    ) from exc

# Use repo helpers (do not reimplement)
try:  # primary import path for CloudWatch batcher
    from core.cloudwatch import CloudWatchBatcher
except Exception as err:  # pragma: no cover - the repo is required for this module
    raise RuntimeError("Missing core.cloudwatch.CloudWatchBatcher in repository") from err


LOGGER = logging.getLogger(__name__)
if not LOGGER.handlers:
    _handler = logging.StreamHandler()
    _handler.setFormatter(
        logging.Formatter("%(asctime)s %(levelname)s %(name)s - %(message)s")
    )
    LOGGER.addHandler(_handler)
LOGGER.setLevel(logging.INFO)

__all__ = [
    "check_elasticache_idle_clusters",
    "check_opensearch_idle_domains",
]

# Try to import the orchestrator's unified CSV writer
WRITE_ROW = None
try:  # newest layout (orchestrator helper)
    from FinOps_Toolset_V2_profiler import (  # type: ignore
        write_resource_to_csv as WRITE_ROW,  # noqa: N816 - keep name for clarity
    )
except Exception:  # pragma: no cover - alternate config entry point
    WRITE_ROW = None  # fall back to raw writer


# ---------------------------------
# Data model
# ---------------------------------

@dataclass
class ClusterRecord:
    """Normalized record for ElastiCache/OpenSearch savings finding."""

    account_id: str
    region: str
    service: str  # "ElastiCache" | "OpenSearch"
    resource_id: str  # CacheClusterId or DomainName
    engine: str
    instance_type: str
    node_count: int
    lookback_days: int
    cpu_average: float
    activity_indicator: float  # CurrConnections p95 (ElastiCache) or IndexingRate sum (OpenSearch)
    is_idle: bool
    potential_monthly_savings: float
    recommendation: str
    run_id: str

    def asdict(self) -> Dict[str, Any]:
        """Return a plain dict suitable for CSV/JSON serialization."""
        return asdict(self)


# ---------------------------------
# Small helpers (no toolset duplication)
# ---------------------------------

def _now_utc() -> datetime:
    """Return current time in UTC with tzinfo."""
    return datetime.now(tz=timezone.utc)


def _signals_to_str(signals: Any) -> str:
    """Normalize signals into the orchestrator-friendly compact string.

    Dicts are rendered as "k=v" joined by " | "; lists are joined by " | ".
    Other types are stringified.
    """
    if signals is None:
        return ""
    if isinstance(signals, str):
        return signals
    if isinstance(signals, list):
        return " | ".join(str(x) for x in signals)
    if isinstance(signals, dict):
        parts: List[str] = []
        for k, v in signals.items():
            try:
                parts.append(f"{k}={v}")
            except Exception:  # pragma: no cover - guard
                parts.append(f"{k}=<err>")
        return " | ".join(parts)
    return str(signals)


def _emit(writer: Any, row: Mapping[str, Any]) -> None:
    """Emit a row in the repository's unified CSV schema.

    If the orchestrator's :func:`write_resource_to_csv` is available, this
    function uses it. Otherwise it falls back to writing the ordered list of
    columns directly via `writer.writerow([...])`.
    """
    if not writer:
        return

    # Prefer the repo's writer to ensure consistent schema & derived columns
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
        except Exception:  # pragma: no cover - fallback to raw writer
            pass

    # Raw fallback — mirrors orchestrator column order
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
        # Signals string; if dict, join k=v to a string similar to orchestrator
        _signals_to_str(row.get("Signals", "")),
    ]

    if hasattr(writer, "writerow"):
        writer.writerow(ordered)
        return
    if hasattr(writer, "write"):
        writer.write(ordered)
        return
    if callable(writer):  # type: ignore[call-arg]
        writer(ordered)
        return
    for meth in ("writerow", "write", "emit"):
        if hasattr(writer, meth):
            getattr(writer, meth)(row)
            return
    if callable(writer):  # type: ignore[call-arg]
        writer(row)


def _paginate(
    fetch_fn,  # type: ignore[no-untyped-def]
    *,
    page_key: str,
    next_key: str = "Marker",
    **kwargs: Any,
) -> Iterable[Mapping[str, Any]]:
    """Generic paginator for AWS list/describe APIs using Marker/NextToken.

    Args:
        fetch_fn: Callable for the API (e.g., describe_cache_clusters).
        page_key: Key containing the list of items in the page.
        next_key: Continuation token key; defaults to "Marker".
        **kwargs: Additional parameters for the fetch function.

    Yields:
        Items across all pages.
    """
    token_key = next_key
    marker: Optional[str] = None
    while True:
        params = dict(kwargs)
        if marker:
            params[token_key] = marker
        try:
            page = fetch_fn(**params)
        except (BotoCoreError, ClientError) as err:  # pragma: no cover - network
            LOGGER.error("Pagination error: %s", err)
            break
        for item in page.get(page_key, []) or []:
            yield item
        marker = page.get(token_key) or page.get("NextToken")
        if not marker:
            break


def _safe_get_price(key_candidates: Sequence[str], default: float = 0.0) -> float:
    """Resolve a price using the repo's :func:`get_price` with safe fallbacks.

    The helper tries each key in order and returns the first non-None value.
    A float default is returned if nothing resolves.
    """
    for key in key_candidates:
        try:
            val = CONF.safe_price(key, default)  # type: ignore[call-arg]
            if val is not None:
                return float(val)
        except Exception:  # pragma: no cover - keep scanning
            continue
    return float(default)


def _hourly_price_for_instance(service_prefix: str, instance_type: str) -> float:
    """Return hourly price for an instance/node type via :func:`get_price`.

    Tries common key patterns used in cost maps. Example candidates:
    - `elasticache.instance_hourly.cache.r6g.large`
    - `elasticache.node_hourly.cache.r6g.large`
    - `opensearch.instance_hourly.r6g.large.search`
    - `es.instance_hourly.r6g.large`
    - `aws.es.r6g.large.hourly`
    Defaults to 0.0 if unknown (savings will then be zeroed, conservative).
    """
    inst = instance_type.strip()
    candidates = [
        f"{service_prefix}.instance_hourly.{inst}",
        f"{service_prefix}.node_hourly.{inst}",
        f"aws.{service_prefix}.{inst}.hourly",
        f"{service_prefix}.{inst}.hourly",
        f"{service_prefix}.hourly.{inst}",
    ]
    if service_prefix == "opensearch":  # also try legacy ES keys
        candidates.extend(
            [
                f"es.instance_hourly.{inst}",
                f"aws.es.{inst}.hourly",
            ]
        )
    return _safe_get_price(candidates, default=0.0)


def _monthly_cost_from_nodes(service_prefix: str, instance_type: str, count: int) -> float:
    """Compute conservative monthly cost based on hourly * 730 * count."""
    hourly = _hourly_price_for_instance(service_prefix, instance_type)
    return round(hourly * 730.0 * float(max(count, 0)), 2)


def _run_cw_queries(
    cw: BaseClient, queries: Sequence[Dict[str, Any]], start: datetime, end: datetime
) -> List[Mapping[str, Any]]:
    """Execute CloudWatch GetMetricData using :class:`CloudWatchBatcher`.

    Returns the raw `MetricDataResults` list.
    """
    batcher = CloudWatchBatcher(cw)
    if hasattr(batcher, "get_metric_data"):
        resp = batcher.get_metric_data(  # type: ignore[attr-defined]
            MetricDataQueries=list(queries),
            StartTime=start,
            EndTime=end,
            ScanBy="TimestampAscending",
        )
        return list(resp.get("MetricDataResults", []) or [])
    if hasattr(batcher, "run"):
        results = batcher.run(list(queries), start, end)  # type: ignore[attr-defined]
        return list(results)
    resp = cw.get_metric_data(
        MetricDataQueries=list(queries),
        StartTime=start,
        EndTime=end,
        ScanBy="TimestampAscending",
    )
    return list(resp.get("MetricDataResults", []) or [])


# ---------------------------------
# ElastiCache
# ---------------------------------

def _discover_cache_clusters(elasticache: BaseClient) -> List[Mapping[str, Any]]:
    """Return cache clusters across all pages (summaries)."""
    return list(
        _paginate(
            elasticache.describe_cache_clusters,
            page_key="CacheClusters",
            next_key="Marker",
            ShowCacheNodeInfo=False,
        )
    )


def _ec_queries_for_clusters(clusters: Sequence[Mapping[str, Any]]) -> Tuple[List[Dict[str, Any]], Dict[str, str]]:
    """Build CloudWatch queries for ElastiCache clusters.

    For each `CacheClusterId`, create metric queries for:
      - CPUUtilization (Average)
      - CurrConnections (Maximum ~ p95)
      - NetworkBytesIn/Out (Sum), with an expression to add them

    Returns the list of queries and a map of result `Id` to cluster id.
    """
    queries: List[Dict[str, Any]] = []
    id_map: Dict[str, str] = {}
    for idx, c in enumerate(clusters):
        cid = c.get("CacheClusterId") or f"cluster-{idx}"
        # CPU average
        qid_cpu = f"ec_cpu_{idx}"
        queries.append(
            {
                "Id": qid_cpu,
                "MetricStat": {
                    "Metric": {
                        "Namespace": "AWS/ElastiCache",
                        "MetricName": "CPUUtilization",
                        "Dimensions": [{"Name": "CacheClusterId", "Value": cid}],
                    },
                    "Period": 3600,
                    "Stat": "Average",
                    "Unit": "Percent",
                },
                "ReturnData": True,
            }
        )
        id_map[qid_cpu] = cid

        # CurrConnections (using Max over the period approximates p95 at low volume)
        qid_conn = f"ec_conn_{idx}"
        queries.append(
            {
                "Id": qid_conn,
                "MetricStat": {
                    "Metric": {
                        "Namespace": "AWS/ElastiCache",
                        "MetricName": "CurrConnections",
                        "Dimensions": [{"Name": "CacheClusterId", "Value": cid}],
                    },
                    "Period": 3600,
                    "Stat": "Maximum",
                    "Unit": "Count",
                },
                "ReturnData": True,
            }
        )
        id_map[qid_conn] = cid

        # Network I/O sum (In + Out) as a single expression result
        qid_in = f"ec_in_{idx}"
        qid_out = f"ec_out_{idx}"
        qid_net = f"ec_net_{idx}"
        for metric, qid in (("NetworkBytesIn", qid_in), ("NetworkBytesOut", qid_out)):
            queries.append(
                {
                    "Id": qid,
                    "MetricStat": {
                        "Metric": {
                            "Namespace": "AWS/ElastiCache",
                            "MetricName": metric,
                            "Dimensions": [{"Name": "CacheClusterId", "Value": cid}],
                        },
                        "Period": 3600,
                        "Stat": "Sum",
                        "Unit": "Bytes",
                    },
                    "ReturnData": False,
                }
            )
        queries.append(
            {
                "Id": qid_net,
                "Expression": f"SUM([{qid_in},{qid_out}])",
                "Label": f"{cid}:NetworkBytesTotal",
                "ReturnData": True,
            }
        )
        id_map[qid_net] = cid
    return queries, id_map


def _ec_summarize_results(
    clusters: Sequence[Mapping[str, Any]],
    results: Sequence[Mapping[str, Any]],
) -> Dict[str, Dict[str, float]]:
    """Summarize CloudWatch results into per-cluster indicators.

    Returns a mapping: CacheClusterId -> {"cpu_avg": float, "conn_p95": float, "net_sum": float}
    """
    cluster_ids = {c.get("CacheClusterId") or "": True for c in clusters}
    summary: Dict[str, Dict[str, float]] = {
        cid: {"cpu_avg": 0.0, "conn_p95": 0.0, "net_sum": 0.0} for cid in cluster_ids
    }
    for item in results:
        rid = item.get("Id") or ""
        if not rid:
            continue
        vals = [float(v) for v in (item.get("Values") or [])]
        if not vals:
            continue
        avg_val = sum(vals) / float(len(vals))
        if rid.startswith("ec_cpu_"):
            idx = int(rid.split("_")[-1])
            cid = clusters[int(idx)].get("CacheClusterId") or ""
            if cid:
                summary[cid]["cpu_avg"] = avg_val
        elif rid.startswith("ec_conn_"):
            idx = int(rid.split("_")[-1])
            cid = clusters[int(idx)].get("CacheClusterId") or ""
            if cid:
                summary[cid]["conn_p95"] = max(vals)  # use max as p95 approximation
        elif rid.startswith("ec_net_"):
            idx = int(rid.split("_")[-1])
            cid = clusters[int(idx)].get("CacheClusterId") or ""
            if cid:
                summary[cid]["net_sum"] = float(sum(vals))
    return summary


# ---------------------------------
# OpenSearch
# ---------------------------------

def _get_os_client(opensearch: Optional[BaseClient], es: Optional[BaseClient]) -> BaseClient:
    """Return a client for OpenSearch, falling back to legacy `es` if needed.

    Args:
        opensearch: Boto3 OpenSearch client if available.
        es: Legacy Elasticsearch Service client if available.

    Returns:
        A working client (OpenSearch preferred), or raises `RuntimeError`.
    """
    if opensearch is not None:
        return opensearch
    if es is not None:
        return es
    raise RuntimeError("Neither 'opensearch' nor 'es' client was provided")


def _discover_domains(os_client: BaseClient) -> List[str]:
    """Return a list of domain names for OpenSearch in the region."""
    try:
        resp = os_client.list_domain_names()
        names = [d.get("DomainName", "") for d in resp.get("DomainNames", [])]
    except (BotoCoreError, ClientError) as err:  # pragma: no cover - network
        LOGGER.error("list_domain_names failed: %s", err)
        names = []
    return [n for n in names if n]


def _describe_domain(os_client: BaseClient, name: str) -> Mapping[str, Any]:
    """Describe an OpenSearch/ES domain and return its status structure."""
    try:
        resp = os_client.describe_domain(DomainName=name)
        return resp.get("DomainStatus", {})
    except (BotoCoreError, ClientError) as err:  # pragma: no cover - network
        LOGGER.warning("describe_domain failed for %s: %s", name, err)
        return {}


def _os_queries_for_domains(names: Sequence[str]) -> List[Dict[str, Any]]:
    """Build CloudWatch queries for OpenSearch domains (namespace `AWS/ES`).

    For each domain, create queries for:
      - CPUUtilization (Average)
      - JVMMemoryPressure (Average)
      - IndexingRate (Sum)

    Returns a list of queries; results are mapped by ID prefix.
    """
    queries: List[Dict[str, Any]] = []
    ns = "AWS/ES"
    for idx, name in enumerate(names):
        dim = [{"Name": "DomainName", "Value": name}]
        qid_cpu = f"os_cpu_{idx}"
        qid_jvm = f"os_jvm_{idx}"
        qid_idx = f"os_idx_{idx}"
        queries.extend(
            [
                {
                    "Id": qid_cpu,
                    "MetricStat": {
                        "Metric": {
                            "Namespace": ns,
                            "MetricName": "CPUUtilization",
                            "Dimensions": dim,
                        },
                        "Period": 3600,
                        "Stat": "Average",
                        "Unit": "Percent",
                    },
                    "ReturnData": True,
                },
                {
                    "Id": qid_jvm,
                    "MetricStat": {
                        "Metric": {
                            "Namespace": ns,
                            "MetricName": "JVMMemoryPressure",
                            "Dimensions": dim,
                        },
                        "Period": 3600,
                        "Stat": "Average",
                        "Unit": "Percent",
                    },
                    "ReturnData": True,
                },
                {
                    "Id": qid_idx,
                    "MetricStat": {
                        "Metric": {
                            "Namespace": ns,
                            "MetricName": "IndexingRate",
                            "Dimensions": dim,
                        },
                        "Period": 3600,
                        "Stat": "Sum",
                        "Unit": "Count/Second",
                    },
                    "ReturnData": True,
                },
            ]
        )
    return queries


def _os_summarize_results(
    names: Sequence[str], results: Sequence[Mapping[str, Any]]
) -> Dict[str, Dict[str, float]]:
    """Summarize CloudWatch results into per-domain indicators.

    Returns: DomainName -> {"cpu_avg": float, "jvm_avg": float, "index_sum": float}
    """
    summary: Dict[str, Dict[str, float]] = {
        n: {"cpu_avg": 0.0, "jvm_avg": 0.0, "index_sum": 0.0} for n in names
    }
    for item in results:
        rid = item.get("Id") or ""
        if not rid:
            continue
        vals = [float(v) for v in (item.get("Values") or [])]
        if not vals:
            continue
        avg_val = sum(vals) / float(len(vals))
        try:
            idx = int(rid.split("_")[-1])
        except (ValueError, IndexError):
            continue
        if idx < 0 or idx >= len(names):
            continue
        name = names[idx]
        if rid.startswith("os_cpu_"):
            summary[name]["cpu_avg"] = avg_val
        elif rid.startswith("os_jvm_"):
            summary[name]["jvm_avg"] = avg_val
        elif rid.startswith("os_idx_"):
            summary[name]["index_sum"] = float(sum(vals))
    return summary


# ---------------------------------
# Orchestrator-compatible public checks
# ---------------------------------

def check_elasticache_idle_clusters(
    *,
    region: str,
    writer: Any,
    cloudwatch: BaseClient,
    elasticache: BaseClient,
    account_id: Optional[str] = None,
    lookback_days: int = 30,
    run_id: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Checker for **idle ElastiCache clusters** with savings estimates.

    This function is designed to be called by the orchestrator via
    `run_check(…, region, check_elasticache_idle_clusters, writer=…, cloudwatch=…, elasticache=…, …)`.

    Args:
        region: AWS region for the check.
        writer: Writer object used by the toolset to emit rows.
        cloudwatch: Boto3 CloudWatch client (from orchestrator).
        elasticache: Boto3 ElastiCache client (from orchestrator).
        account_id: Optional AWS account ID for output; can be added by upstream.
        lookback_days: Number of days of metrics to analyze.
        run_id: Optional correlation id for this run; defaults to UTC timestamp.

    Returns:
        List of row dicts that were emitted, for convenience/testing.
    """
    start = _now_utc() - timedelta(days=lookback_days)
    end = _now_utc()

    clusters = _discover_cache_clusters(elasticache)
    queries, _ = _ec_queries_for_clusters(clusters)
    results = _run_cw_queries(cloudwatch, queries, start, end)
    summary = _ec_summarize_results(clusters, results)

    rows: List[Dict[str, Any]] = []
    for c in clusters:
        cid = c.get("CacheClusterId", "")
        node_type = c.get("CacheNodeType", "")
        nodes = int(c.get("NumCacheNodes", 0))
        status = c.get("CacheClusterStatus", "")
        created = c.get("CacheClusterCreateTime")
        created_iso = created.strftime("%Y-%m-%dT%H:%M:%SZ") if hasattr(created, "strftime") else ""
        arn = c.get("ARN", "") or cid

        s = summary.get(cid, {"cpu_avg": 0.0, "conn_p95": 0.0, "net_sum": 0.0})
        cpu = float(s["cpu_avg"])  # average CPU %
        conn = float(s["conn_p95"])  # approximate p95 connections
        net_total = float(s["net_sum"])  # bytes over lookback

        is_idle = (cpu < 2.0) and (conn < 1.0) and (net_total < 10_000_000.0)
        monthly_cost = _monthly_cost_from_nodes("elasticache", node_type, nodes)
        savings = monthly_cost if is_idle else 0.0

        flags = []
        if is_idle:
            flags.append("Idle")
        if cpu < 2.0:
            flags.append("CPU<2%")
        if conn < 1.0:
            flags.append("Conn≈0")
        if net_total < 10_000_000.0:
            flags.append("Net<10MB/period")

        row: Dict[str, Any] = {
            "Resource_ID": arn,
            "Name": cid,
            "ResourceType": "ElastiCacheCluster",
            "OwnerId": account_id or "",
            "Region": region,
            "State": status,
            "Creation_Date": created_iso,
            "Storage_GB": 0.0,
            "Object_Count": "",
            "Estimated_Cost_USD": monthly_cost,
            "Potential_Saving_USD": savings if is_idle else None,
            "ApplicationID": "",
            "Application": "",
            "Environment": "",
            "ReferencedIn": "",
            "Flags": ", ".join(flags),
            "Confidence": 90 if is_idle else 70,
            "Signals": {
                "cpu_avg_pct": round(cpu, 2),
                "conn_p95": round(conn, 2),
                "net_bytes_sum": int(net_total),
                "node_count": nodes,
                "node_type": node_type,
            },
        }
        _emit(writer, row)
        rows.append(row)

    return rows


def check_opensearch_idle_domains(
    *,
    region: str,
    writer: Any,
    cloudwatch: BaseClient,
    opensearch: Optional[BaseClient] = None,
    es: Optional[BaseClient] = None,
    account_id: Optional[str] = None,
    lookback_days: int = 30,
    max_workers: int = 16,
    run_id: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Checker for **idle OpenSearch/ES domains** with savings estimates.

    Designed for orchestrator usage:
    `run_check(…, region, check_opensearch_idle_domains, writer=…, cloudwatch=…, opensearch=…|es=…, …)`.

    Args:
        region: AWS region for the check.
        writer: Writer object used by the toolset to emit rows.
        cloudwatch: Boto3 CloudWatch client (from orchestrator).
        opensearch: Boto3 OpenSearch client if available.
        es: Legacy Elasticsearch Service client alternative.
        account_id: Optional AWS account ID for output.
        lookback_days: Number of days of metrics to analyze.
        max_workers: Concurrency for domain describes.
        run_id: Optional correlation id for this run.

    Returns:
        List of row dicts that were emitted, for convenience/testing.
    """
    start = _now_utc() - timedelta(days=lookback_days)
    end = _now_utc()

    os_client = _get_os_client(opensearch, es)
    names = _discover_domains(os_client)

    if names:
        q_os = _os_queries_for_domains(names)
        r_os = _run_cw_queries(cloudwatch, q_os, start, end)
        os_summary = _os_summarize_results(names, r_os)
    else:
        os_summary = {}

    rows: List[Dict[str, Any]] = []
    with futures.ThreadPoolExecutor(max_workers=max_workers) as pool:
        futs = {pool.submit(_describe_domain, os_client, name): name for name in names}
        for fut in futures.as_completed(futs):
            name = futs[fut]
            status = fut.result() or {}
            cfg = status.get("ClusterConfig", {})
            data_type = cfg.get("InstanceType", "")
            data_count = int(cfg.get("InstanceCount", 0) or 0)
            master_count = (
                int(cfg.get("DedicatedMasterCount", 0) or 0)
                if cfg.get("DedicatedMasterEnabled")
                else 0
            )
            master_type = cfg.get("DedicatedMasterType", "") if master_count else ""
            warm_count = int(cfg.get("WarmCount", 0) or 0) if cfg.get("WarmEnabled") else 0
            warm_type = cfg.get("WarmType", "") if warm_count else ""
            domain_arn = status.get("ARN", "") or name
            processing = status.get("Processing", False)
            state = "processing" if processing else "active"

            s = os_summary.get(name, {"cpu_avg": 0.0, "jvm_avg": 0.0, "index_sum": 0.0})
            cpu = float(s["cpu_avg"])  # average CPU %
            index_sum = float(s["index_sum"])  # total index ops over time window

            is_idle = (cpu < 2.0) and (index_sum < 1.0)

            monthly_cost = 0.0
            monthly_cost += _monthly_cost_from_nodes("opensearch", data_type, data_count)
            if master_count and master_type:
                monthly_cost += _monthly_cost_from_nodes(
                    "opensearch", master_type, master_count
                )
            if warm_count and warm_type:
                monthly_cost += _monthly_cost_from_nodes("opensearch", warm_type, warm_count)

            savings = monthly_cost if is_idle else 0.0

            flags = []
            if is_idle:
                flags.append("Idle")
            if cpu < 2.0:
                flags.append("CPU<2%")
            if index_sum < 1.0:
                flags.append("Index≈0")

            row: Dict[str, Any] = {
                "Resource_ID": domain_arn,
                "Name": name,
                "ResourceType": "OpenSearchDomain",
                "OwnerId": account_id or "",
                "Region": region,
                "State": state,
                "Creation_Date": "",
                "Storage_GB": 0.0,
                "Object_Count": "",
                "Estimated_Cost_USD": round(monthly_cost, 2),
                "Potential_Saving_USD": round(savings, 2) if is_idle else None,
                "ApplicationID": "",
                "Application": "",
                "Environment": "",
                "ReferencedIn": "",
                "Flags": ", ".join(flags),
                "Confidence": 90 if is_idle else 70,
                "Signals": {
                    "cpu_avg_pct": round(cpu, 2),
                    "index_sum": round(index_sum, 2),
                    "data_nodes": data_count,
                    "master_nodes": master_count,
                    "warm_nodes": warm_count,
                    "data_type": data_type,
                    "master_type": master_type,
                    "warm_type": warm_type,
                },
            }
            _emit(writer, row)
            rows.append(row)

    return rows
