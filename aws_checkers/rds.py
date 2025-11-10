"""RDS & Aurora savings checkers (extended coverage).

RDS/Aurora analysis beyond engine-version support to include high-value
savings opportunities:

- Underutilized RDS instances → rightsizing suggestions
- Multi-AZ on non‑prod → consider single‑AZ
- Unused read replicas → remove
- Provisioned IOPS overprovisioned → reduce
- gp2 → gp3 storage class modernization
- Aurora (cluster) low activity → review for downsizing (and pause when
  `EngineMode=serverless`)
- Engine versions in extended/legacy support windows → upgrade

"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple
import concurrent.futures as futures
import aws_checkers.config as CONF  # type: ignore

try:
    from botocore.client import BaseClient
    from botocore.exceptions import BotoCoreError, ClientError
except Exception as exc:  # pragma: no cover - import guard for lintable module
    raise RuntimeError("botocore is required for rds_aurora_savings") from exc

# Repo helpers
try:
    from core.cloudwatch import CloudWatchBatcher
except Exception as err:  # pragma: no cover - repository contract
    raise RuntimeError("Missing core.cloudwatch.CloudWatchBatcher in repository") from err

# Central repo helpers (logger, signals formatter, ISO-8601)
try:
    from aws_checkers.common import _logger, _signals_str, _to_utc_iso  # type: ignore
except Exception as err:  # pragma: no cover
    raise RuntimeError("Missing aws_checkers.common helpers (_logger, _signals_str, _to_utc_iso)") from err


if not hasattr(CONF, "safe_price"):
    raise RuntimeError("config.safe_price is required by this checker module")

if not hasattr(CONF, "ACCOUNT_ID"):
    raise RuntimeError("config.ACCOUNT_ID is required by this checker module")

__all__ = [
    # Orchestrator-visible checks
    "check_rds_underutilized_instances",
    "check_rds_multi_az_non_prod",
    "check_rds_unused_read_replicas",
    "check_rds_iops_overprovisioned",
    "check_rds_gp2_to_gp3_candidates",
    "check_aurora_low_activity_clusters",
    "check_rds_engine_extended_support",
]

# Try to import the orchestrator's unified CSV writer
WRITE_ROW = None
try:  # newest layout (orchestrator helper)
    from FinOps_Toolset_V2_profiler import (  # type: ignore
        write_resource_to_csv as WRITE_ROW,  # noqa: N816 - keep name for clarity
    )
except Exception:  # pragma: no cover - alternate config entry point
    WRITE_ROW = None  # fall back to raw writer


# ----------------------------------------------------------------------------
# Shared helpers
# ----------------------------------------------------------------------------

def _now_utc() -> datetime:
    """Return the current UTC time with tzinfo."""
    return datetime.now(tz=timezone.utc)

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
        _signals_str(row.get("Signals", "")),
    ]

    if hasattr(writer, "writerow"):
        writer.writerow(ordered)
        return
    if hasattr(writer, "write"):
        writer.write(ordered)
        return
    if callable(writer):  # type: ignore[call-arg]
        writer(ordered)


# Pricing helpers -------------------------------------------------------------

def _safe_price(key: str, default: float = 0.0) -> float:
    """Look up a price using :func:`config.safe_price` with default fallback."""
    try:
        # Support both signatures: safe_price(key) and safe_price(key, default)
        try:
            val = CONF.safe_price(key, default)  # type: ignore[attr-defined]
        except TypeError:
            val = CONF.safe_price(key, default)  # type: ignore[attr-defined]
        if val is None:
            return float(default)
        return float(val)
    except Exception:  # pragma: no cover
        return float(default)


def _hourly_price_instance(instance_class: str) -> float:
    """Return estimated hourly price for an RDS instance class.

    Tries multiple pricing key variants in the repo pricing map.
    """
    inst = instance_class.strip()
    candidates = [
        f"rds.instance_hourly.{inst}",
        f"rds.instance_hourly.{inst.replace('db.', '')}",
        f"aws.rds.{inst}.hourly",
        f"aws.rds.{inst.replace('db.', '')}.hourly",
    ]
    for key in candidates:
        p = _safe_price(key, default=0.0)
        if p > 0.0:
            return p
    return 0.0


def _gp_price_delta_per_gb_month() -> float:
    """Return gp2→gp3 price delta per GB-month (positive means gp2 is costlier)."""
    p_gp2 = _safe_price("rds.gp2_gb_month", 0.10)
    p_gp3 = _safe_price("rds.gp3_gb_month", 0.08)
    return max(0.0, p_gp2 - p_gp3)


def _iops_price_per_month() -> float:
    """Return provisioned IOPS monthly price per IOPS (io1/io2)."""
    return _safe_price("rds.iops_prov_month", 0.10)


# Data helpers ----------------------------------------------------------------

def _paginate(
    fetch_fn,  # type: ignore[no-untyped-def]
    *,
    page_key: str,
    next_key: str = "Marker",
    **kwargs: Any,
) -> Iterable[Mapping[str, Any]]:
    """Generic paginator for AWS APIs using Marker/NextToken semantics."""

    log = _logger(kwargs.get("logger"))
    token: Optional[str] = None
    while True:
        params = dict(kwargs)
        if token:
            params[next_key] = token
        try:
            page = fetch_fn(**params)
        except (BotoCoreError, ClientError) as err:  # pragma: no cover - network
            log.error("Pagination error: %s", err)
            break
        for item in page.get(page_key, []) or []:
            yield item
        token = page.get(next_key) or page.get("NextToken")
        if not token:
            break


def _list_db_instances(rds: BaseClient) -> List[Mapping[str, Any]]:
    """Return all DB instances in the region (summaries)."""
    instances = list(
        _paginate(rds.describe_db_instances, page_key="DBInstances", next_key="Marker")
    )
    return instances


def _list_db_clusters(rds: BaseClient) -> List[Mapping[str, Any]]:
    """Return all DB clusters (Aurora)."""
    clusters = list(
        _paginate(rds.describe_db_clusters, page_key="DBClusters", next_key="Marker")
    )
    return clusters


def _list_tags(rds: BaseClient, arn: str) -> Dict[str, str]:
    """Return tags for a given RDS ARN as a simple dict."""
    try:
        resp = rds.list_tags_for_resource(ResourceName=arn)
        tags = resp.get("TagList", []) or []
        out: Dict[str, str] = {}
        for t in tags:
            k = str(t.get("Key") or "").strip()
            v = str(t.get("Value") or "").strip()
            if k:
                out[k.lower()] = v
        return out
    except (BotoCoreError, ClientError):  # pragma: no cover - best effort only
        return {}


def _env_from_tags(tags: Mapping[str, str]) -> str:
    """Infer environment name from common tag keys (best-effort)."""
    for key in ("env", "environment", "stage", "stack"):
        v = tags.get(key)
        if v:
            return v.lower()
    return ""


def _build_rds_metric_queries(inst_ids: Sequence[str]) -> List[Dict[str, Any]]:
    """Build CloudWatch GetMetricData queries for RDS instances.

    For each instance id, we query:
      - CPUUtilization (Average)
      - DatabaseConnections (Maximum)
      - ReadIOPS (Sum)
      - WriteIOPS (Sum)
    """
    queries: List[Dict[str, Any]] = []
    for idx, name in enumerate(inst_ids):
        dim = [{"Name": "DBInstanceIdentifier", "Value": name}]
        for metric, stat, unit, qprefix in (
            ("CPUUtilization", "Average", "Percent", "cpu"),
            ("DatabaseConnections", "Maximum", "Count", "conn"),
            ("ReadIOPS", "Sum", "Count/Second", "riops"),
            ("WriteIOPS", "Sum", "Count/Second", "wiops"),
        ):
            queries.append(
                {
                    "Id": f"{qprefix}_{idx}",
                    "MetricStat": {
                        "Metric": {
                            "Namespace": "AWS/RDS",
                            "MetricName": metric,
                            "Dimensions": dim,
                        },
                        "Period": 3600,
                        "Stat": stat,
                        "Unit": unit,
                    },
                    "ReturnData": True,
                }
            )
    return queries


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


def _summarize_rds_results(inst_ids: Sequence[str], results: Sequence[Mapping[str, Any]]) -> Dict[str, Dict[str, float]]:
    """Summarize per-instance metrics from GetMetricData results."""
    summary: Dict[str, Dict[str, float]] = {
        i: {"cpu_avg": 0.0, "conn_max": 0.0, "riops_sum": 0.0, "wiops_sum": 0.0}
        for i in inst_ids
    }
    for item in results:
        rid = item.get("Id", "")
        if not rid:
            continue
        vals = [float(v) for v in (item.get("Values") or [])]
        if not vals:
            continue
        try:
            idx = int(rid.split("_")[-1])
        except (ValueError, IndexError):
            continue
        if idx < 0 or idx >= len(inst_ids):
            continue
        name = inst_ids[idx]
        if rid.startswith("cpu_"):
            summary[name]["cpu_avg"] = sum(vals) / float(len(vals))
        elif rid.startswith("conn_"):
            summary[name]["conn_max"] = max(vals)
        elif rid.startswith("riops_"):
            summary[name]["riops_sum"] = sum(vals)
        elif rid.startswith("wiops_"):
            summary[name]["wiops_sum"] = sum(vals)
    return summary


def _step_down_instance_class(inst: str) -> str:
    """Return a one-step smaller RDS class within the same family.

    Example: `db.r6g.2xlarge` → `db.r6g.xlarge`; `db.t3.medium` → `db.t3.small`.
    Returns the input if no smaller size is known.
    """
    sizes = [
        "nano",
        "micro",
        "small",
        "medium",
        "large",
        "xlarge",
        "2xlarge",
        "4xlarge",
        "8xlarge",
        "12xlarge",
        "16xlarge",
        "24xlarge",
        "32xlarge",
        "48xlarge",
        "56xlarge",
        "metal",
    ]
    try:
        parts = inst.split(".")
        # expected: db, family, size
        if len(parts) < 3:
            return inst
        size = parts[-1]
        if size not in sizes:
            return inst
        idx = sizes.index(size)
        if idx == 0:
            return inst
        parts[-1] = sizes[idx - 1]
        return ".".join(parts)
    except Exception:  # pragma: no cover
        return inst


# ----------------------------------------------------------------------------
# Checkers (orchestrator-callable)
# ----------------------------------------------------------------------------

def check_rds_underutilized_instances(
    writer: Any,
    region: str,
    *,
    cloudwatch: BaseClient,
    rds: BaseClient,
    lookback_days: int = 30,
    cpu_threshold_pct: float = 20.0,
    conn_threshold: float = 5.0,
    account_id: Optional[str] = None,
    run_id: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Flag RDS instances with low CPU and connections → rightsizing candidate.

    Emits a row with `Potential_Saving_USD` equal to the delta between the
    current class and a one-step smaller class (hourly × 730), when a smaller
    class exists.
    """
    rid = run_id or _now_utc().strftime("%Y%m%dT%H%M%SZ")
    owner = str(account_id or getattr(CONF, "ACCOUNT_ID", ""))
    start = _now_utc() - timedelta(days=lookback_days)
    end = _now_utc()

    instances = _list_db_instances(rds)
    inst_ids = [i.get("DBInstanceIdentifier", "") for i in instances if i.get("DBInstanceIdentifier")]

    queries = _build_rds_metric_queries(inst_ids)
    results = _run_cw_queries(cloudwatch, queries, start, end)
    metrics = _summarize_rds_results(inst_ids, results)

    rows: List[Dict[str, Any]] = []
    for inst in instances:
        inst_id = inst.get("DBInstanceIdentifier", "")
        arn = inst.get("DBInstanceArn", inst_id)
        cls = inst.get("DBInstanceClass", "")
        status = inst.get("DBInstanceStatus", "")
        created = inst.get("InstanceCreateTime")
        created_iso = _to_utc_iso(created) if created else ""

        m = metrics.get(inst_id, {"cpu_avg": 0.0, "conn_max": 0.0})
        cpu = float(m.get("cpu_avg", 0.0))
        conn = float(m.get("conn_max", 0.0))

        smaller = _step_down_instance_class(cls)
        price_now = _hourly_price_instance(cls)
        price_small = _hourly_price_instance(smaller)
        delta_hourly = max(0.0, price_now - price_small) if smaller != cls else 0.0
        potential = 730.0 * delta_hourly if (cpu < cpu_threshold_pct and conn < conn_threshold) else 0.0

        flags: List[str] = []
        if cpu < cpu_threshold_pct:
            flags.append(f"CPU<{cpu_threshold_pct}%")
        if conn < conn_threshold:
            flags.append(f"Conn<{int(conn_threshold)}")
        if potential > 0.0:
            flags.append("RightsizeOneStep")

        row: Dict[str, Any] = {
            "Resource_ID": arn,
            "Name": inst_id,
            "ResourceType": "RDSInstance",
            "OwnerId": owner,
            "Region": region,
            "State": status,
            "Creation_Date": created_iso,
            "Storage_GB": inst.get("AllocatedStorage", 0),
            "Object_Count": "",
            "Estimated_Cost_USD": round(price_now * 730.0, 2),
            "Potential_Saving_USD": round(potential, 2) if potential > 0.0 else None,
            "ApplicationID": "",
            "Application": "",
            "Environment": _env_from_tags(_list_tags(rds, arn)),
            "ReferencedIn": "",
            "Flags": ", ".join(flags),
            "Confidence": 75 if potential > 0.0 else 60,
            "Signals": {
                "cpu_avg_pct": round(cpu, 1),
                "conn_max": round(conn, 1),
                "class": cls,
                "suggested_class": smaller if smaller != cls else "",
            },
            "RunId": rid,
        }
        _emit(writer, row)
        rows.append(row)

    return rows


def check_rds_multi_az_non_prod(
    writer: Any,
    region: str,
    *,
    rds: BaseClient,
    account_id: Optional[str] = None,
    run_id: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Flag Multi‑AZ instances in non‑prod environments → consider single‑AZ.

    Savings is approximated as one instance-hour's monthly cost (730× hourly)
    because Multi‑AZ provisions a standby replica.
    """
    rid = run_id or _now_utc().strftime("%Y%m%dT%H%M%SZ")
    owner = str(account_id or getattr(CONF, "ACCOUNT_ID", ""))

    instances = _list_db_instances(rds)
    rows: List[Dict[str, Any]] = []

    # Fetch tags concurrently (can be slow per-instance)
    with futures.ThreadPoolExecutor(max_workers=16) as pool:
        futs = {pool.submit(_list_tags, rds, i.get("DBInstanceArn", "")): i for i in instances}
        tag_map: Dict[str, Dict[str, str]] = {}
        for fut, inst in futs.items():
            try:
                tag_map[inst.get("DBInstanceIdentifier", "")] = fut.result()
            except Exception:  # pragma: no cover - conservative
                tag_map[inst.get("DBInstanceIdentifier", "")] = {}

    for inst in instances:
        if not inst.get("MultiAZ"):
            continue
        inst_id = inst.get("DBInstanceIdentifier", "")
        arn = inst.get("DBInstanceArn", inst_id)
        env = _env_from_tags(tag_map.get(inst_id, {}))
        if env in {"prod", "production", "live"}:
            continue
        cls = inst.get("DBInstanceClass", "")
        price_hourly = _hourly_price_instance(cls)
        potential = 730.0 * price_hourly if price_hourly > 0.0 else 0.0

        row: Dict[str, Any] = {
            "Resource_ID": arn,
            "Name": inst_id,
            "ResourceType": "RDSInstance",
            "OwnerId": owner,
            "Region": region,
            "State": inst.get("DBInstanceStatus", ""),
            "Creation_Date": "",
            "Storage_GB": inst.get("AllocatedStorage", 0),
            "Object_Count": "",
            "Estimated_Cost_USD": round(price_hourly * 730.0 * 2.0, 2) if price_hourly else 0.0,
            "Potential_Saving_USD": round(potential, 2) if potential else None,
            "ApplicationID": "",
            "Application": "",
            "Environment": env,
            "ReferencedIn": "",
            "Flags": "MultiAZ, NonProd",
            "Confidence": 80,
            "Signals": {"class": cls, "env": env},
            "RunId": rid,
        }
        _emit(writer, row)
        rows.append(row)

    return rows


def check_rds_unused_read_replicas(
    writer: Any,
    region: str,
    *,
    cloudwatch: BaseClient,
    rds: BaseClient,
    lookback_days: int = 30,
    conn_threshold: float = 1.0,
    iops_threshold: float = 5.0,
    account_id: Optional[str] = None,
    run_id: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Flag read replicas with near-zero connections and IOPS → remove.

    Potential saving equals the replica class monthly cost.
    """
    rid = run_id or _now_utc().strftime("%Y%m%dT%H%M%SZ")
    owner = str(account_id or getattr(CONF, "ACCOUNT_ID", ""))
    start = _now_utc() - timedelta(days=lookback_days)
    end = _now_utc()

    instances = [i for i in _list_db_instances(rds) if i.get("ReadReplicaSourceDBInstanceIdentifier")]
    inst_ids = [i.get("DBInstanceIdentifier", "") for i in instances if i.get("DBInstanceIdentifier")]
    queries = _build_rds_metric_queries(inst_ids)
    results = _run_cw_queries(cloudwatch, queries, start, end)
    metrics = _summarize_rds_results(inst_ids, results)

    rows: List[Dict[str, Any]] = []
    for inst in instances:
        inst_id = inst.get("DBInstanceIdentifier", "")
        arn = inst.get("DBInstanceArn", inst_id)
        cls = inst.get("DBInstanceClass", "")
        status = inst.get("DBInstanceStatus", "")
        price_hourly = _hourly_price_instance(cls)

        m = metrics.get(inst_id, {"conn_max": 0.0, "riops_sum": 0.0, "wiops_sum": 0.0})
        conn = float(m.get("conn_max", 0.0))
        iops = float(m.get("riops_sum", 0.0)) + float(m.get("wiops_sum", 0.0))

        is_idle = conn < conn_threshold and iops < iops_threshold
        potential = 730.0 * price_hourly if (is_idle and price_hourly > 0.0) else 0.0

        flags = ["ReadReplica"]
        if is_idle:
            flags.append("Idle")

        row: Dict[str, Any] = {
            "Resource_ID": arn,
            "Name": inst_id,
            "ResourceType": "RDSInstance",
            "OwnerId": owner,
            "Region": region,
            "State": status,
            "Creation_Date": "",
            "Storage_GB": inst.get("AllocatedStorage", 0),
            "Object_Count": "",
            "Estimated_Cost_USD": round(price_hourly * 730.0, 2),
            "Potential_Saving_USD": round(potential, 2) if potential > 0.0 else None,
            "ApplicationID": "",
            "Application": "",
            "Environment": _env_from_tags(_list_tags(rds, arn)),
            "ReferencedIn": "",
            "Flags": ", ".join(flags),
            "Confidence": 85 if is_idle else 60,
            "Signals": {"conn_max": round(conn, 1), "iops_sum": round(iops, 1), "class": cls},
            "RunId": rid,
        }
        _emit(writer, row)
        rows.append(row)

    return rows


def check_rds_iops_overprovisioned(
    writer: Any,
    region: str,
    *,
    cloudwatch: BaseClient,
    rds: BaseClient,
    lookback_days: int = 30,
    headroom_pct: float = 50.0,
    account_id: Optional[str] = None,
    run_id: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Flag instances with provisioned IOPS ≫ observed IOPS → reduce IOPS.

    Savings ≈ (ProvisionedIOPS − RecommendedIOPS) × price_per_IOPS_month.
    The recommended IOPS is `p95_observed × (1 + headroom_pct/100)`.
    """
    rid = run_id or _now_utc().strftime("%Y%m%dT%H%M%SZ")
    owner = str(account_id or getattr(CONF, "ACCOUNT_ID", ""))
    start = _now_utc() - timedelta(days=lookback_days)
    end = _now_utc()

    instances = _list_db_instances(rds)
    # Only storage types with provisioned IOPS
    instances = [i for i in instances if str(i.get("StorageType", "")).lower() in {"io1", "io2", "gp3"}]

    inst_ids = [i.get("DBInstanceIdentifier", "") for i in instances if i.get("DBInstanceIdentifier")]
    queries = _build_rds_metric_queries(inst_ids)
    results = _run_cw_queries(cloudwatch, queries, start, end)
    metrics = _summarize_rds_results(inst_ids, results)

    price_per_iops = _iops_price_per_month()

    rows: List[Dict[str, Any]] = []
    for inst in instances:
        inst_id = inst.get("DBInstanceIdentifier", "")
        arn = inst.get("DBInstanceArn", inst_id)
        storage_type = str(inst.get("StorageType", "")).lower()
        prov_iops = int(inst.get("Iops", 0) or 0)
        status = inst.get("DBInstanceStatus", "")

        m = metrics.get(inst_id, {"riops_sum": 0.0, "wiops_sum": 0.0})
        # Convert summed per-hour counts to an approximate p95/sec proxy:
        # we conservatively divide by hours to get avg/sec and scale 1.5x for p95.
        hours = max(1.0, float(lookback_days) * 24.0)
        avg_iops = (float(m.get("riops_sum", 0.0)) + float(m.get("wiops_sum", 0.0))) / hours
        p95_iops = avg_iops * 1.5
        recommended = int(p95_iops * (1.0 + headroom_pct / 100.0))

        potential = 0.0
        if prov_iops and recommended < prov_iops:
            potential = (prov_iops - recommended) * price_per_iops

        flags: List[str] = [f"Storage={storage_type}", f"ProvIOPS={prov_iops}"]
        if potential > 0.0:
            flags.append(f"ReduceIOPS→{recommended}")

        row: Dict[str, Any] = {
            "Resource_ID": arn,
            "Name": inst_id,
            "ResourceType": "RDSInstance",
            "OwnerId": owner,
            "Region": region,
            "State": status,
            "Creation_Date": "",
            "Storage_GB": inst.get("AllocatedStorage", 0),
            "Object_Count": "",
            "Estimated_Cost_USD": "",
            "Potential_Saving_USD": round(potential, 2) if potential > 0.0 else None,
            "ApplicationID": "",
            "Application": "",
            "Environment": _env_from_tags(_list_tags(rds, arn)),
            "ReferencedIn": "",
            "Flags": ", ".join(flags),
            "Confidence": 70 if potential > 0.0 else 60,
            "Signals": {"avg_iops": round(avg_iops, 1), "p95_iops": round(p95_iops, 1)},
            "RunId": rid,
        }
        _emit(writer, row)
        rows.append(row)

    return rows


def check_rds_gp2_to_gp3_candidates(
    writer: Any,
    region: str,
    *,
    rds: BaseClient,
    account_id: Optional[str] = None,
    run_id: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Flag RDS instances on gp2 → recommend gp3 (price delta per GB-month)."""
    rid = run_id or _now_utc().strftime("%Y%m%dT%H%M%SZ")
    owner = str(account_id or getattr(CONF, "ACCOUNT_ID", ""))

    delta = _gp_price_delta_per_gb_month()
    instances = [i for i in _list_db_instances(rds) if str(i.get("StorageType", "")).lower() == "gp2"]

    rows: List[Dict[str, Any]] = []
    for inst in instances:
        inst_id = inst.get("DBInstanceIdentifier", "")
        arn = inst.get("DBInstanceArn", inst_id)
        size_gb = int(inst.get("AllocatedStorage", 0) or 0)
        potential = float(size_gb) * delta

        row: Dict[str, Any] = {
            "Resource_ID": arn,
            "Name": inst_id,
            "ResourceType": "RDSInstance",
            "OwnerId": owner,
            "Region": region,
            "State": inst.get("DBInstanceStatus", ""),
            "Creation_Date": "",
            "Storage_GB": size_gb,
            "Object_Count": "",
            "Estimated_Cost_USD": "",
            "Potential_Saving_USD": round(potential, 2) if potential > 0.0 else None,
            "ApplicationID": "",
            "Application": "",
            "Environment": _env_from_tags(_list_tags(rds, arn)),
            "ReferencedIn": "",
            "Flags": "gp2→gp3",
            "Confidence": 95 if potential > 0.0 else 80,
            "Signals": {"gb": size_gb, "delta_per_gb": delta},
            "RunId": rid,
        }
        _emit(writer, row)
        rows.append(row)

    return rows


def check_aurora_low_activity_clusters(
    writer: Any,
    region: str,
    *,
    cloudwatch: BaseClient,
    rds: BaseClient,
    lookback_days: int = 30,
    cpu_threshold_pct: float = 10.0,
    conn_threshold: float = 5.0,
    account_id: Optional[str] = None,
    run_id: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Flag Aurora clusters with low aggregate activity → downsize/pause review.

    For `EngineMode=serverless`, suggest pause when idle. Savings are not
    directly computed here (vary by ACU & burst), but we provide strong
    signals to guide action.
    """
    rid = run_id or _now_utc().strftime("%Y%m%dT%H%M%SZ")
    owner = str(account_id or getattr(CONF, "ACCOUNT_ID", ""))
    start = _now_utc() - timedelta(days=lookback_days)
    end = _now_utc()

    clusters = [c for c in _list_db_clusters(rds) if str(c.get("Engine", "")).lower().startswith("aurora")]

    # Gather all instance ids across clusters
    cluster_members: Dict[str, List[str]] = {}
    for c in clusters:
        cid = c.get("DBClusterIdentifier", "")
        members = [m.get("DBInstanceIdentifier", "") for m in c.get("DBClusterMembers", []) if m.get("DBInstanceIdentifier")]
        cluster_members[cid] = members

    all_inst_ids = sorted({i for ids in cluster_members.values() for i in ids if i})
    queries = _build_rds_metric_queries(all_inst_ids)
    results = _run_cw_queries(cloudwatch, queries, start, end)
    metrics = _summarize_rds_results(all_inst_ids, results)

    rows: List[Dict[str, Any]] = []
    for c in clusters:
        cid = c.get("DBClusterIdentifier", "")
        arn = c.get("DBClusterArn", cid)
        engine_mode = str(c.get("EngineMode", "") or "provisioned").lower()
        state = c.get("Status", "")
        inst_ids = cluster_members.get(cid, [])

        # Aggregate per-cluster
        cpu_vals = [metrics.get(i, {}).get("cpu_avg", 0.0) for i in inst_ids]
        conn_vals = [metrics.get(i, {}).get("conn_max", 0.0) for i in inst_ids]
        avg_cpu = (sum(cpu_vals) / len(cpu_vals)) if cpu_vals else 0.0
        max_conn = max(conn_vals) if conn_vals else 0.0

        low = avg_cpu < cpu_threshold_pct and max_conn < conn_threshold

        flags: List[str] = []
        if low:
            flags.append("LowActivity")
        if engine_mode == "serverless":
            flags.append("Serverless")

        row: Dict[str, Any] = {
            "Resource_ID": arn,
            "Name": cid,
            "ResourceType": "AuroraCluster",
            "OwnerId": owner,
            "Region": region,
            "State": state,
            "Creation_Date": "",
            "Storage_GB": "",
            "Object_Count": "",
            "Estimated_Cost_USD": "",
            "Potential_Saving_USD": None,
            "ApplicationID": "",
            "Application": "",
            "Environment": _env_from_tags(_list_tags(rds, arn)),
            "ReferencedIn": "",
            "Flags": ", ".join(flags),
            "Confidence": 70 if low else 50,
            "Signals": {
                "engine_mode": engine_mode,
                "avg_cpu_pct": round(avg_cpu, 1),
                "max_conn": round(max_conn, 1),
                "members": len(inst_ids),
            },
            "RunId": rid,
        }
        _emit(writer, row)
        rows.append(row)

    return rows


# Engine version support ------------------------------------------------------

def _needs_engine_upgrade(engine: str, version: str) -> Tuple[bool, str]:
    """Return (needs_upgrade, target_hint) based on simple EoS heuristics.

    This is a conservative, static heuristic to avoid web calls:
    - MySQL: 5.6/5.7 considered legacy → suggest 8.0
    - PostgreSQL: 9.x/10.x/11.x considered legacy → suggest 14
    - Aurora MySQL: same as MySQL
    - Aurora PostgreSQL: same as PostgreSQL
    """
    e = engine.lower()
    v = version.strip().lower()
    if "mysql" in e:
        if v.startswith("5.6") or v.startswith("5.7"):
            return True, "8.0"
    if "postgres" in e:
        if v.startswith("9.") or v.startswith("10.") or v.startswith("11."):
            return True, "14"
    return False, ""


def check_rds_engine_extended_support(
    writer: Any,
    region: str,
    *,
    rds: BaseClient,
    account_id: Optional[str] = None,
    run_id: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Flag RDS/Aurora engines on legacy/extended support versions → upgrade.

    This supersedes the old `extended_support.py` checker.
    """
    rid = run_id or _now_utc().strftime("%Y%m%dT%H%M%SZ")
    owner = str(account_id or getattr(CONF, "ACCOUNT_ID", ""))

    rows: List[Dict[str, Any]] = []

    # Instances
    for inst in _list_db_instances(rds):
        inst_id = inst.get("DBInstanceIdentifier", "")
        arn = inst.get("DBInstanceArn", inst_id)
        engine = inst.get("Engine", "")
        version = inst.get("EngineVersion", "")
        need, target = _needs_engine_upgrade(engine, version)
        if not need:
            continue
        row: Dict[str, Any] = {
            "Resource_ID": arn,
            "Name": inst_id,
            "ResourceType": "RDSInstance",
            "OwnerId": owner,
            "Region": region,
            "State": inst.get("DBInstanceStatus", ""),
            "Creation_Date": "",
            "Storage_GB": inst.get("AllocatedStorage", 0),
            "Object_Count": "",
            "Estimated_Cost_USD": "",
            "Potential_Saving_USD": None,
            "ApplicationID": "",
            "Application": "",
            "Environment": _env_from_tags(_list_tags(rds, arn)),
            "ReferencedIn": "",
            "Flags": "LegacyEngineVersion",
            "Confidence": 90,
            "Signals": {"engine": engine, "engine_version": version, "target": target},
            "RunId": rid,
        }
        _emit(writer, row)
        rows.append(row)

    # Clusters (Aurora)
    for c in _list_db_clusters(rds):
        cid = c.get("DBClusterIdentifier", "")
        arn = c.get("DBClusterArn", cid)
        engine = c.get("Engine", "")
        version = c.get("EngineVersion", "")
        need, target = _needs_engine_upgrade(engine, version)
        if not need:
            continue
        row = {
            "Resource_ID": arn,
            "Name": cid,
            "ResourceType": "AuroraCluster",
            "OwnerId": owner,
            "Region": region,
            "State": c.get("Status", ""),
            "Creation_Date": "",
            "Storage_GB": "",
            "Object_Count": "",
            "Estimated_Cost_USD": "",
            "Potential_Saving_USD": None,
            "ApplicationID": "",
            "Application": "",
            "Environment": _env_from_tags(_list_tags(rds, arn)),
            "ReferencedIn": "",
            "Flags": "LegacyEngineVersion",
            "Confidence": 90,
            "Signals": {"engine": engine, "engine_version": version, "target": target},
            "RunId": rid,
        }
        _emit(writer, row)
        rows.append(row)

    return rows
