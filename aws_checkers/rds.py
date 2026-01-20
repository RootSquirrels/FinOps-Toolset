"""Checkers: RDS & Aurora."""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

from botocore.client import BaseClient
from botocore.exceptions import ClientError

from core.cloudwatch import CloudWatchBatcher  # noqa: E402
from core.retry import retry_with_backoff

from aws_checkers import config
from finops_toolset import config as const


# ---------------------------------------------------------------------------
# Logger & call normalization
# ---------------------------------------------------------------------------

def _logger(fallback: Optional[logging.Logger]) -> logging.Logger:
    """Return a usable logger from fallback or config.LOGGER."""
    return fallback or config.LOGGER or logging.getLogger(__name__)


def _split_region_from_args(
    args: Tuple[Any, ...],
    kwargs: Dict[str, Any],
) -> Tuple[Optional[str], Tuple[Any, ...]]:
    """Normalize region+args for both call styles.

    Returns (region, remaining_args).

    Accepted patterns:
      - Orchestrator: fn(writer, **kwargs) -> region in kwargs (optional) or inferred.
      - Legacy: fn(region, writer, ...) -> first arg is region str.
    """
    region = kwargs.get("region")
    if region:
        return str(region), args

    if args and isinstance(args[0], str) and len(args) >= 2:
        # Legacy: (region, writer, ...)
        return str(args[0]), args[1:]

    return None, args


def _infer_region_from_clients(cloudwatch: Optional[BaseClient], rds: Optional[BaseClient]) -> str:
    """Infer region from cloudwatch/rds client; fallback to 'GLOBAL'."""
    for client in (cloudwatch, rds):
        if client is None:
            continue
        region = getattr(getattr(client, "meta", None), "region_name", None)
        if region:
            return str(region)
    return "GLOBAL"


# ---------------------------------------------------------------------------
# Extractors (orchestrator-compatible)
# ---------------------------------------------------------------------------

def _extract_writer_rds(
    args: Tuple[Any, ...],
    kwargs: Dict[str, Any],
) -> Tuple[Any, BaseClient]:
    """Extract (writer, rds) from args/kwargs; raise on missing.

    Orchestrator style:
      writer is positional args[0]
      rds client is passed as kwargs['client']
    Legacy style:
      (writer, rds) may be passed positionally.
    """
    writer = kwargs.get("writer", args[0] if len(args) >= 1 else None)

    # Accept 'client' (orchestrator), or legacy 'rds', or positional
    rds = kwargs.get("client", kwargs.get("rds", args[1] if len(args) >= 2 else None))
    if writer is None or rds is None:
        raise TypeError("Expected 'writer' and RDS client as 'client' (or legacy 'rds')")
    return writer, rds


def _extract_writer_cw_rds(
    args: Tuple[Any, ...],
    kwargs: Dict[str, Any],
) -> Tuple[Any, BaseClient, BaseClient]:
    """Extract (writer, cloudwatch, rds) from args/kwargs; raise on missing.

    Orchestrator style:
      writer is positional args[0]
      cloudwatch is kwargs['cloudwatch']
      rds is kwargs['client']
    Legacy style:
      (writer, cloudwatch, rds) may be passed positionally.
    """
    writer = kwargs.get("writer", args[0] if len(args) >= 1 else None)
    cloudwatch = kwargs.get("cloudwatch", kwargs.get("cw", args[1] if len(args) >= 2 else None))
    rds = kwargs.get("client", kwargs.get("rds", args[2] if len(args) >= 3 else None))

    if writer is None or cloudwatch is None or rds is None:
        raise TypeError("Expected 'writer', 'cloudwatch' and RDS client as 'client' (or 'rds')")
    return writer, cloudwatch, rds


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _safe_price(service: str, key: str, default: float = 0.0) -> float:
    """Resolve a price via config.safe_price(service, key, default)."""
    try:
        return float(config.safe_price(service, key, default))  # type: ignore[arg-type]
    except Exception:  # pylint: disable=broad-except
        return float(default)


def _iso(dt: Optional[datetime]) -> str:
    """UTC ISO-8601 string or empty string."""
    if not dt:
        return ""
    if not dt.tzinfo:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).isoformat()


def _hourly_price_instance(instance_class: str) -> float:
    """Resolve hourly price for an RDS instance class via pricing keys."""
    ic = instance_class.strip()
    candidates = [
        f"INSTANCE_HOURLY.{ic}",
        f"INSTANCE_HOURLY.{ic.replace('db.', '')}",
    ]
    for key in candidates:
        p = _safe_price("RDS", key, 0.0)
        if p > 0.0:
            return p
    return 0.0


def _gp_price_delta_per_gb_month() -> float:
    """Return gp2→gp3 price delta per GB-month (>= 0.0)."""
    p_gp2 = _safe_price("RDS", "GP2_GB_MONTH", 0.10)
    p_gp3 = _safe_price("RDS", "GP3_GB_MONTH", 0.08)
    return max(0.0, p_gp2 - p_gp3)


def _iops_price_per_month() -> float:
    """Return provisioned IOPS monthly price per IOPS (io1/io2)."""
    return _safe_price("RDS", "IOPS_PROV_MONTH", 0.10)


def _paginate(fetch_fn, *, page_key: str, next_key: str = "Marker", **kwargs: Any):
    """Generic paginator using Marker/NextToken semantics."""
    token: Optional[str] = None
    while True:
        params = dict(kwargs)
        if token:
            params[next_key] = token
        page = fetch_fn(**params)
        for item in page.get(page_key, []) or []:
            yield item
        token = page.get(next_key) or page.get("NextToken")
        if not token:
            break


def _list_db_instances(rds: BaseClient) -> List[Mapping[str, Any]]:
    """Return all DB instances in the region."""
    return list(_paginate(rds.describe_db_instances, page_key="DBInstances", next_key="Marker"))


def _list_db_clusters(rds: BaseClient) -> List[Mapping[str, Any]]:
    """Return all DB clusters (Aurora) in the region."""
    return list(_paginate(rds.describe_db_clusters, page_key="DBClusters", next_key="Marker"))


def _build_rds_metric_queries(inst_ids: Sequence[str]) -> List[Dict[str, Any]]:
    """Build query specs for CPU/Conn/IOPS; no Unit fields (Moto-safe)."""
    queries: List[Dict[str, Any]] = []
    for idx, name in enumerate(inst_ids):
        dims = [{"Name": "DBInstanceIdentifier", "Value": name}]
        spec = (
            ("CPUUtilization", "Average", "cpu"),
            ("DatabaseConnections", "Maximum", "conn"),
            ("ReadIOPS", "Average", "riops"),
            ("WriteIOPS", "Average", "wiops"),
        )
        for metric, stat, qid in spec:
            queries.append(
                {
                    "Id": f"{qid}_{idx}",
                    "Namespace": "AWS/RDS",
                    "Metric": metric,
                    "Dims": dims,
                    "Stat": stat,
                    "Period": 3600,
                }
            )
    return queries


def _run_cw_queries(
    region: str,
    cloudwatch: BaseClient,
    queries: Sequence[Dict[str, Any]],
    start: datetime,
    end: datetime,
) -> Dict[str, List[Tuple[datetime, float]]]:
    """Run queries via CloudWatchBatcher.add_q/execute (repo API)."""
    batcher = CloudWatchBatcher(region, client=cloudwatch)
    for q in queries:
        batcher.add_q(
            id_hint=q.get("Id", ""),
            namespace=q.get("Namespace", "AWS/RDS"),
            metric=q.get("Metric", ""),
            dims=q.get("Dims", []) or [],
            stat=q.get("Stat", "Average"),
            period=int(q.get("Period", 3600) or 3600),
        )
    return batcher.execute(start, end)


def _summarize_rds_series(
    inst_ids: Sequence[str],
    series_by_id: Mapping[str, List[Tuple[datetime, float]]],
) -> Dict[str, Dict[str, float]]:
    """Summarize CPU avg, Conn max, IOPS avg per instance from series dict."""
    out: Dict[str, Dict[str, float]] = {
        i: {"cpu_avg": 0.0, "conn_max": 0.0, "riops_avg": 0.0, "wiops_avg": 0.0}
        for i in inst_ids
    }
    for rid, series in series_by_id.items():
        vals = [float(v) for _, v in series]
        if not vals:
            continue
        try:
            idx = int(str(rid).split("_")[-1])
        except (ValueError, IndexError):
            continue
        if idx < 0 or idx >= len(inst_ids):
            continue
        name = inst_ids[idx]
        if rid.startswith("cpu_"):
            out[name]["cpu_avg"] = sum(vals) / float(len(vals))
        elif rid.startswith("conn_"):
            out[name]["conn_max"] = max(vals)
        elif rid.startswith("riops_"):
            out[name]["riops_avg"] = sum(vals) / float(len(vals))
        elif rid.startswith("wiops_"):
            out[name]["wiops_avg"] = sum(vals) / float(len(vals))
    return out


def _step_down_instance_class(inst: str) -> str:
    """Return the next smaller class within the same family (best-effort)."""
    sizes = [
        "nano", "micro", "small", "medium", "large", "xlarge",
        "2xlarge", "4xlarge", "8xlarge", "12xlarge", "16xlarge",
        "24xlarge", "32xlarge", "48xlarge", "56xlarge", "metal",
    ]
    parts = inst.split(".")
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


# ---------------------------------------------------------------------------
# Checkers
# ---------------------------------------------------------------------------

@retry_with_backoff(exceptions=(ClientError,))
def check_rds_underutilized_instances(  # noqa: D401
    *args: Any,
    logger: Optional[logging.Logger] = None,
    lookback_days: int = 30,
    cpu_threshold_pct: float = 20.0,
    conn_threshold: float = 5.0,
    account_id: Optional[str] = None,
    **kwargs: Any,
) -> List[Dict[str, Any]]:
    """Flag RDS instances with low CPU + connections → rightsizing candidate."""
    log = _logger(kwargs.get("logger") or logger)

    region, norm_args = _split_region_from_args(args, kwargs)
    try:
        writer, cloudwatch, rds = _extract_writer_cw_rds(norm_args, kwargs)
    except TypeError as exc:
        log.warning("[check_rds_underutilized_instances] Skipping: %s", exc)
        return []

    if not region:
        region = _infer_region_from_clients(cloudwatch, rds)

    start = datetime.now(timezone.utc) - timedelta(days=lookback_days)
    end = datetime.now(timezone.utc)
    owner = str(account_id or config.ACCOUNT_ID or "")

    instances = _list_db_instances(rds)
    inst_ids = [
        i.get("DBInstanceIdentifier", "")
        for i in instances
        if i.get("DBInstanceIdentifier")
    ]
    if not inst_ids:
        return []

    series = _run_cw_queries(region, cloudwatch, _build_rds_metric_queries(inst_ids), start, end)
    metrics = _summarize_rds_series(inst_ids, series)

    rows: List[Dict[str, Any]] = []
    for inst in instances:
        inst_id = inst.get("DBInstanceIdentifier", "")
        arn = inst.get("DBInstanceArn", inst_id)
        cls = inst.get("DBInstanceClass", "")
        status = inst.get("DBInstanceStatus", "")
        created = inst.get("InstanceCreateTime")
        created_iso = _iso(created if isinstance(created, datetime) else None)

        m = metrics.get(inst_id, {"cpu_avg": 0.0, "conn_max": 0.0})
        cpu = float(m.get("cpu_avg", 0.0))
        conn = float(m.get("conn_max", 0.0))

        smaller = _step_down_instance_class(cls)
        price_now = _hourly_price_instance(cls)
        price_small = _hourly_price_instance(smaller)
        delta_hr = max(0.0, price_now - price_small) if smaller != cls else 0.0
        potential = (
            const.HOURS_PER_MONTH * delta_hr
            if (cpu < cpu_threshold_pct and conn < conn_threshold)
            else 0.0
        )

        flags: List[str] = []
        if cpu < cpu_threshold_pct:
            flags.append(f"CPU<{cpu_threshold_pct}%")
        if conn < conn_threshold:
            flags.append(f"Conn<{int(conn_threshold)}")
        if potential > 0.0:
            flags.append("RightsizeOneStep")

        try:
            # type: ignore[call-arg]
            config.WRITE_ROW(
                writer=writer,
                resource_id=arn,
                name=inst_id,
                owner_id=owner,  # type: ignore[arg-type]
                resource_type="RDSInstance",
                region=region,
                state=status,
                creation_date=created_iso,
                storage_gb=inst.get("AllocatedStorage", 0),
                estimated_cost=round(price_now * const.HOURS_PER_MONTH, 2) if price_now else 0.0,
                potential_saving=round(potential, 2) if potential > 0.0 else None,
                flags=flags,
                confidence=75 if potential > 0.0 else 60,
                signals=(
                    f"class={cls}|suggested={smaller if smaller != cls else ''}|"
                    f"cpu_avg={round(cpu,1)}|conn_max={round(conn,1)}"
                ),
            )
        except Exception as exc:  # pylint: disable=broad-except
            log.warning("[rds] write_row(rightsize) failed: %s", exc)
        rows.append({"id": inst_id, "potential": potential})

    return rows


@retry_with_backoff(exceptions=(ClientError,))
def check_rds_multi_az_non_prod(  # noqa: D401
    *args: Any,
    logger: Optional[logging.Logger] = None,
    account_id: Optional[str] = None,
    **kwargs: Any,
) -> List[Dict[str, Any]]:
    """Flag Multi-AZ instances (approx saving = one instance cost per month)."""
    log = _logger(kwargs.get("logger") or logger)

    region, norm_args = _split_region_from_args(args, kwargs)
    try:
        writer, rds = _extract_writer_rds(norm_args, kwargs)
    except TypeError as exc:
        log.warning("[check_rds_multi_az_non_prod] Skipping: %s", exc)
        return []

    if not region:
        region = _infer_region_from_clients(None, rds)

    owner = str(account_id or config.ACCOUNT_ID or "")
    instances = _list_db_instances(rds)
    rows: List[Dict[str, Any]] = []

    for inst in instances:
        if not inst.get("MultiAZ"):
            continue
        inst_id = inst.get("DBInstanceIdentifier", "")
        arn = inst.get("DBInstanceArn", inst_id)
        cls = inst.get("DBInstanceClass", "")
        price_hourly = _hourly_price_instance(cls)
        potential = const.HOURS_PER_MONTH * price_hourly if price_hourly > 0.0 else 0.0

        try:
            # type: ignore[call-arg]
            config.WRITE_ROW(
                writer=writer,
                resource_id=arn,
                name=inst_id,
                owner_id=owner,  # type: ignore[arg-type]
                resource_type="RDSInstance",
                region=region,
                state=inst.get("DBInstanceStatus", ""),
                creation_date=_iso(inst.get("InstanceCreateTime")),
                storage_gb=inst.get("AllocatedStorage", 0),
                estimated_cost=(
                    round(price_hourly * const.HOURS_PER_MONTH * 2.0, 2) if price_hourly else 0.0
                ),
                potential_saving=round(potential, 2) if potential else None,
                flags=["MultiAZ", "NonProd"],
                confidence=80,
                signals=f"class={cls}",
            )
        except Exception as exc:  # pylint: disable=broad-except
            log.warning("[rds] write_row(multiaz) failed: %s", exc)
        rows.append({"id": inst_id, "potential": potential})

    return rows


@retry_with_backoff(exceptions=(ClientError,))
def check_rds_unused_read_replicas(  # noqa: D401
    *args: Any,
    logger: Optional[logging.Logger] = None,
    lookback_days: int = 30,
    conn_threshold: float = 1.0,
    iops_threshold: float = 5.0,
    account_id: Optional[str] = None,
    **kwargs: Any,
) -> List[Dict[str, Any]]:
    """Flag read replicas with near-zero connections/IOPS → remove."""
    log = _logger(kwargs.get("logger") or logger)

    region, norm_args = _split_region_from_args(args, kwargs)
    try:
        writer, cloudwatch, rds = _extract_writer_cw_rds(norm_args, kwargs)
    except TypeError as exc:
        log.warning("[check_rds_unused_read_replicas] Skipping: %s", exc)
        return []

    if not region:
        region = _infer_region_from_clients(cloudwatch, rds)

    owner = str(account_id or config.ACCOUNT_ID or "")
    start = datetime.now(timezone.utc) - timedelta(days=lookback_days)
    end = datetime.now(timezone.utc)

    instances = [
        i for i in _list_db_instances(rds)
        if i.get("ReadReplicaSourceDBInstanceIdentifier")
    ]
    inst_ids = [
        i.get("DBInstanceIdentifier", "")
        for i in instances
        if i.get("DBInstanceIdentifier")
    ]
    if not inst_ids:
        return []

    series = _run_cw_queries(region, cloudwatch, _build_rds_metric_queries(inst_ids), start, end)
    metrics = _summarize_rds_series(inst_ids, series)

    rows: List[Dict[str, Any]] = []
    for inst in instances:
        inst_id = inst.get("DBInstanceIdentifier", "")
        arn = inst.get("DBInstanceArn", inst_id)
        cls = inst.get("DBInstanceClass", "")
        price_hourly = _hourly_price_instance(cls)

        m = metrics.get(inst_id, {"conn_max": 0.0, "riops_avg": 0.0, "wiops_avg": 0.0})
        conn = float(m.get("conn_max", 0.0))
        iops = float(m.get("riops_avg", 0.0)) + float(m.get("wiops_avg", 0.0))

        is_idle = conn < conn_threshold and iops < iops_threshold
        potential = const.HOURS_PER_MONTH * price_hourly if (is_idle and price_hourly > 0.0) else 0.0

        flags = ["ReadReplica"]
        if is_idle:
            flags.append("Idle")

        try:
            # type: ignore[call-arg]
            config.WRITE_ROW(
                writer=writer,
                resource_id=arn,
                name=inst_id,
                owner_id=owner,  # type: ignore[arg-type]
                resource_type="RDSInstance",
                region=region,
                state=inst.get("DBInstanceStatus", ""),
                creation_date=_iso(inst.get("InstanceCreateTime")),
                storage_gb=inst.get("AllocatedStorage", 0),
                estimated_cost=round(price_hourly * const.HOURS_PER_MONTH, 2) if price_hourly else 0.0,
                potential_saving=round(potential, 2) if potential > 0.0 else None,
                flags=flags,
                confidence=85 if is_idle else 60,
                signals=f"conn_max={round(conn,1)}|iops_avg={round(iops,1)}|class={cls}",
            )
        except Exception as exc:  # pylint: disable=broad-except
            log.warning("[rds] write_row(rr idle) failed: %s", exc)
        rows.append({"id": inst_id, "potential": potential})

    return rows


@retry_with_backoff(exceptions=(ClientError,))
def check_rds_iops_overprovisioned(  # noqa: D401
    *args: Any,
    logger: Optional[logging.Logger] = None,
    lookback_days: int = 30,
    headroom_pct: float = 50.0,
    account_id: Optional[str] = None,
    **kwargs: Any,
) -> List[Dict[str, Any]]:
    """Flag instances with provisioned IOPS >> observed IOPS → reduce IOPS."""
    log = _logger(kwargs.get("logger") or logger)

    region, norm_args = _split_region_from_args(args, kwargs)
    try:
        writer, cloudwatch, rds = _extract_writer_cw_rds(norm_args, kwargs)
    except TypeError as exc:
        log.warning("[check_rds_iops_overprovisioned] Skipping: %s", exc)
        return []

    if not region:
        region = _infer_region_from_clients(cloudwatch, rds)

    owner = str(account_id or config.ACCOUNT_ID or "")
    start = datetime.now(timezone.utc) - timedelta(days=lookback_days)
    end = datetime.now(timezone.utc)

    instances = _list_db_instances(rds)
    instances = [
        i for i in instances
        if str(i.get("StorageType", "")).lower() in {"io1", "io2", "gp3"}
    ]
    inst_ids = [
        i.get("DBInstanceIdentifier", "")
        for i in instances
        if i.get("DBInstanceIdentifier")
    ]
    if not inst_ids:
        return []

    series = _run_cw_queries(region, cloudwatch, _build_rds_metric_queries(inst_ids), start, end)
    metrics = _summarize_rds_series(inst_ids, series)

    price_per_iops = _iops_price_per_month()
    rows: List[Dict[str, Any]] = []

    for inst in instances:
        inst_id = inst.get("DBInstanceIdentifier", "")
        arn = inst.get("DBInstanceArn", inst_id)
        storage_type = str(inst.get("StorageType", "")).lower()
        prov_iops = int(inst.get("Iops", 0) or 0)
        status = inst.get("DBInstanceStatus", "")

        m = metrics.get(inst_id, {"riops_avg": 0.0, "wiops_avg": 0.0})
        avg_iops = float(m.get("riops_avg", 0.0)) + float(m.get("wiops_avg", 0.0))
        p95_iops = avg_iops * 1.5
        recommended = int(p95_iops * (1.0 + headroom_pct / 100.0))

        potential = 0.0
        if prov_iops and recommended < prov_iops:
            potential = float(prov_iops - recommended) * price_per_iops

        flags: List[str] = [f"Storage={storage_type}", f"ProvIOPS={prov_iops}"]
        if potential > 0.0:
            flags.append(f"ReduceIOPS→{recommended}")

        try:
            # type: ignore[call-arg]
            config.WRITE_ROW(
                writer=writer,
                resource_id=arn,
                name=inst_id,
                owner_id=owner,  # type: ignore[arg-type]
                resource_type="RDSInstance",
                region=region,
                state=status,
                creation_date=_iso(inst.get("InstanceCreateTime")),
                storage_gb=inst.get("AllocatedStorage", 0),
                estimated_cost="",
                potential_saving=round(potential, 2) if potential > 0.0 else None,
                flags=flags,
                confidence=70 if potential > 0.0 else 60,
                signals=f"avg_iops={round(avg_iops,1)}|p95_iops={round(p95_iops,1)}",
            )
        except Exception as exc:  # pylint: disable=broad-except
            log.warning("[rds] write_row(iops) failed: %s", exc)
        rows.append({"id": inst_id, "potential": potential})

    return rows


@retry_with_backoff(exceptions=(ClientError,))
def check_rds_gp2_to_gp3_candidates(  # noqa: D401
    *args: Any,
    logger: Optional[logging.Logger] = None,
    account_id: Optional[str] = None,
    **kwargs: Any,
) -> List[Dict[str, Any]]:
    """Flag RDS instances using gp2 → recommend gp3 (delta per GB-month)."""
    log = _logger(kwargs.get("logger") or logger)

    region, norm_args = _split_region_from_args(args, kwargs)
    try:
        writer, rds = _extract_writer_rds(norm_args, kwargs)
    except TypeError as exc:
        log.warning("[check_rds_gp2_to_gp3_candidates] Skipping: %s", exc)
        return []

    if not region:
        region = _infer_region_from_clients(None, rds)

    owner = str(account_id or config.ACCOUNT_ID or "")
    delta = _gp_price_delta_per_gb_month()
    instances = [
        i for i in _list_db_instances(rds)
        if str(i.get("StorageType", "")).lower() == "gp2"
    ]
    rows: List[Dict[str, Any]] = []

    for inst in instances:
        inst_id = inst.get("DBInstanceIdentifier", "")
        arn = inst.get("DBInstanceArn", inst_id)
        size_gb = int(inst.get("AllocatedStorage", 0) or 0)
        potential = float(size_gb) * delta

        try:
            # type: ignore[call-arg]
            config.WRITE_ROW(
                writer=writer,
                resource_id=arn,
                name=inst_id,
                owner_id=owner,  # type: ignore[arg-type]
                resource_type="RDSInstance",
                region=region,
                state=inst.get("DBInstanceStatus", ""),
                creation_date=_iso(inst.get("InstanceCreateTime")),
                storage_gb=size_gb,
                estimated_cost="",
                potential_saving=round(potential, 2) if potential > 0.0 else None,
                flags=["gp2→gp3"],
                confidence=95 if potential > 0.0 else 80,
                signals=f"gb={size_gb}|delta_per_gb={delta}",
            )
        except Exception as exc:  # pylint: disable=broad-except
            log.warning("[rds] write_row(gp2→gp3) failed: %s", exc)
        rows.append({"id": inst_id, "potential": potential})

    return rows


@retry_with_backoff(exceptions=(ClientError,))
def check_aurora_low_activity_clusters(  # noqa: D401
    *args: Any,
    logger: Optional[logging.Logger] = None,
    lookback_days: int = 30,
    cpu_threshold_pct: float = 10.0,
    conn_threshold: float = 5.0,
    account_id: Optional[str] = None,
    **kwargs: Any,
) -> List[Dict[str, Any]]:
    """Flag Aurora clusters with low activity → downsize/pause review."""
    log = _logger(kwargs.get("logger") or logger)

    region, norm_args = _split_region_from_args(args, kwargs)
    try:
        writer, cloudwatch, rds = _extract_writer_cw_rds(norm_args, kwargs)
    except TypeError as exc:
        log.warning("[check_aurora_low_activity_clusters] Skipping: %s", exc)
        return []

    if not region:
        region = _infer_region_from_clients(cloudwatch, rds)

    owner = str(account_id or config.ACCOUNT_ID or "")
    start = datetime.now(timezone.utc) - timedelta(days=lookback_days)
    end = datetime.now(timezone.utc)

    clusters = [
        c for c in _list_db_clusters(rds)
        if str(c.get("Engine", "")).lower().startswith("aurora")
    ]

    cluster_members: Dict[str, List[str]] = {}
    for c in clusters:
        cid = c.get("DBClusterIdentifier", "")
        members = [
            m.get("DBInstanceIdentifier", "")
            for m in c.get("DBClusterMembers", []) or []
            if m.get("DBInstanceIdentifier")
        ]
        cluster_members[cid] = members

    all_inst_ids = sorted({i for ids in cluster_members.values() for i in ids if i})
    series = _run_cw_queries(region, cloudwatch, _build_rds_metric_queries(all_inst_ids), start, end)
    metrics = _summarize_rds_series(all_inst_ids, series)

    rows: List[Dict[str, Any]] = []
    for c in clusters:
        cid = c.get("DBClusterIdentifier", "")
        arn = c.get("DBClusterArn", cid)
        engine_mode = str(c.get("EngineMode", "") or "provisioned").lower()
        state = c.get("Status", "")
        inst_ids = cluster_members.get(cid, [])

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

        try:
            # type: ignore[call-arg]
            config.WRITE_ROW(
                writer=writer,
                resource_id=arn,
                name=cid,
                owner_id=owner,  # type: ignore[arg-type]
                resource_type="AuroraCluster",
                region=region,
                state=state,
                creation_date=_iso(c.get("EarliestRestorableTime")),
                estimated_cost="",
                potential_saving=None,
                flags=flags,
                confidence=70 if low else 50,
                signals=(
                    f"engine_mode={engine_mode}|avg_cpu={round(avg_cpu,1)}|"
                    f"max_conn={round(max_conn,1)}|members={len(inst_ids)}"
                ),
            )
        except Exception as exc:  # pylint: disable=broad-except
            log.warning("[aurora] write_row(low activity) failed: %s", exc)
        rows.append({"id": cid, "low": low})

    return rows


# ---------------------------------------------------------------------------
# Engine version support (supersedes extended_support.py)
# ---------------------------------------------------------------------------

def _needs_engine_upgrade(engine: str, version: str) -> Tuple[bool, str]:
    """Return (needs_upgrade, target_hint) via conservative static heuristics."""
    e = engine.lower()
    v = version.strip().lower()
    if "mysql" in e:
        if v.startswith("5.6") or v.startswith("5.7"):
            return True, "8.0"
    if "postgres" in e:
        if v.startswith("9.") or v.startswith("10.") or v.startswith("11."):
            return True, "14"
    return False, ""


@retry_with_backoff(exceptions=(ClientError,))
def check_rds_engine_extended_support(  # noqa: D401
    *args: Any,
    logger: Optional[logging.Logger] = None,
    account_id: Optional[str] = None,
    **kwargs: Any,
) -> List[Dict[str, Any]]:
    """Flag RDS/Aurora engines on legacy/extended support versions → upgrade."""
    log = _logger(kwargs.get("logger") or logger)

    region, norm_args = _split_region_from_args(args, kwargs)
    try:
        writer, rds = _extract_writer_rds(norm_args, kwargs)
    except TypeError as exc:
        log.warning("[check_rds_engine_extended_support] Skipping: %s", exc)
        return []

    if not region:
        region = _infer_region_from_clients(None, rds)

    owner = str(account_id or config.ACCOUNT_ID or "")

    # Instances
    for inst in _list_db_instances(rds):
        inst_id = inst.get("DBInstanceIdentifier", "")
        arn = inst.get("DBInstanceArn", inst_id)
        engine = inst.get("Engine", "")
        version = inst.get("EngineVersion", "")
        need, target = _needs_engine_upgrade(engine, version)
        if not need:
            continue
        try:
            # type: ignore[call-arg]
            config.WRITE_ROW(
                writer=writer,
                resource_id=arn,
                name=inst_id,
                owner_id=owner,  # type: ignore[arg-type]
                resource_type="RDSInstance",
                region=region,
                state=inst.get("DBInstanceStatus", ""),
                creation_date=_iso(inst.get("InstanceCreateTime")),
                storage_gb=inst.get("AllocatedStorage", 0),
                estimated_cost="",
                potential_saving=None,
                flags=["LegacyEngineVersion"],
                confidence=90,
                signals=f"engine={engine}|version={version}|target={target}",
            )
        except Exception as exc:  # pylint: disable=broad-except
            log.warning("[rds] write_row(engine support) failed: %s", exc)

    # Clusters (Aurora)
    for cl in _list_db_clusters(rds):
        cid = cl.get("DBClusterIdentifier", "")
        arn = cl.get("DBClusterArn", cid)
        engine = cl.get("Engine", "")
        version = cl.get("EngineVersion", "")
        need, target = _needs_engine_upgrade(engine, version)
        if not need:
            continue
        try:
            # type: ignore[call-arg]
            config.WRITE_ROW(
                writer=writer,
                resource_id=arn,
                name=cid,
                owner_id=owner,  # type: ignore[arg-type]
                resource_type="AuroraCluster",
                region=region,
                state=cl.get("Status", ""),
                creation_date=_iso(cl.get("EarliestRestorableTime")),
                estimated_cost="",
                potential_saving=None,
                flags=["LegacyEngineVersion"],
                confidence=90,
                signals=f"engine={engine}|version={version}|target={target}",
            )
        except Exception as exc:  # pylint: disable=broad-except
            log.warning("[aurora] write_row(engine support) failed: %s", exc)
