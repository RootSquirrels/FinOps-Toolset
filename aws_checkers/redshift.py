"""Checkers: Amazon Redshift (idle clusters, stale snapshots)."""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from botocore.client import BaseClient
from botocore.exceptions import ClientError

from aws_checkers.common import _logger, _signals_str, _to_utc_iso
from aws_checkers import config as chk
from finops_toolset import config as const
from core.retry import retry_with_backoff
from core.cloudwatch import CloudWatchBatcher


# ---------------------------------------------------------------------------
# Call normalization
# ---------------------------------------------------------------------------

def _split_region_from_args(
    args: Tuple[Any, ...],
    kwargs: Dict[str, Any],
) -> Tuple[Optional[str], Tuple[Any, ...]]:
    """Normalize region + remaining args for orchestrator and legacy calls.

    Returns (region, remaining_args).

    Accepted patterns:
      - Orchestrator: fn(writer, **kwargs) -> region in kwargs (optional)
      - Legacy: fn(region, writer, ...) -> first arg is region str
    """
    region = kwargs.get("region")
    if region:
        return str(region), args

    if args and isinstance(args[0], str) and len(args) >= 2:
        return str(args[0]), args[1:]

    return None, args


def _infer_region_from_clients(
    cloudwatch: Optional[BaseClient],
    redshift: Optional[BaseClient],
) -> str:
    """Infer region from cloudwatch/redshift meta; fallback to 'GLOBAL'."""
    for client in (cloudwatch, redshift):
        if client is None:
            continue
        r = getattr(getattr(client, "meta", None), "region_name", None)
        if r:
            return str(r)
    return "GLOBAL"


# ---------------------------------------------------------------------------
# Extractors
# ---------------------------------------------------------------------------

def _extract_writer_client(
    args: Tuple[Any, ...], kwargs: Dict[str, Any]
) -> Tuple[Any, BaseClient]:
    """Extract (writer, redshift client) from args/kwargs; raise if missing.

    Supports:
      - Orchestrator: writer in args[0], client in kwargs['client']
      - Legacy: client in kwargs['redshift'] or args[1]
    """
    writer = kwargs.get("writer", args[0] if len(args) >= 1 else None)
    client = kwargs.get("client", kwargs.get("redshift", args[1] if len(args) >= 2 else None))
    if writer is None or client is None:
        raise TypeError("Expected 'writer' and Redshift client as 'client' (or legacy 'redshift')")
    return writer, client


def _extract_writer_cw_client(
    args: Tuple[Any, ...], kwargs: Dict[str, Any]
) -> Tuple[Any, BaseClient, BaseClient]:
    """Extract (writer, cloudwatch, redshift) from args/kwargs; raise if missing.

    Supports:
      - Orchestrator: writer in args[0], cloudwatch in kwargs['cloudwatch'],
                      redshift in kwargs['client']
      - Legacy: cloudwatch in kwargs['cloudwatch'] or args[1], redshift in kwargs['redshift'] or args[2]
    """
    writer = kwargs.get("writer", args[0] if len(args) >= 1 else None)
    cloudwatch = kwargs.get("cloudwatch", kwargs.get("cw", args[1] if len(args) >= 2 else None))
    redshift = kwargs.get("client", kwargs.get("redshift", args[2] if len(args) >= 3 else None))
    if writer is None or cloudwatch is None or redshift is None:
        raise TypeError("Expected 'writer', 'cloudwatch' and Redshift client as 'client' (or 'redshift')")
    return writer, cloudwatch, redshift


# ---------------------------------------------------------------------------
# Helpers (unchanged)
# ---------------------------------------------------------------------------

def _paginate(
    fn, page_key: str, token_key: str, **kwargs: Any
) -> Iterable[Dict[str, Any]]:
    """Generic paginator for list/describe APIs that return a next token."""
    token: Optional[str] = None
    while True:
        params = dict(kwargs)
        if token:
            params[token_key] = token
        page = fn(**params)
        for item in page.get(page_key, []) or []:
            yield item
        token = page.get(token_key)
        if not token:
            break


def _sum_series(points: Sequence[Tuple[datetime, float]]) -> float:
    """Sum values in a (timestamp, value) series."""
    return float(sum(float(v) for _, v in (points or [])))


def _avg_series(points: Sequence[Tuple[datetime, float]]) -> float:
    """Average values in a (timestamp, value) series."""
    vals = [float(v) for _, v in (points or [])]
    return float(sum(vals) / len(vals)) if vals else 0.0


def _node_hourly(node_type: str) -> float:
    """Resolve hourly price for a Redshift node type via price map."""
    key = f"NODE_HOURLY.{(node_type or '').strip()}"
    try:
        return float(chk.safe_price("REDSHIFT", key, 0.0))  # type: ignore[arg-type]
    except Exception:  # pylint: disable=broad-except
        return 0.0


def _snapshot_gb_month() -> float:
    """Price per GB-month for Redshift snapshot storage."""
    try:
        return float(chk.safe_price("REDSHIFT", "SNAPSHOT_GB_MONTH", 0.0))  # type: ignore[arg-type]
    except Exception:  # pylint: disable=broad-except
        return 0.0


def _cw_dims_cluster(cluster_id: str) -> List[Dict[str, str]]:
    """CW dimensions for Redshift cluster-level metrics."""
    return [{"Name": "ClusterIdentifier", "Value": cluster_id}]


def _list_clusters(redshift: BaseClient) -> List[Dict[str, Any]]:
    """Describe provisioned Redshift clusters (serverless not included)."""
    out: List[Dict[str, Any]] = []
    for c in _paginate(redshift.describe_clusters, page_key="Clusters", token_key="Marker"):
        if not c.get("NodeType"):
            continue
        out.append(c)
    return out


def _list_manual_snapshots(redshift: BaseClient) -> List[Dict[str, Any]]:
    """List manual snapshots (exclude automated)."""
    out: List[Dict[str, Any]] = []
    for s in _paginate(
        redshift.describe_cluster_snapshots,
        page_key="Snapshots",
        token_key="Marker",
        SnapshotType="manual",
    ):
        out.append(s)
    return out


# ---------------------------------------------------------------------------
# Check 1: Idle clusters (low queries & CPU)
# ---------------------------------------------------------------------------

@retry_with_backoff(exceptions=(ClientError,))
def check_redshift_idle_clusters(  # noqa: D401
    *args: Any,
    logger: Optional[logging.Logger] = None,
    lookback_days: int = 14,
    min_queries_sum: int = 10,
    cpu_threshold: float = 5.0,
    **kwargs: Any,
) -> List[Dict[str, Any]]:
    """Flag provisioned clusters with tiny query count and low CPU for days."""
    log = _logger(kwargs.get("logger") or logger)

    region, norm_args = _split_region_from_args(args, kwargs)
    try:
        writer, cloudwatch, redshift = _extract_writer_cw_client(norm_args, kwargs)
    except TypeError as exc:
        log.warning("[check_redshift_idle_clusters] Skipping: %s", exc)
        return []

    if not region:
        region = _infer_region_from_clients(cloudwatch, redshift)

    owner = str(kwargs.get("account_id") or chk.ACCOUNT_ID or "")
    if not (owner and chk.WRITE_ROW):
        log.warning("[check_redshift_idle_clusters] Skipping: missing config.")
        return []

    clusters = _list_clusters(redshift)
    if not clusters:
        return []

    start = datetime.now(timezone.utc) - timedelta(days=lookback_days)
    end = datetime.now(timezone.utc)

    batch = CloudWatchBatcher(region, client=cloudwatch)
    items: List[Tuple[str, str, str, int]] = []  # (arn, id, node_type, nodes)

    for idx, c in enumerate(clusters):
        cid = str(c.get("ClusterIdentifier") or f"cluster-{idx}")
        arn = str(c.get("ClusterNamespaceArn") or cid)
        node_type = str(c.get("NodeType") or "")
        nodes = int(c.get("NumberOfNodes") or 1)
        dims = _cw_dims_cluster(cid)

        batch.add_q(
            id_hint=f"q_{idx}",
            namespace="AWS/Redshift",
            metric="QueriesCompleted",
            dims=dims,
            stat="Sum",
            period=3600,
        )
        batch.add_q(
            id_hint=f"cpu_{idx}",
            namespace="AWS/Redshift",
            metric="CPUUtilization",
            dims=dims,
            stat="Average",
            period=3600,
        )
        items.append((arn or cid, cid, node_type, nodes))

    series = batch.execute(start, end)
    rows: List[Dict[str, Any]] = []
    hours = float(getattr(const, "HOURS_PER_MONTH", 730))

    for idx, (arn, cid, node_type, nodes) in enumerate(items):
        q_sum = _sum_series(series.get(f"q_{idx}", []))
        cpu_avg = _avg_series(series.get(f"cpu_{idx}", []))

        if q_sum > float(min_queries_sum) or cpu_avg > float(cpu_threshold):
            continue

        hourly = _node_hourly(node_type)
        monthly = float(nodes) * hourly * hours if hourly > 0.0 else 0.0
        potential = monthly if monthly > 0.0 else None

        info = next((x for x in clusters if x.get("ClusterIdentifier") == cid), {})
        created_iso = _to_utc_iso(info.get("ClusterCreateTime"))
        state = str(info.get("ClusterStatus") or "Unknown")

        flags = ["IdleCluster"]
        signals = _signals_str(
            {
                "queries_sum": int(q_sum),
                "cpu_avg": round(cpu_avg, 2),
                "node_type": node_type,
                "node_count": nodes,
                "hourly": round(hourly, 4),
            }
        )

        try:
            chk.WRITE_ROW(  # type: ignore[call-arg]
                writer=writer,
                resource_id=arn,
                name=cid,
                owner_id=owner,  # type: ignore[arg-type]
                resource_type="RedshiftCluster",
                region=region,
                state=state,
                creation_date=created_iso,
                estimated_cost=round(monthly, 2) if monthly else 0.0,
                potential_saving=round(potential, 2) if potential else None,
                flags=flags,
                confidence=85,
                signals=signals,
            )
        except Exception as exc:  # pylint: disable=broad-except
            log.warning("[redshift] write_row(idle) failed: %s", exc)

        rows.append({"id": cid, "potential": potential or 0.0})

    return rows


# ---------------------------------------------------------------------------
# Check 2: Stale manual snapshots (old, likely unused)
# ---------------------------------------------------------------------------

@retry_with_backoff(exceptions=(ClientError,))
def check_redshift_stale_snapshots(  # noqa: D401
    *args: Any,
    logger: Optional[logging.Logger] = None,
    older_than_days: int = 30,
    **kwargs: Any,
) -> List[Dict[str, Any]]:
    """Flag manual snapshots older than N days (storage cost with little value)."""
    log = _logger(kwargs.get("logger") or logger)

    region, norm_args = _split_region_from_args(args, kwargs)
    try:
        writer, redshift = _extract_writer_client(norm_args, kwargs)
    except TypeError as exc:
        log.warning("[check_redshift_stale_snapshots] Skipping: %s", exc)
        return []

    if not region:
        region = _infer_region_from_clients(None, redshift)

    owner = str(kwargs.get("account_id") or chk.ACCOUNT_ID or "")
    if not (owner and chk.WRITE_ROW):
        log.warning("[check_redshift_stale_snapshots] Skipping: missing config.")
        return []

    snapshots = _list_manual_snapshots(redshift)
    if not snapshots:
        return []

    cutoff = datetime.now(timezone.utc) - timedelta(days=int(older_than_days))
    p_gb_mo = _snapshot_gb_month()

    for s in snapshots:
        sid = str(s.get("SnapshotIdentifier") or "")
        arn = str(s.get("SnapshotArn") or sid)
        cid = str(s.get("ClusterIdentifier") or "")
        created = s.get("SnapshotCreateTime")
        created_iso = _to_utc_iso(created)

        if not created or not isinstance(created, datetime):
            continue
        if created.tzinfo is None:
            created = created.replace(tzinfo=timezone.utc)
        if created > cutoff:
            continue

        size_mb = (
            s.get("TotalBackupSizeInMegaBytes")
            or s.get("ActualIncrementalBackupSizeInMegaBytes")
            or s.get("EstimatedSizeInMegaBytes")
            or None
        )
        size_gb = float(size_mb) / 1024.0 if isinstance(size_mb, (int, float)) else None

        potential = None
        if size_gb is not None and p_gb_mo > 0.0:
            potential = round(float(size_gb) * float(p_gb_mo), 2)

        flags = ["StaleSnapshot"]
        signals = _signals_str(
            {
                "cluster": cid,
                "age_days": int((datetime.now(timezone.utc) - created).days),
                "size_gb": int(size_gb) if size_gb is not None else "na",
                "price_gb_month": p_gb_mo,
            }
        )

        try:
            chk.WRITE_ROW(  # type: ignore[call-arg]
                writer=writer,
                resource_id=arn,
                name=sid or arn,
                owner_id=owner,  # type: ignore[arg-type]
                resource_type="RedshiftSnapshot",
                region=region,
                state="Available",
                creation_date=created_iso,
                estimated_cost="",
                potential_saving=potential,
                flags=flags,
                confidence=70 if potential else 60,
                signals=signals,
            )
        except Exception as exc:  # pylint: disable=broad-except
            log.warning("[redshift] write_row(snapshot) failed: %s", exc)
