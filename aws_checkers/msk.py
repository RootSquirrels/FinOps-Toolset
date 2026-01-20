"""Checkers: MSK (Managed Streaming for Apache Kafka)."""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from botocore.client import BaseClient
from botocore.exceptions import ClientError

from aws_checkers.common import _logger, _signals_str, _to_utc_iso
from aws_checkers import config
from finops_toolset import config as const
from core.retry import retry_with_backoff
from core.cloudwatch import CloudWatchBatcher


# ---------------------------------------------------------------------------
# Call normalization & Extractor
# ---------------------------------------------------------------------------


def _split_region_from_args(
    args: Tuple[Any, ...], kwargs: Dict[str, Any]
) -> Tuple[Optional[str], Tuple[Any, ...]]:
    """Normalize region + remaining args for orchestrator and legacy calls.

    Accepted patterns:
      - Orchestrator: fn(writer, **kwargs) -> region may be in kwargs (optional)
      - Legacy: fn(region, writer, ...) -> first arg is region str
    """
    region_kw = kwargs.get("region")
    if isinstance(region_kw, str) and region_kw:
        return region_kw, args

    if args and isinstance(args[0], str) and len(args) >= 2:
        return str(args[0]), args[1:]

    return None, args


def _infer_region_from_clients(cloudwatch: Optional[BaseClient], kafka: Optional[BaseClient]) -> str:
    """Infer region from boto3 client meta; fallback to 'GLOBAL'."""
    for client in (cloudwatch, kafka):
        if client is None:
            continue
        r = getattr(getattr(client, "meta", None), "region_name", None)
        if r:
            return str(r)
    return "GLOBAL"


def _extract_writer_cw_client(
    args: Tuple[Any, ...], kwargs: Dict[str, Any]
) -> Tuple[Any, BaseClient, BaseClient]:
    """Extract (writer, cloudwatch, kafka) from args/kwargs; raise if missing.

    Supports:
      - Orchestrator: writer positional, cloudwatch=..., client=... (kafka)
      - Legacy: fn(region, writer, cloudwatch, kafka)
      - Back-compat: kafka may also be provided as 'kafka='
    """
    writer = kwargs.get("writer", args[0] if len(args) >= 1 else None)
    cloudwatch = kwargs.get("cloudwatch", args[1] if len(args) >= 2 else None)
    kafka = kwargs.get("client", kwargs.get("kafka", args[2] if len(args) >= 3 else None))
    if writer is None or cloudwatch is None or kafka is None:
        raise TypeError("Expected 'writer', 'cloudwatch' and Kafka client as 'client' (or 'kafka')")
    return writer, cloudwatch, kafka


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _paginate(
    fetch_fn, page_key: str, token_key: str, **kwargs: Any
) -> Iterable[Dict[str, Any]]:
    """Generic paginator for list_* APIs that return tokenized pages."""
    token: Optional[str] = None
    while True:
        params = dict(kwargs)
        if token:
            params[token_key] = token
        page = fetch_fn(**params)
        for item in page.get(page_key, []) or []:
            yield item
        token = page.get(token_key)
        if not token:
            break


def _sum_series(points: Sequence[Tuple[datetime, float]]) -> float:
    """Sum values in a time series of (timestamp, value)."""
    return float(sum(float(v) for _, v in (points or [])))


def _gb_from_bytes(num: float) -> float:
    """Convert bytes to GiB (approx; conservative to avoid false positives)."""
    try:
        return float(num) / (1024.0 ** 3)
    except Exception:  # pylint: disable=broad-except
        return 0.0


def _broker_hourly(instance_type: str) -> float:
    """Resolve hourly price for a broker instance via pricing keys.

    We normalize 'kafka.m5.large' -> 'm5.large' and look up:
        MSK / BROKER_HOURLY.<type>
    """
    it = (instance_type or "").strip()
    it = it.replace("kafka.", "")
    key = f"BROKER_HOURLY.{it}"
    try:
        return float(config.safe_price("MSK", key, 0.0))  # type: ignore[arg-type]
    except Exception:  # pylint: disable=broad-except
        return 0.0


def _storage_gb_month_price() -> float:
    """Return MSK storage per-GB per-month price."""
    try:
        return float(config.safe_price("MSK", "STORAGE_GB_MONTH", 0.0))  # type: ignore[arg-type]
    except Exception:  # pylint: disable=broad-except
        return 0.0


def _fetch_clusters(kafka: BaseClient) -> List[Dict[str, Any]]:
    """List clusters using v2 if available, else v1."""
    try:
        return list(
            _paginate(
                kafka.list_clusters_v2, page_key="ClusterSummaryList", token_key="NextToken"
            )
        )
    except Exception:  # pylint: disable=broad-except
        return list(
            _paginate(kafka.list_clusters, page_key="ClusterInfoList", token_key="NextToken")
        )


def _describe_cluster(kafka: BaseClient, arn: str) -> Dict[str, Any]:
    """Describe a cluster; support v2/v1 response shapes."""
    try:
        out = kafka.describe_cluster_v2(ClusterArn=arn)
        return out.get("ClusterInfo", {})  # type: ignore[return-value]
    except Exception:  # pylint: disable=broad-except
        out = kafka.describe_cluster(ClusterArn=arn)
        return out.get("ClusterInfo", {})  # type: ignore[return-value]


def _cw_dims_for_cluster(name: str) -> List[Dict[str, str]]:
    """Return CW dimensions for MSK cluster-level metrics."""
    return [{"Name": "Cluster Name", "Value": name}]


def _batch_bytes_metrics(
    region: str,
    cloudwatch: BaseClient,
    clusters: List[Tuple[str, str]],
    start: datetime,
    end: datetime,
) -> Dict[str, List[Tuple[datetime, float]]]:
    """Build and execute bytes-in/out queries for all clusters in one batch."""
    batch = CloudWatchBatcher(region, client=cloudwatch)
    for idx, (_arn, name) in enumerate(clusters):
        dims = _cw_dims_for_cluster(name)
        batch.add_q(
            id_hint=f"bin_{idx}",
            namespace="AWS/Kafka",
            metric="BytesInPerSec",
            dims=dims,
            stat="Sum",
            period=3600,
        )
        batch.add_q(
            id_hint=f"bout_{idx}",
            namespace="AWS/Kafka",
            metric="BytesOutPerSec",
            dims=dims,
            stat="Sum",
            period=3600,
        )
    return batch.execute(start, end)


def _cluster_monthly_cost(
    broker_count: int, instance_type: str, storage_gb: float
) -> float:
    """Estimate current monthly cluster cost (brokers + storage)."""
    hours = float(getattr(const, "HOURS_PER_MONTH", 730))
    hourly = _broker_hourly(instance_type)
    stor = _storage_gb_month_price()
    return float(broker_count) * hourly * hours + storage_gb * stor


# ---------------------------------------------------------------------------
# Check 1: Idle MSK clusters
# ---------------------------------------------------------------------------

@retry_with_backoff(exceptions=(ClientError,))
def check_msk_idle_clusters(  # noqa: D401
    *args: Any,
    logger: Optional[logging.Logger] = None,
    lookback_days: int = 14,
    bytes_threshold_gb: float = 1.0,
    min_brokers_for_saving: int = 1,
    **kwargs: Any,
) -> List[Dict[str, Any]]:
    """Flag clusters with ~zero traffic; suggest deleting or shutting down.

    Potential saving includes broker-hours and provisioned storage.
    """
    log = _logger(kwargs.get("logger") or logger)
    region, norm_args = _split_region_from_args(args, kwargs)
    try:
        writer, cloudwatch, kafka = _extract_writer_cw_client(norm_args, kwargs)
    except TypeError as exc:
        log.warning("[check_msk_idle_clusters] Skipping: %s", exc)
        return []

    if not region:
        region = _infer_region_from_clients(cloudwatch, kafka)

    owner = str(kwargs.get("account_id") or config.ACCOUNT_ID or "")
    if not (owner and config.WRITE_ROW):
        log.warning("[check_msk_idle_clusters] Skipping: missing config.")
        return []

    start = datetime.now(timezone.utc) - timedelta(days=lookback_days)
    end = datetime.now(timezone.utc)

    clusters_raw = _fetch_clusters(kafka)
    if not clusters_raw:
        return []

    clusters: List[Tuple[str, str]] = []
    for c in clusters_raw:
        arn = c.get("ClusterArn") or c.get("ClusterArnV2") or c.get("ClusterArn", "")
        name = c.get("ClusterName") or c.get("ClusterNameV2") or c.get("ClusterName", "")
        if arn and name:
            clusters.append((arn, name))

    if not clusters:
        return []

    series = _batch_bytes_metrics(region, cloudwatch, clusters, start, end)

    rows: List[Dict[str, Any]] = []

    for idx, (arn, name) in enumerate(clusters):
        info = _describe_cluster(kafka, arn)
        group = info.get("BrokerNodeGroupInfo", {})
        count = int(info.get("NumberOfBrokerNodes") or 0)
        instance_type = str(group.get("InstanceType") or "")
        volume_gb = float(
            (((group.get("StorageInfo") or {}).get("EbsStorageInfo") or {}).get("VolumeSize") or 0.0)
        )
        storage_gb = float(count) * float(volume_gb)

        bin_sum = _sum_series(series.get(f"bin_{idx}", []))
        bout_sum = _sum_series(series.get(f"bout_{idx}", []))
        bytes_in_gb = _gb_from_bytes(bin_sum)
        bytes_out_gb = _gb_from_bytes(bout_sum)

        if (
            bytes_in_gb < float(bytes_threshold_gb)
            and bytes_out_gb < float(bytes_threshold_gb)
            and count >= int(min_brokers_for_saving)
        ):
            monthly = _cluster_monthly_cost(count, instance_type, storage_gb)
            potential = monthly if monthly > 0.0 else None

            flags = ["IdleCluster"]
            created_iso = _to_utc_iso(info.get("CreationTime"))
            signals = _signals_str(
                {
                    "bytes_in_gb": round(bytes_in_gb, 3),
                    "bytes_out_gb": round(bytes_out_gb, 3),
                    "broker_count": count,
                    "instance_type": instance_type,
                    "storage_gb": int(storage_gb),
                }
            )

            try:
                # type: ignore[call-arg]
                config.WRITE_ROW(
                    writer=writer,
                    resource_id=str(arn),
                    name=name,
                    owner_id=owner,  # type: ignore[arg-type]
                    resource_type="MSKCluster",
                    region=region,
                    state=str(info.get("State") or "Unknown"),
                    creation_date=created_iso,
                    estimated_cost=round(monthly, 2) if monthly else 0.0,
                    potential_saving=round(potential, 2) if potential else None,
                    flags=flags,
                    confidence=85,
                    signals=signals,
                )
            except Exception as exc:  # pylint: disable=broad-except
                log.warning("[msk] write_row(idle) failed: %s", exc)

            rows.append(
                {
                    "arn": arn,
                    "name": name,
                    "brokers": count,
                    "potential": potential or 0.0,
                }
            )

    return rows


# ---------------------------------------------------------------------------
# Check 2: Over-provisioned brokers (low traffic)
# ---------------------------------------------------------------------------

@retry_with_backoff(exceptions=(ClientError,))
def check_msk_overprovisioned_brokers(  # noqa: D401
    *args: Any,
    logger: Optional[logging.Logger] = None,
    lookback_days: int = 14,
    low_traffic_gb: float = 10.0,
    min_brokers: int = 3,
    scale_down_factor: float = 0.5,
    **kwargs: Any,
) -> List[Dict[str, Any]]:
    """Flag clusters with brokers likely exceeding traffic needs.

    Heuristic: total bytes_in over lookback < `low_traffic_gb`, and brokers > min_brokers.
    Target brokers = max(min_brokers, ceil(brokers * scale_down_factor)).
    """
    log = _logger(kwargs.get("logger") or logger)
    region, norm_args = _split_region_from_args(args, kwargs)
    try:
        writer, cloudwatch, kafka = _extract_writer_cw_client(norm_args, kwargs)
    except TypeError as exc:
        log.warning("[check_msk_overprovisioned_brokers] Skipping: %s", exc)
        return []

    if not region:
        region = _infer_region_from_clients(cloudwatch, kafka)

    owner = str(kwargs.get("account_id") or config.ACCOUNT_ID or "")
    if not (owner and config.WRITE_ROW):
        log.warning("[check_msk_overprovisioned_brokers] Skipping: missing config.")
        return []

    start = datetime.now(timezone.utc) - timedelta(days=lookback_days)
    end = datetime.now(timezone.utc)

    clusters_raw = _fetch_clusters(kafka)
    if not clusters_raw:
        return []

    clusters: List[Tuple[str, str]] = []
    for c in clusters_raw:
        arn = c.get("ClusterArn") or c.get("ClusterArnV2") or c.get("ClusterArn", "")
        name = c.get("ClusterName") or c.get("ClusterNameV2") or c.get("ClusterName", "")
        if arn and name:
            clusters.append((arn, name))

    if not clusters:
        return []

    series = _batch_bytes_metrics(region, cloudwatch, clusters, start, end)

    hours = float(getattr(const, "HOURS_PER_MONTH", 730))

    for idx, (arn, name) in enumerate(clusters):
        info = _describe_cluster(kafka, arn)
        group = info.get("BrokerNodeGroupInfo", {})
        count = int(info.get("NumberOfBrokerNodes") or 0)
        instance_type = str(group.get("InstanceType") or "")

        bin_sum = _sum_series(series.get(f"bin_{idx}", []))
        bytes_in_gb = _gb_from_bytes(bin_sum)

        if count <= int(min_brokers):
            continue
        if bytes_in_gb >= float(low_traffic_gb):
            continue

        target = max(int(min_brokers), int((count * float(scale_down_factor)) + 0.9999))
        if target >= count:
            continue

        delta = count - target
        hourly = _broker_hourly(instance_type)
        potential = float(delta) * hourly * hours if hourly > 0.0 else None

        flags = ["LowTraffic", f"ScaleTo={target}"]
        created_iso = _to_utc_iso(info.get("CreationTime"))
        signals = _signals_str(
            {
                "bytes_in_gb": round(bytes_in_gb, 3),
                "broker_count": count,
                "instance_type": instance_type,
                "target_brokers": target,
            }
        )

        try:
            # type: ignore[call-arg]
            config.WRITE_ROW(
                writer=writer,
                resource_id=str(arn),
                name=name,
                owner_id=owner,  # type: ignore[arg-type]
                resource_type="MSKCluster",
                region=region,
                state=str(info.get("State") or "Unknown"),
                creation_date=created_iso,
                estimated_cost="",
                potential_saving=round(potential, 2) if potential else None,
                flags=flags,
                confidence=70,
                signals=signals,
            )
        except Exception as exc:  # pylint: disable=broad-except
            log.warning("[msk] write_row(overprov) failed: %s", exc)
