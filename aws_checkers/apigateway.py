"""Checkers: API Gateway."""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Sequence, Tuple

from botocore.client import BaseClient
from botocore.exceptions import ClientError

from aws_checkers import config
from core.cloudwatch import CloudWatchBatcher
from core.retry import retry_with_backoff
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
    """Normalize region + remaining args for orchestrator and legacy calls.

    Returns:
      (region, remaining_args)

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


def _infer_region_from_clients(cloudwatch: Optional[BaseClient], client: Optional[BaseClient]) -> str:
    """Infer region from cloudwatch/client meta; fallback to 'GLOBAL'."""
    for c in (cloudwatch, client):
        if c is None:
            continue
        r = getattr(getattr(c, "meta", None), "region_name", None)
        if r:
            return str(r)
    return "GLOBAL"


# ---------------------------------------------------------------------------
# Extractors (orchestrator-compatible)
# ---------------------------------------------------------------------------

def _extract_writer_client(
    args: Tuple[Any, ...], kwargs: Dict[str, Any]
) -> Tuple[Any, BaseClient]:
    """Extract (writer, client) from args/kwargs, else raise TypeError."""
    writer = kwargs.get("writer", args[0] if len(args) >= 1 else None)
    client = kwargs.get("client", args[1] if len(args) >= 2 else None)
    if writer is None or client is None:
        raise TypeError("Expected 'writer' and 'client'")
    return writer, client


def _extract_writer_cw_client(
    args: Tuple[Any, ...], kwargs: Dict[str, Any]
) -> Tuple[Any, BaseClient, BaseClient]:
    """Extract (writer, cloudwatch, client) from args/kwargs, else raise TypeError."""
    writer = kwargs.get("writer", args[0] if len(args) >= 1 else None)
    cloudwatch = kwargs.get("cloudwatch", args[1] if len(args) >= 2 else None)
    client = kwargs.get("client", args[2] if len(args) >= 3 else None)
    if writer is None or cloudwatch is None or client is None:
        raise TypeError("Expected 'writer', 'cloudwatch' and 'client'")
    return writer, cloudwatch, client


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _safe_price(service: str, key: str, default: float = 0.0) -> float:
    """Resolve a price via config.safe_price(service, key, default)."""
    try:
        return float(config.safe_price(service, key, default))  # type: ignore[arg-type]
    except Exception:  # pylint: disable=broad-except
        return float(default)


def _paginate(fetch_fn, *, page_key: str, token_name: str = "position", **kwargs: Any):
    """Generic paginator for API Gateway list calls (varies by version)."""
    token: Optional[str] = None
    while True:
        params = dict(kwargs)
        if token:
            params[token_name] = token
        page = fetch_fn(**params)
        for item in page.get(page_key, []) or []:
            yield item
        token = page.get(token_name) or page.get("NextToken")
        if not token:
            break


def _sum_series(series: List[Tuple[datetime, float]]) -> float:
    """Sum a time series of (timestamp, value) tuples."""
    return float(sum(float(v) for _, v in (series or [])))


def _ratio(numer: float, denom: float) -> float:
    """Return a safe ratio numer/denom."""
    d = float(denom) if denom else 0.0
    return float(numer) / d if d > 0.0 else 0.0


# ---------------------------------------------------------------------------
# Metrics building (REST & HTTP APIs)
# ---------------------------------------------------------------------------

def _build_rest_stage_queries(api_name: str, stage_name: str, idx: int) -> List[Dict[str, Any]]:
    """Create CloudWatchBatcher.add_q specs for a REST API stage."""
    dims = [
        {"Name": "ApiName", "Value": api_name},
        {"Name": "Stage", "Value": stage_name},
    ]
    q: List[Dict[str, Any]] = []
    q.append(
        {
            "Id": f"cnt_{idx}",
            "Namespace": "AWS/ApiGateway",
            "Metric": "Count",
            "Dims": dims,
            "Stat": "Sum",
            "Period": 3600,
        }
    )
    q.append(
        {
            "Id": f"hit_{idx}",
            "Namespace": "AWS/ApiGateway",
            "Metric": "CacheHitCount",
            "Dims": dims,
            "Stat": "Sum",
            "Period": 3600,
        }
    )
    q.append(
        {
            "Id": f"miss_{idx}",
            "Namespace": "AWS/ApiGateway",
            "Metric": "CacheMissCount",
            "Dims": dims,
            "Stat": "Sum",
            "Period": 3600,
        }
    )
    return q


def _build_http_stage_queries(api_id: str, stage_name: str, idx: int) -> List[Dict[str, Any]]:
    """Create CloudWatchBatcher.add_q specs for an HTTP API stage (v2)."""
    dims = [
        {"Name": "ApiId", "Value": api_id},
        {"Name": "Stage", "Value": stage_name},
    ]
    return [
        {
            "Id": f"cnt_{idx}",
            "Namespace": "AWS/ApiGateway",
            "Metric": "Count",
            "Dims": dims,
            "Stat": "Sum",
            "Period": 3600,
        }
    ]


def _run_cw_queries(
    region: str,
    cloudwatch: BaseClient,
    queries: Sequence[Dict[str, Any]],
    start: datetime,
    end: datetime,
) -> Dict[str, List[Tuple[datetime, float]]]:
    """Run CloudWatch queries via CloudWatchBatcher.add_q/execute (repo API)."""
    batcher = CloudWatchBatcher(region, client=cloudwatch)
    for q in queries:
        batcher.add_q(
            id_hint=q.get("Id", ""),
            namespace=q.get("Namespace", ""),
            metric=q.get("Metric", ""),
            dims=q.get("Dims", []) or [],
            stat=q.get("Stat", "Sum"),
            period=int(q.get("Period", 3600) or 3600),
        )
    return batcher.execute(start, end)


# ---------------------------------------------------------------------------
# Check 1: REST stages with cache enabled but poor cache hit ratio
# ---------------------------------------------------------------------------

@retry_with_backoff(exceptions=(ClientError,))
def check_apigw_low_cache_hit_ratio(  # noqa: D401
    *args: Any,
    logger: Optional[logging.Logger] = None,
    lookback_days: int = 14,
    hit_ratio_threshold: float = 0.2,
    min_requests_sum: float = 100.0,
    **kwargs: Any,
) -> None:
    """Flag REST API stages with cache enabled but low cache hit ratio."""
    log = _logger(kwargs.get("logger") or logger)

    region, norm_args = _split_region_from_args(args, kwargs)
    try:
        writer, cloudwatch, apigw = _extract_writer_cw_client(norm_args, kwargs)
    except TypeError as exc:
        log.warning("[check_apigw_low_cache_hit_ratio] Skipping: %s", exc)
        return

    if not region:
        region = _infer_region_from_clients(cloudwatch, apigw)

    if not (config.ACCOUNT_ID and config.WRITE_ROW):
        log.warning("[check_apigw_low_cache_hit_ratio] Skipping: missing config.")
        return

    start = datetime.now(timezone.utc) - timedelta(days=lookback_days)
    end = datetime.now(timezone.utc)

    try:
        apis = list(_paginate(apigw.get_rest_apis, page_key="items", token_name="position"))
    except ClientError as exc:
        log.warning("[apigw] get_rest_apis failed: %s", exc)
        return

    stage_specs: List[Tuple[str, str, str, float]] = []
    for api in apis:
        api_id = api.get("id", "")
        api_name = api.get("name", api_id)
        try:
            stages = apigw.get_stages(restApiId=api_id).get("item", [])  # type: ignore[call-arg]
        except ClientError:
            continue
        for st in stages:
            if not st.get("cacheClusterEnabled"):
                continue
            size_raw = st.get("cacheClusterSize") or ""
            try:
                cache_size_gb = float(str(size_raw))
            except Exception:  # pylint: disable=broad-except
                cache_size_gb = 0.0
            stage_name = st.get("stageName", "")
            if stage_name:
                stage_specs.append((api_id, api_name, stage_name, cache_size_gb))

    if not stage_specs:
        return

    queries: List[Dict[str, Any]] = []
    for idx, (_, api_name, stage_name, _) in enumerate(stage_specs):
        queries.extend(_build_rest_stage_queries(api_name, stage_name, idx))

    series = _run_cw_queries(region, cloudwatch, queries, start, end)

    for idx, (api_id, api_name, stage_name, cache_size_gb) in enumerate(stage_specs):
        hit = _sum_series(series.get(f"hit_{idx}", []))
        miss = _sum_series(series.get(f"miss_{idx}", []))
        req = _sum_series(series.get(f"cnt_{idx}", []))
        ratio = _ratio(hit, hit + miss)

        if req < float(min_requests_sum) or ratio >= float(hit_ratio_threshold):
            continue

        price_key = f"CACHE_HR.{cache_size_gb:g}"
        hourly = _safe_price("APIGW", price_key, 0.0)
        monthly = hourly * const.HOURS_PER_MONTH if hourly > 0.0 else 0.0
        potential = monthly if monthly > 0.0 else None

        resource_id = f"apigw:{api_id}:{stage_name}"
        flags = ["CacheEnabled", f"CacheSizeGB={cache_size_gb:g}", "LowHitRatio"]

        try:
            config.WRITE_ROW(  # type: ignore[call-arg]
                writer=writer,
                resource_id=resource_id,
                name=f"{api_name}:{stage_name}",
                owner_id=config.ACCOUNT_ID,  # type: ignore[arg-type]
                resource_type="APIGatewayStage",
                region=region,
                state="InService",
                creation_date="",
                estimated_cost=round(monthly, 2) if monthly else 0.0,
                potential_saving=round(potential, 2) if potential else None,
                flags=flags,
                confidence=85,
                signals=(
                    f"requests_sum={int(req)}|cache_hit_ratio={round(ratio, 3)}|"
                    f"cache_size_gb={cache_size_gb:g}"
                ),
            )
        except Exception as exc:  # pylint: disable=broad-except
            log.warning("[apigw] write_row(cache-hr) failed: %s", exc)


# ---------------------------------------------------------------------------
# Check 2: Idle APIs — REST (v1)
# ---------------------------------------------------------------------------

@retry_with_backoff(exceptions=(ClientError,))
def check_apigw_idle_rest_apis(  # noqa: D401
    *args: Any,
    logger: Optional[logging.Logger] = None,
    lookback_days: int = 14,
    requests_threshold: float = 50.0,
    **kwargs: Any,
) -> None:
    """Flag REST APIs with near-zero requests over the lookback window."""
    log = _logger(kwargs.get("logger") or logger)

    region, norm_args = _split_region_from_args(args, kwargs)
    try:
        writer, cloudwatch, apigw = _extract_writer_cw_client(norm_args, kwargs)
    except TypeError as exc:
        log.warning("[check_apigw_idle_rest_apis] Skipping: %s", exc)
        return

    if not region:
        region = _infer_region_from_clients(cloudwatch, apigw)

    if not (config.ACCOUNT_ID and config.WRITE_ROW):
        log.warning("[check_apigw_idle_rest_apis] Skipping: missing config.")
        return

    start = datetime.now(timezone.utc) - timedelta(days=lookback_days)
    end = datetime.now(timezone.utc)

    try:
        apis = list(_paginate(apigw.get_rest_apis, page_key="items", token_name="position"))
    except ClientError as exc:
        log.warning("[apigw] get_rest_apis failed: %s", exc)
        return

    stage_index: List[Tuple[str, str, str]] = []
    for api in apis:
        api_id = api.get("id", "")
        api_name = api.get("name", api_id)
        try:
            stages = apigw.get_stages(restApiId=api_id).get("item", [])  # type: ignore[call-arg]
        except ClientError:
            continue
        for st in stages:
            stage_name = st.get("stageName", "")
            if stage_name:
                stage_index.append((api_id, api_name, stage_name))

    if not stage_index:
        return

    queries: List[Dict[str, Any]] = []
    for idx, (_, api_name, stage_name) in enumerate(stage_index):
        queries.extend(_build_rest_stage_queries(api_name, stage_name, idx=idx)[:1])

    series = _run_cw_queries(region, cloudwatch, queries, start, end)

    requests_sum_by_api: Dict[str, float] = {}
    for idx, (api_id, _api_name, _stage) in enumerate(stage_index):
        cnt = _sum_series(series.get(f"cnt_{idx}", []))
        requests_sum_by_api[api_id] = requests_sum_by_api.get(api_id, 0.0) + cnt

    for api in apis:
        api_id = api.get("id", "")
        api_name = api.get("name", api_id)
        req = float(requests_sum_by_api.get(api_id, 0.0))
        if req >= float(requests_threshold):
            continue

        resource_id = f"apigw:{api_id}"
        try:
            config.WRITE_ROW(  # type: ignore[call-arg]
                writer=writer,
                resource_id=resource_id,
                name=api_name,
                owner_id=config.ACCOUNT_ID,  # type: ignore[arg-type]
                resource_type="APIGatewayREST",
                region=region,
                state="InService",
                creation_date="",
                estimated_cost="",
                potential_saving=None,
                flags=["IdleAPI"],
                confidence=80,
                signals=f"requests_sum={int(req)}",
            )
        except Exception as exc:  # pylint: disable=broad-except
            log.warning("[apigw] write_row(idle-rest) failed: %s", exc)


# ---------------------------------------------------------------------------
# Check 3: Idle APIs — HTTP (v2)
# ---------------------------------------------------------------------------

@retry_with_backoff(exceptions=(ClientError,))
def check_apigw_idle_http_apis(  # noqa: D401
    *args: Any,
    logger: Optional[logging.Logger] = None,
    lookback_days: int = 14,
    requests_threshold: float = 50.0,
    **kwargs: Any,
) -> None:
    """Flag HTTP APIs (API Gateway v2) with ~zero requests."""
    log = _logger(kwargs.get("logger") or logger)

    region, norm_args = _split_region_from_args(args, kwargs)
    try:
        writer, cloudwatch, apigw2 = _extract_writer_cw_client(norm_args, kwargs)
    except TypeError as exc:
        log.warning("[check_apigw_idle_http_apis] Skipping: %s", exc)
        return

    if not region:
        region = _infer_region_from_clients(cloudwatch, apigw2)

    if not (config.ACCOUNT_ID and config.WRITE_ROW):
        log.warning("[check_apigw_idle_http_apis] Skipping: missing config.")
        return

    start = datetime.now(timezone.utc) - timedelta(days=lookback_days)
    end = datetime.now(timezone.utc)

    try:
        apis = list(_paginate(apigw2.get_apis, page_key="Items", token_name="NextToken"))
    except ClientError as exc:
        log.warning("[apigw2] get_apis failed: %s", exc)
        return

    stage_index: List[Tuple[str, str]] = [] # (api_id, stage_name)
    names_by_id: Dict[str, str] = {}

    for api in apis:
        api_id = api.get("ApiId", "")
        names_by_id[api_id] = api.get("Name", api_id)
        try:
            stages = apigw2.get_stages(ApiId=api_id).get("Items", [])  # type: ignore[call-arg]
        except ClientError:
            continue
        for st in stages:
            stage_name = st.get("StageName", "")
            if stage_name:
                stage_index.append((api_id, stage_name))

    if not stage_index:
        return

    queries: List[Dict[str, Any]] = []
    for idx, (api_id, stage_name) in enumerate(stage_index):
        queries.extend(_build_http_stage_queries(api_id, stage_name, idx=idx))

    series = _run_cw_queries(region, cloudwatch, queries, start, end)

    # Aggregate per API across stages
    requests_sum_by_api: Dict[str, float] = {}
    for idx, (api_id, _stage) in enumerate(stage_index):
        cnt = _sum_series(series.get(f"cnt_{idx}", []))
        requests_sum_by_api[api_id] = requests_sum_by_api.get(api_id, 0.0) + cnt

    for api in apis:
        api_id = api.get("ApiId", "")
        name = names_by_id.get(api_id, api_id)
        req = float(requests_sum_by_api.get(api_id, 0.0))
        if req >= float(requests_threshold):
            continue

        resource_id = f"apigw2:{api_id}"
        try:
            config.WRITE_ROW(  # type: ignore[call-arg]
                writer=writer,
                resource_id=resource_id,
                name=name,
                owner_id=config.ACCOUNT_ID,  # type: ignore[arg-type]
                resource_type="APIGatewayHTTP",
                region=region,
                state="InService",
                creation_date="",
                estimated_cost="",
                potential_saving=None,
                flags=["IdleAPI"],
                confidence=80,
                signals=f"requests_sum={int(req)}",
            )
        except Exception as exc:  # pylint: disable=broad-except
            log.warning("[apigw2] write_row(idle-http) failed: %s", exc)
