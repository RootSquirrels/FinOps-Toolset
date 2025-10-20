"""Checker: Amazon CloudFront distributions.

Finds CloudFront distributions that appear unused in a recent window and/or are
disabled. Outputs Flags, Estimated_Cost_USD, Potential_Saving_USD, and Signals.

Heuristics:
  - Unused: Sum(Requests)==0 AND Sum(BytesDownloaded)==0 over lookback window.
  - Disabled: distribution "Enabled" is False.
  - Logging disabled: best-effort (requires get_distribution_config).

Estimated cost (heuristic):
  - requests_cost   = Requests / 1_000_000 * price("CloudFront","REQUESTS_1M")
  - data_out_cost   = BytesDownloaded / GB * price("CloudFront","DATA_OUT_GB")
  - estimated_cost  = requests_cost + data_out_cost
  - potential_saving = estimated_cost if Unused else 0.0

Design:
  - Dependencies via finops_toolset.checkers.config.setup(...).
  - Uses CloudWatchBatcher with global CloudFront dimensions (Region='Global').
  - Tolerant to missing clients/config; logs warnings and skips instead of raising.
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
    _to_utc_iso,
)
from core.retry import retry_with_backoff
from core.cloudwatch import CloudWatchBatcher


# ----------------------------- helpers --------------------------------- #


def _sum_from_result(res: Any) -> float:
    """Reduce CloudWatchBatcher result → sum of values (supports [(ts, val)])."""
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


def _extract_writer_cf_cw(
    args: Tuple[Any, ...],
    kwargs: Dict[str, Any],
) -> Tuple[Any, Any, Any]:
    """Accept writer/cloudfront/cloudwatch positionally or by keyword; prefer kw."""
    writer = kwargs.get("writer", args[0] if len(args) >= 1 else None)
    cloudfront = kwargs.get("cloudfront", args[1] if len(args) >= 2 else None)
    cloudwatch = kwargs.get("cloudwatch", args[2] if len(args) >= 3 else None)
    if writer is None or cloudfront is None or cloudwatch is None:
        raise TypeError(
            "check_cloudfront_distributions expected 'writer', 'cloudfront', and 'cloudwatch' "
            f"(got writer={writer!r}, cloudfront={cloudfront!r}, cloudwatch={cloudwatch!r})"
        )
    return writer, cloudfront, cloudwatch


def _get_logging_enabled(cloudfront, dist_id: str, log: logging.Logger) -> Optional[bool]:
    """Best-effort 'Logging.Enabled' from get_distribution_config (may fail)."""
    try:
        resp = cloudfront.get_distribution_config(Id=dist_id)
        cfg = resp.get("DistributionConfig", {}) or {}
        logging_cfg = cfg.get("Logging") or {}
        enabled = logging_cfg.get("Enabled")
        return bool(enabled)
    except ClientError as exc:
        log.debug("[cloudfront logging] get_distribution_config failed for %s: %s", dist_id, exc)
        return None


# ------------------------------ checker -------------------------------- #

@retry_with_backoff(exceptions=(ClientError,))
def check_cloudfront_distributions(  # pylint: disable=unused-argument
    *args,
    logger: Optional[logging.Logger] = None,
    lookback_days: int = 30,
    **kwargs,
) -> None:
    """
    Enumerate CloudFront distributions and flag those that are unused and/or disabled.
    Uses CloudWatch 'AWS/CloudFront' metrics with Region='Global'.
    """
    log = _logger(kwargs.get("logger") or logger)

    # tolerate missing clients in tests
    try:
        writer, cloudfront, cloudwatch = _extract_writer_cf_cw(args, kwargs)
    except TypeError as exc:
        log.warning("[check_cloudfront_distributions] Skipping: %s", exc)
        return

    # Window & batcher (CloudFront metrics are global; CloudWatch region typically us-east-1)
    now_utc = datetime.now(timezone.utc).replace(microsecond=0)
    start_time = now_utc - timedelta(days=lookback_days)
    period = 3600  # 1 hour buckets
    cw_region = getattr(getattr(cloudwatch, "meta", None), "region_name", "") or "us-east-1"
    cw_batch = CloudWatchBatcher(region=cw_region, client=cloudwatch)

    # List distributions (global service; marker-based pagination)
    dists: List[Dict[str, Any]] = []
    try:
        marker: Optional[str] = None
        while True:
            resp = cloudfront.list_distributions(Marker=marker) if marker else cloudfront.list_distributions()
            dist_list = (resp.get("DistributionList") or {})
            items = dist_list.get("Items") or []
            dists.extend(items)
            if not dist_list.get("IsTruncated"):
                break
            marker = dist_list.get("NextMarker")
    except ClientError as exc:
        log.error("[check_cloudfront_distributions] list_distributions failed: %s", exc)
        return  # skip gracefully

    # Queue CloudWatch queries per distribution (Requests & BytesDownloaded)
    id_map: Dict[str, Dict[str, str]] = {}
    for d in dists:
        dist_id = d.get("Id")
        if not dist_id:
            continue
        req_id = f"req_{dist_id}"
        bytes_id = f"bytes_{dist_id}"
        dims = [("DistributionId", dist_id), ("Region", "Global")]

        cw_batch.add_q(
            id_hint=req_id,
            namespace="AWS/CloudFront",
            metric="Requests",
            dims=dims,
            stat="Sum",
            period=period,
        )
        cw_batch.add_q(
            id_hint=bytes_id,
            namespace="AWS/CloudFront",
            metric="BytesDownloaded",
            dims=dims,
            stat="Sum",
            period=period,
        )
        id_map[dist_id] = {"req": req_id, "bytes": bytes_id}

    # Execute metrics (best-effort)
    metrics_ok = True
    results: Dict[str, Any] = {}
    try:
        results = cw_batch.execute(start=start_time, end=now_utc)
    except ClientError as exc:
        log.warning("[cloudfront metrics] GetMetricData failed: %s", exc)
        metrics_ok = False
    except Exception as exc:  # pylint: disable=broad-except
        log.warning("[cloudfront metrics] batch error: %s", exc)
        metrics_ok = False

    # Pricing (heuristic)
    price_req_1m = config.safe_price("CloudFront", "REQUESTS_1M", default=0.0)
    price_gb_out = config.safe_price("CloudFront", "DATA_OUT_GB", default=0.0)

    # Emit rows
    for d in dists:
        dist_id = d.get("Id")
        if not dist_id:
            continue

        domain = d.get("DomainName") or ""
        enabled = bool(d.get("Enabled"))
        status = d.get("Status") or ""
        last_mod = d.get("LastModifiedTime")
        price_class = d.get("PriceClass") or ""
        web_acl_id = d.get("WebACLId") or ""
        staging = d.get("Staging")

        # Logging (best-effort; don't fail if API denies)
        logging_enabled = _get_logging_enabled(cloudfront, dist_id, log)

        # Metrics reduction
        requests_sum = 0.0
        bytes_sum = 0.0
        if metrics_ok:
            ids = id_map.get(dist_id, {})
            req_series = results.get(ids.get("req"))
            bytes_series = results.get(ids.get("bytes"))
            requests_sum = _sum_from_result(req_series)
            bytes_sum = _sum_from_result(bytes_series)

        # Costs
        est_requests_cost = (requests_sum / 1_000_000.0) * price_req_1m
        est_data_cost = (bytes_sum / (1024.0 ** 3)) * price_gb_out
        estimated_cost = est_requests_cost + est_data_cost

        # Flags
        flags: List[str] = []
        if not enabled:
            flags.append("CloudFrontDistributionDisabled")
        # Only assert unused when metrics were actually available
        if metrics_ok and requests_sum <= 0.0 and bytes_sum <= 0.0:
            flags.append("CloudFrontDistributionUnused")
        if logging_enabled is False:
            flags.append("CloudFrontNoAccessLogs")

        if not flags:
            log.info(
                "[check_cloudfront_distributions] Processed: %s (enabled=%s req=%s bytes=%s)",
                dist_id,
                enabled,
                int(requests_sum),
                int(bytes_sum),
            )
            continue

        # Potential saving: only when flagged unused (otherwise 0.0)
        potential_saving = estimated_cost if "CloudFrontDistributionUnused" in flags else 0.0

        signals = _signals_str(
            {
                "Id": dist_id,
                "DomainName": domain,
                "Enabled": enabled,
                "Status": status,
                "LastModified": _to_utc_iso(last_mod) if isinstance(last_mod, datetime) else last_mod,
                "PriceClass": price_class,
                "WebACLId": web_acl_id,
                "Staging": staging,
                "LoggingEnabled": logging_enabled,
                "RequestsSum": int(requests_sum),
                "BytesDownloadedSum": int(bytes_sum),
                "LookbackDays": lookback_days,
                "MetricsAvailable": metrics_ok,
                "Region": "Global",
            }
        )

        try:
            # type: ignore[call-arg]  (WRITE_ROW injected at runtime)
            config.WRITE_ROW(
                writer=writer,
                resource_id=dist_id,
                name=domain or dist_id,
                owner_id=config.ACCOUNT_ID,  # type: ignore[arg-type]
                resource_type="CloudFrontDistribution",
                estimated_cost=estimated_cost,
                potential_saving=potential_saving,
                flags=flags,
                confidence=100,
                signals=signals,
            )
        except Exception as exc:  # pylint: disable=broad-except
            log.warning("[check_cloudfront_distributions] write_row failed for %s: %s", dist_id, exc)

        log.info(
            "[check_cloudfront_distributions] Wrote: %s (flags=%s est=%.4f save=%.4f)",
            dist_id,
            flags,
            estimated_cost,
            potential_saving,
        )
