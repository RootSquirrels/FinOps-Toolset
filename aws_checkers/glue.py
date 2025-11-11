"""Checkers: AWS Glue (idle dev endpoints, zombie crawlers)."""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Iterable, List, Optional, Tuple

from botocore.client import BaseClient
from botocore.exceptions import ClientError

from aws_checkers.common import _logger, _signals_str, _to_utc_iso
from aws_checkers import config as chk
from finops_toolset import config as const
from core.retry import retry_with_backoff


# ---------------------------------------------------------------------------
# Extractors
# ---------------------------------------------------------------------------

def _extract_writer_client(
    args: Tuple[Any, ...], kwargs: Dict[str, Any]
) -> Tuple[Any, BaseClient]:
    """Extract (writer, client) from args/kwargs; raise if missing."""
    writer = kwargs.get("writer", args[0] if len(args) >= 1 else None)
    client = kwargs.get("client", args[1] if len(args) >= 2 else None)
    if writer is None or client is None:
        raise TypeError("Expected 'writer' and 'client'")
    return writer, client


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _paginate(fn, page_key: str, token_key: str, **kwargs: Any) -> Iterable[Dict[str, Any]]:
    """Generic paginator for list/describe APIs with NextToken/Marker."""
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


def _price_dpu_hour() -> float:
    """Return Glue DPU hourly price."""
    try:
        return float(chk.safe_price("GLUE", "DPU_HOUR", 0.0))  # type: ignore[arg-type]
    except Exception:  # pylint: disable=broad-except
        return 0.0


def _estimate_endpoint_dpus(ep: Dict[str, Any]) -> float:
    """Best-effort DPUs for a dev endpoint based on worker shape."""
    # Dev endpoints may expose NumberOfWorkers+WorkerType (Glue 2.0/3.0) or NumberOfNodes
    n_workers = ep.get("NumberOfWorkers")
    worker_type = str(ep.get("WorkerType") or "")
    n_nodes = ep.get("NumberOfNodes")

    if isinstance(n_workers, int) and n_workers > 0:
        per = {"G.1X": 1.0, "G.2X": 2.0, "STANDARD": 2.0, "Standard": 2.0}
        return float(n_workers) * float(per.get(worker_type, 1.0))

    if isinstance(n_nodes, int) and n_nodes > 0:
        # Legacy shape — assume ~1 DPU/node (conservative)
        return float(n_nodes)

    return 1.0  # fallback minimal billing unit


def _now_utc() -> datetime:
    """Return timezone-aware now in UTC."""
    return datetime.now(timezone.utc)


def _max_dt(a: Optional[datetime], b: Optional[datetime]) -> Optional[datetime]:
    """Return the max datetime with tz-awareness preserved."""
    if a is None:
        return b
    if b is None:
        return a
    if a.tzinfo is None:
        a = a.replace(tzinfo=timezone.utc)
    if b.tzinfo is None:
        b = b.replace(tzinfo=timezone.utc)
    return a if a >= b else b


def _latest_job_run_time(glue: BaseClient) -> Optional[datetime]:
    """Return the latest job run start/stop time across all jobs (or None)."""
    latest: Optional[datetime] = None
    try:
        # names
        names: List[str] = []
        for page in _paginate(glue.list_jobs, page_key="JobNames", token_key="NextToken"):
            names.extend(page if isinstance(page, list) else [page])

        # quick probe: fetch only 1 most recent run per job
        for name in names:
            try:
                runs = glue.get_job_runs(JobName=name, MaxResults=1).get("JobRuns", [])
            except ClientError:
                continue
            if not runs:
                continue
            jr = runs[0]
            latest = _max_dt(latest, jr.get("CompletedOn") or jr.get("StartedOn"))
    except Exception:  # pylint: disable=broad-except
        return latest
    return latest


def _list_dev_endpoints(glue: BaseClient) -> List[Dict[str, Any]]:
    """List dev endpoints (prefers 'get_dev_endpoints', falls back to names)."""
    # Preferred: get_dev_endpoints (already returns endpoint dicts)
    try:
        out: List[Dict[str, Any]] = []
        for ep in _paginate(glue.get_dev_endpoints,
                            page_key="DevEndpoints", token_key="NextToken"):
            out.append(ep)
        if out:
            return out
    except Exception:  # pylint: disable=broad-except
        pass

    # Fallback: list names then get each endpoint
    eps: List[Dict[str, Any]] = []
    try:
        names: List[str] = []
        for page in _paginate(glue.list_dev_endpoints,
                              page_key="DevEndpointNames", token_key="NextToken"):
            names.extend(page if isinstance(page, list) else [page])
        for n in names:
            try:
                ep = glue.get_dev_endpoint(EndpointName=n).get("DevEndpoint", {})  # type: ignore[call-arg]
                if ep:
                    eps.append(ep)
            except ClientError:
                continue
    except Exception:  # pylint: disable=broad-except
        return eps

    return eps


def _list_crawlers(glue: BaseClient) -> List[str]:
    """Return crawler names (lightweight)."""
    names: List[str] = []
    for page in _paginate(glue.list_crawlers, page_key="CrawlerNames", token_key="NextToken"):
        names.extend(page if isinstance(page, list) else [page])
    return names


def _get_crawlers(glue: BaseClient, names: List[str]) -> List[Dict[str, Any]]:
    """Return crawler objects in small batches (DescribeCrawlers caps)."""
    out: List[Dict[str, Any]] = []
    step = 25
    for i in range(0, len(names), step):
        batch = names[i : i + step]
        try:
            resp = glue.batch_get_crawlers(CrawlerNames=batch)  # type: ignore[call-arg]
            out.extend(resp.get("Crawlers", []) or [])
        except ClientError:
            continue
    return out


def _get_crawler_metrics(glue: BaseClient, names: List[str]) -> Dict[str, Dict[str, Any]]:
    """Return crawler metrics (LastStartTime, etc.) as dict by name."""
    step = 50
    metrics: Dict[str, Dict[str, Any]] = {}
    for i in range(0, len(names), step):
        batch = names[i : i + step]
        try:
            resp = glue.get_crawler_metrics(CrawlerNameList=batch)  # type: ignore[call-arg]
        except ClientError:
            continue
        for m in resp.get("CrawlerMetricsList", []) or []:
            nm = m.get("CrawlerName")
            if nm:
                metrics[str(nm)] = m
    return metrics


# ---------------------------------------------------------------------------
# Check 1: Idle dev endpoints (no job activity for N days, but endpoint READY)
# ---------------------------------------------------------------------------

@retry_with_backoff(exceptions=(ClientError,))
def check_glue_idle_dev_endpoints(  # noqa: D401
    region: str,
    *args: Any,
    logger: Optional[logging.Logger] = None,
    lookback_days: int = 14,
    **kwargs: Any,
) -> List[Dict[str, Any]]:
    """Flag dev endpoints running while there is no job activity for N days.

    Potential saving: dpus * DPU_HOUR * HOURS_PER_MONTH (conservative).
    """
    log = _logger(kwargs.get("logger") or logger)

    try:
        writer, glue = _extract_writer_client(args, kwargs)
    except TypeError as exc:
        log.warning("[check_glue_idle_dev_endpoints] Skipping: %s", exc)
        return []

    owner = str(kwargs.get("account_id") or chk.ACCOUNT_ID or "")
    if not (owner and chk.WRITE_ROW):
        log.warning("[check_glue_idle_dev_endpoints] Skipping: missing config.")
        return []

    endpoints = _list_dev_endpoints(glue)
    if not endpoints:
        return []

    # Determine latest job run across account; if stale, endpoints should be torn down
    latest_job = _latest_job_run_time(glue)
    cutoff = _now_utc() - timedelta(days=int(lookback_days))
    no_recent_jobs = latest_job is None or latest_job < cutoff

    dpu_hour = _price_dpu_hour()
    hours = float(getattr(const, "HOURS_PER_MONTH", 730))

    rows: List[Dict[str, Any]] = []
    for ep in endpoints:
        status = str(ep.get("Status") or "").upper()
        name = str(ep.get("EndpointName") or ep.get("Name") or "dev-endpoint")
        arn = str(ep.get("EndpointArn") or name)

        # Only endpoints actively incurring hourly costs
        if status not in {"READY", "PROVISIONING"}:
            continue

        dpus = _estimate_endpoint_dpus(ep)
        monthly = dpus * dpu_hour * hours if dpu_hour > 0.0 else 0.0

        # Flag only when org activity is stale
        if not no_recent_jobs:
            continue

        flags = ["IdleDevEndpoint"]
        created_iso = _to_utc_iso(ep.get("CreatedTimestamp") or ep.get("LastModifiedTimestamp"))
        signals = _signals_str(
            {
                "endpoint_status": status,
                "dpus": round(dpus, 2),
                "dpu_hour": round(dpu_hour, 4),
                "last_job_run": _to_utc_iso(latest_job),
            }
        )

        try:
            # type: ignore[call-arg]
            chk.WRITE_ROW(
                writer=writer,
                resource_id=arn,
                name=name,
                owner_id=owner,  # type: ignore[arg-type]
                resource_type="GlueDevEndpoint",
                region=region,
                state=status,
                creation_date=created_iso,
                estimated_cost=round(monthly, 2) if monthly else 0.0,
                potential_saving=round(monthly, 2) if monthly > 0.0 else None,
                flags=flags,
                confidence=80,
                signals=signals,
            )
        except Exception as exc:  # pylint: disable=broad-except
            log.warning("[glue] write_row(dev-endpoint) failed: %s", exc)

        rows.append({"name": name, "potential": monthly})

    return rows


# ---------------------------------------------------------------------------
# Check 2: Zombie crawlers (scheduled but haven’t run for N days)
# ---------------------------------------------------------------------------

@retry_with_backoff(exceptions=(ClientError,))
def check_glue_zombie_crawlers(  # noqa: D401
    region: str,
    *args: Any,
    logger: Optional[logging.Logger] = None,
    older_than_days: int = 30,
    **kwargs: Any,
) -> List[Dict[str, Any]]:
    """Flag crawlers that still have a schedule but haven’t run for N days.

    Potential saving: typically None (runs incur cost; idle scheduled does not),
    but eliminating schedules reduces accidental/forgotten runs.
    """
    log = _logger(kwargs.get("logger") or logger)

    try:
        writer, glue = _extract_writer_client(args, kwargs)
    except TypeError as exc:
        log.warning("[check_glue_zombie_crawlers] Skipping: %s", exc)
        return []

    owner = str(kwargs.get("account_id") or chk.ACCOUNT_ID or "")
    if not (owner and chk.WRITE_ROW):
        log.warning("[check_glue_zombie_crawlers] Skipping: missing config.")
        return []

    names = _list_crawlers(glue)
    if not names:
        return []

    crawlers = _get_crawlers(glue, names)
    metrics_by_name = _get_crawler_metrics(glue, names)

    cutoff = _now_utc() - timedelta(days=int(older_than_days))
    rows: List[Dict[str, Any]] = []

    for c in crawlers:
        name = str(c.get("Name") or "crawler")
        arn = str(c.get("CrawlerArn") or name)
        sched = c.get("Schedule") or {}
        sched_expr = sched.get("ScheduleExpression") or ""
        has_schedule = bool(sched_expr)

        if not has_schedule:
            continue

        # Derive last start time from metrics (prefer), else from crawler LastCrawl
        m = metrics_by_name.get(name, {})
        last_start = m.get("LastStartTime")
        if not last_start:
            last_crawl = c.get("LastCrawl") or {}
            last_start = last_crawl.get("StartTime")

        if isinstance(last_start, datetime):
            if last_start.tzinfo is None:
                last_start = last_start.replace(tzinfo=timezone.utc)
        else:
            last_start = None

        if last_start is not None and last_start >= cutoff:
            continue  # recently active; skip

        flags = ["ZombieCrawler"]
        created_iso = _to_utc_iso(c.get("CreationTime"))
        signals = _signals_str(
            {
                "schedule": sched_expr,
                "last_start": _to_utc_iso(last_start),
                "state": str(c.get("State") or "Unknown"),
            }
        )

        try:
            # type: ignore[call-arg]
            chk.WRITE_ROW(
                writer=writer,
                resource_id=arn,
                name=name,
                owner_id=owner,  # type: ignore[arg-type]
                resource_type="GlueCrawler",
                region=region,
                state=str(c.get("State") or "Unknown"),
                creation_date=created_iso,
                estimated_cost="",
                potential_saving=None,
                flags=flags,
                confidence=70,
                signals=signals,
            )
        except Exception as exc:  # pylint: disable=broad-except
            log.warning("[glue] write_row(crawler) failed: %s", exc)

        rows.append({"name": name, "potential": 0.0})

    return rows
