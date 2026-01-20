"""Checkers: SageMaker."""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional, Tuple

from botocore.client import BaseClient
from botocore.exceptions import ClientError

from aws_checkers import config
from core.retry import retry_with_backoff
from finops_toolset import config as const


def _logger(fallback: Optional[logging.Logger]) -> logging.Logger:
    """Return a usable logger from fallback or config.LOGGER."""
    return fallback or config.LOGGER or logging.getLogger(__name__)


def _infer_region(client: Optional[BaseClient], kwargs: Dict[str, Any]) -> str:
    """Infer region from kwargs or boto3 client meta; fallback to empty string."""
    kw_region = kwargs.get("region")
    if kw_region:
        return str(kw_region)
    if client is None:
        return ""
    return str(getattr(getattr(client, "meta", None), "region_name", "") or "")


def _extract_writer_client(args: Tuple[Any, ...], kwargs: Dict[str, Any]):
    """Extract (writer, sagemaker_client) from args/kwargs, else raise TypeError.

    Supports:
      - Orchestrator: writer positional args[0], client in kwargs['client']
      - Legacy: client in kwargs['sagemaker'] or positional args[1]
    """
    writer = kwargs.get("writer", args[0] if len(args) >= 1 else None)
    client = kwargs.get("client", kwargs.get("sagemaker", args[1] if len(args) >= 2 else None))
    if writer is None or client is None:
        raise TypeError("Expected 'writer' and SageMaker client as 'client' (or legacy 'sagemaker')")
    return writer, client


def _safe_price(service: str, key: str, default: float = 0.0) -> float:
    """Resolve a price via config.safe_price(service, key, default)."""
    try:
        return float(config.safe_price(service, key, default))  # type: ignore[arg-type]
    except Exception:  # pylint: disable=broad-except
        return float(default)


def _iso(dt: Optional[datetime]) -> str:
    """UTC ISO8601 or empty string."""
    if not dt:
        return ""
    if not dt.tzinfo:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).isoformat()


def _signals(d: Dict[str, Any]) -> str:
    """Render signals as compact 'k=v|k2=v2' string."""
    parts = []
    for k, v in d.items():
        parts.append(f"{k}={v}")
    return "|".join(parts)


@retry_with_backoff(exceptions=(ClientError,))
def check_sagemaker_idle_notebooks(  # noqa: D401
    *args,
    logger: Optional[logging.Logger] = None,
    lookback_days: int = 14,
    idle_grace_hours: int = 12,
    **kwargs,
) -> None:
    """Flag SageMaker Notebook Instances that are InService but likely unused.

    Heuristic:
      - Instance status is 'InService'
      - LastModifiedTime is older than `lookback_days` (plus `idle_grace_hours`)
    Potential saving ~= (instance_hourly * HOURS_PER_MONTH).
    """
    log = _logger(kwargs.get("logger") or logger)
    try:
        writer, sm = _extract_writer_client(args, kwargs)
    except TypeError as exc:
        log.warning("[check_sagemaker_idle_notebooks] Skipping: %s", exc)
        return
    if not (config.ACCOUNT_ID and config.WRITE_ROW):
        log.warning("[check_sagemaker_idle_notebooks] Skipping: checker config not provided.")
        return

    region = _infer_region(sm, kwargs)
    cutoff = datetime.now(timezone.utc) - timedelta(days=lookback_days, hours=idle_grace_hours)
    next_token: Optional[str] = None

    while True:
        try:
            page = (
                sm.list_notebook_instances(NextToken=next_token)
                if next_token
                else sm.list_notebook_instances()
            )
        except ClientError as exc:
            log.warning(
                "[check_sagemaker_idle_notebooks] list_notebook_instances failed: %s",
                exc,
            )
            return

        for item in page.get("NotebookInstances", []) or []:
            status = item.get("NotebookInstanceStatus", "")
            if status != "InService":
                continue

            name = item.get("NotebookInstanceName", "")
            arn = item.get("NotebookInstanceArn", name)
            inst_type = item.get("InstanceType", "")
            mod_time = item.get("LastModifiedTime") or item.get("CreationTime")
            last_mod = mod_time if isinstance(mod_time, datetime) else None

            hourly = _safe_price("SAGEMAKER", f"NOTEBOOK_HR.{inst_type}", 0.0)
            monthly = hourly * const.HOURS_PER_MONTH if hourly > 0.0 else 0.0
            idle = bool(last_mod and last_mod < cutoff)

            potential = monthly if idle else 0.0
            flags = []
            if idle:
                flags.append("Idle")
            if status:
                flags.append(f"Status={status}")

            try:
                # type: ignore[call-arg]
                config.WRITE_ROW(
                    writer=writer,
                    resource_id=arn,
                    name=name,
                    owner_id=config.ACCOUNT_ID,  # type: ignore[arg-type]
                    resource_type="SageMakerNotebook",
                    region=region,
                    state=status,
                    creation_date=_iso(item.get("CreationTime")),
                    estimated_cost=round(monthly, 2),
                    potential_saving=round(potential, 2) if potential else None,
                    flags=flags,
                    confidence=85 if idle else 60,
                    signals=_signals(
                        {
                            "instance_type": inst_type,
                            "last_modified": _iso(last_mod),
                        }
                    ),
                )
            except Exception as exc:  # pylint: disable=broad-except
                log.warning("[sagemaker] write_row(notebook) failed: %s", exc)

        next_token = page.get("NextToken")
        if not next_token:
            break


def _sum_endpoint_invocations(
    cw_client: Any,
    endpoint_name: str,
    start: datetime,
    end: datetime,
) -> float:
    """Return total 'Invocations' over the window for an endpoint (best-effort)."""
    if not cw_client:
        return 0.0
    try:
        stats = cw_client.get_metric_statistics(
            Namespace="AWS/SageMaker",
            MetricName="Invocations",
            Dimensions=[{"Name": "EndpointName", "Value": endpoint_name}],
            StartTime=start,
            EndTime=end,
            Period=3600,
            Statistics=["Sum"],
        )
        total = 0.0
        for dp in stats.get("Datapoints", []) or []:
            total += float(dp.get("Sum") or 0.0)
        return total
    except ClientError:
        return 0.0


@retry_with_backoff(exceptions=(ClientError,))
def check_sagemaker_idle_endpoints(  # noqa: D401
    *args,
    logger: Optional[logging.Logger] = None,
    lookback_days: int = 14,
    invocation_threshold: float = 5.0,
    **kwargs,
) -> None:
    """Flag SageMaker endpoints with near-zero Invocations over the lookback window.

    Savings ~= sum(variant.instance_count * hourly(instance_type)) * HOURS_PER_MONTH.
    """
    log = _logger(kwargs.get("logger") or logger)
    try:
        writer, sm = _extract_writer_client(args, kwargs)
    except TypeError as exc:
        log.warning("[check_sagemaker_idle_endpoints] Skipping: %s", exc)
        return
    if not (config.ACCOUNT_ID and config.WRITE_ROW):
        log.warning("[check_sagemaker_idle_endpoints] Skipping: checker config not provided.")
        return

    region = _infer_region(sm, kwargs)
    cw = kwargs.get("cloudwatch")
    start = datetime.now(timezone.utc) - timedelta(days=lookback_days)
    end = datetime.now(timezone.utc)
    next_token: Optional[str] = None

    while True:
        try:
            page = sm.list_endpoints(NextToken=next_token) if next_token else sm.list_endpoints()
        except ClientError as exc:
            log.warning("[check_sagemaker_idle_endpoints] list_endpoints failed: %s", exc)
            return

        for ep in page.get("Endpoints", []) or []:
            name = ep.get("EndpointName", "")
            arn = ep.get("EndpointArn", name)
            status = ep.get("EndpointStatus", "")
            if status != "InService":
                continue

            try:
                desc = sm.describe_endpoint(EndpointName=name)
            except ClientError:
                continue

            variants = desc.get("ProductionVariants", []) or []
            invocations = _sum_endpoint_invocations(cw, name, start, end)

            total_hourly = 0.0
            for v in variants:
                v_type = v.get("InstanceType", "")
                v_count = int(v.get("InitialInstanceCount", 0) or 0)
                hourly = _safe_price("SAGEMAKER", f"ENDPOINT_HOUR.{v_type}", 0.0)
                total_hourly += hourly * float(max(0, v_count))

            monthly = total_hourly * const.HOURS_PER_MONTH if total_hourly > 0.0 else 0.0
            is_idle = invocations < float(invocation_threshold)
            potential = monthly if is_idle else 0.0

            flags = [f"Status={status}"]
            if is_idle:
                flags.append("Idle")

            try:
                # type: ignore[call-arg]
                config.WRITE_ROW(
                    writer=writer,
                    resource_id=arn,
                    name=name,
                    owner_id=config.ACCOUNT_ID,  # type: ignore[arg-type]
                    resource_type="SageMakerEndpoint",
                    region=region,
                    state=status,
                    creation_date=_iso(ep.get("CreationTime")),
                    estimated_cost=round(monthly, 2),
                    potential_saving=round(potential, 2) if potential else None,
                    flags=flags,
                    confidence=85 if is_idle else 60,
                    signals=_signals(
                        {
                            "invocations_sum": int(invocations),
                            "variants": len(variants),
                            "hourly_total": round(total_hourly, 4),
                        }
                    ),
                )
            except Exception as exc:  # pylint: disable=broad-except
                log.warning("[sagemaker] write_row(endpoint) failed: %s", exc)

        next_token = page.get("NextToken")
        if not next_token:
            break


@retry_with_backoff(exceptions=(ClientError,))
def check_sagemaker_studio_zombies(  # noqa: D401
    *args,
    logger: Optional[logging.Logger] = None,
    lookback_days: int = 7,
    **kwargs,
) -> None:
    """Flag SageMaker Studio apps that have been left running for days."""
    log = _logger(kwargs.get("logger") or logger)
    try:
        writer, sm = _extract_writer_client(args, kwargs)
    except TypeError as exc:
        log.warning("[check_sagemaker_studio_zombies] Skipping: %s", exc)
        return
    if not (config.ACCOUNT_ID and config.WRITE_ROW):
        log.warning("[check_sagemaker_studio_zombies] Skipping: checker config not provided.")
        return

    region = _infer_region(sm, kwargs)
    cutoff = datetime.now(timezone.utc) - timedelta(days=lookback_days)
    next_token: Optional[str] = None
    price_app_hr = _safe_price("SAGEMAKER", "STUDIO_APP_HOUR", 0.0)
    monthly = price_app_hr * const.HOURS_PER_MONTH if price_app_hr > 0.0 else 0.0

    while True:
        try:
            page = sm.list_apps(NextToken=next_token) if next_token else sm.list_apps()
        except ClientError as exc:
            log.warning("[check_sagemaker_studio_zombies] list_apps failed: %s", exc)
            return

        for app in page.get("Apps", []) or []:
            status = app.get("Status", "")
            if status not in {"InService", "Pending"}:
                continue

            created = app.get("CreationTime")
            created_dt = created if isinstance(created, datetime) else None
            stale = bool(created_dt and created_dt < cutoff)
            if not stale and status != "InService":
                continue

            app_name = app.get("AppName", "")
            app_type = app.get("AppType", "")
            arn = app.get("AppArn", app_name)

            potential = monthly if monthly > 0.0 else None
            flags = ["StudioApp", f"Status={status}"]
            if stale:
                flags.append("Stale")

            try:
                # type: ignore[call-arg]
                config.WRITE_ROW(
                    writer=writer,
                    resource_id=arn,
                    name=app_name,
                    owner_id=config.ACCOUNT_ID,  # type: ignore[arg-type]
                    resource_type="SageMakerStudioApp",
                    region=region,
                    state=status,
                    creation_date=_iso(created_dt),
                    estimated_cost=round(monthly, 2) if monthly else 0.0,
                    potential_saving=round(potential, 2) if potential else None,
                    flags=flags,
                    confidence=75 if stale else 60,
                    signals=_signals(
                        {
                            "app_type": app_type,
                            "created": _iso(created_dt),
                            "price_hr": round(price_app_hr, 4),
                        }
                    ),
                )
            except Exception as exc:  # pylint: disable=broad-except
                log.warning("[sagemaker] write_row(studio) failed: %s", exc)

        next_token = page.get("NextToken")
        if not next_token:
            break
