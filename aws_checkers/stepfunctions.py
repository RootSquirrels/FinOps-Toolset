"""Checkers: AWS Step Functions (Standard vs Express mismatch)."""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Sequence, Tuple

from botocore.client import BaseClient
from botocore.exceptions import ClientError

from aws_checkers.common import _logger, _signals_str, _to_utc_iso
from aws_checkers import config as chk
from finops_toolset import config as const
from core.retry import retry_with_backoff
from core.cloudwatch import CloudWatchBatcher


# ---------------------------------------------------------------------------
# Extractors
# ---------------------------------------------------------------------------

def _extract_writer_cw_client(
    args: Tuple[Any, ...], kwargs: Dict[str, Any]
) -> Tuple[Any, BaseClient, BaseClient]:
    """Extract (writer, cloudwatch, stepfunctions) from args/kwargs; raise if missing."""
    writer = kwargs.get("writer", args[0] if len(args) >= 1 else None)
    cloudwatch = kwargs.get("cloudwatch", args[1] if len(args) >= 2 else None)
    sfn = kwargs.get("client", args[2] if len(args) >= 3 else None)
    if writer is None or cloudwatch is None or sfn is None:
        raise TypeError("Expected 'writer', 'cloudwatch' and 'client'")
    return writer, cloudwatch, sfn


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _paginate(
    fn, page_items_key: str, token_key: str, **kwargs: Any
) -> List[Dict[str, Any]]:
    """Generic paginator for list APIs that return a next token."""
    out: List[Dict[str, Any]] = []
    token: Optional[str] = None
    while True:
        params = dict(kwargs)
        if token:
            params[token_key] = token
        page = fn(**params)
        items = page.get(page_items_key, []) or []
        out.extend(items)
        token = page.get(token_key)
        if not token:
            break
    return out


def _sum_series(points: Sequence[Tuple[datetime, float]]) -> float:
    """Sum values in a (ts, value) time series."""
    return float(sum(float(v) for _, v in (points or [])))


def _avg_series(points: Sequence[Tuple[datetime, float]]) -> float:
    """Average values in a (ts, value) time series."""
    vals = [float(v) for _, v in (points or [])]
    return float(sum(vals) / len(vals)) if vals else 0.0


def _scale_to_month(start: datetime, end: datetime) -> float:
    """Return multiplicative factor to scale a window to one month of hours."""
    hours_window = max(1.0, (end - start).total_seconds() / 3600.0)
    hours_month = float(getattr(const, "HOURS_PER_MONTH", 730))
    return hours_month / hours_window


def _price(service: str, key: str, default: float = 0.0) -> float:
    """Resolve a price via chk.safe_price(service, key, default)."""
    try:
        return float(chk.safe_price(service, key, default))  # type: ignore[arg-type]
    except Exception:  # pylint: disable=broad-except
        return float(default)


def _standard_monthly_cost(
    monthly_executions: float,
    states_per_execution: float,
    price_per_1k_states: float,
) -> float:
    """Estimated Standard monthly cost from executions and avg states per exec."""
    transitions = float(monthly_executions) * float(states_per_execution)
    return (transitions / 1000.0) * float(price_per_1k_states)


def _express_monthly_cost(
    monthly_executions: float,
    avg_duration_ms: float,
    payload_kb: float,
    req_price_per_1m: float,
    dur_price_gb_s: float,
) -> float:
    """Estimated Express monthly cost from executions, average duration and payload."""
    reqs_cost = (float(monthly_executions) / 1_000_000.0) * float(req_price_per_1m)
    duration_s = max(0.0, float(avg_duration_ms) / 1000.0)
    payload_gb = max(0.0, float(payload_kb) / (1024.0 * 1024.0))
    gb_seconds = float(monthly_executions) * duration_s * payload_gb
    dur_cost = gb_seconds * float(dur_price_gb_s)
    return reqs_cost + dur_cost


# ---------------------------------------------------------------------------
# Checker
# ---------------------------------------------------------------------------

@retry_with_backoff(exceptions=(ClientError,))
def check_sfn_standard_vs_express_mismatch(  # noqa: D401
    region: str,
    *args: Any,
    logger: Optional[logging.Logger] = None,
    lookback_days: int = 14,
    states_per_execution: float = 5.0,
    assumed_payload_kb: float = 64.0,
    min_monthly_execs: int = 1_000,
    **kwargs: Any,
) -> List[Dict[str, Any]]:
    """Flag Standard state machines that would be cheaper on Express.

    We estimate monthly volumes by scaling the CloudWatch lookback window to a month.
    Standard is modeled as per-state-transition (avg states per execution).
    Express is modeled as per-request + GB-second of payload-duration.

    Signals: executions_sum, avg_duration_ms, payload_kb
    Pricing: SFN/STANDARD_REQUEST_1K, SFN/EXPRESS_REQUEST_1M, SFN/EXPRESS_DUR_GB_SECOND
    """
    log = _logger(kwargs.get("logger") or logger)

    try:
        writer, cloudwatch, sfn = _extract_writer_cw_client(args, kwargs)
    except TypeError as exc:
        log.warning("[check_sfn_standard_vs_express_mismatch] Skipping: %s", exc)
        return []

    owner = str(kwargs.get("account_id") or chk.ACCOUNT_ID or "")
    if not (owner and chk.WRITE_ROW):
        log.warning("[check_sfn_standard_vs_express_mismatch] Skipping: missing config.")
        return []

    # Price rates
    p_std_1k = _price("SFN", "STANDARD_REQUEST_1K", 0.025)
    p_exp_1m = _price("SFN", "EXPRESS_REQUEST_1M", 1.00)
    p_exp_gbs = _price("SFN", "EXPRESS_DUR_GB_SECOND", 0.00001667)

    # Enumerate state machines
    sms = _paginate(
        sfn.list_state_machines, page_items_key="stateMachines", token_key="nextToken"
    )
    if not sms:
        return []

    # Prepare metrics batch
    start = datetime.now(timezone.utc) - timedelta(days=lookback_days)
    end = datetime.now(timezone.utc)
    scale = _scale_to_month(start, end)

    batch = CloudWatchBatcher(region, client=cloudwatch)
    items: List[Tuple[str, str, str, datetime]] = []

    for idx, sm in enumerate(sms):
        arn = str(sm.get("stateMachineArn") or "")
        name = str(sm.get("name") or arn)
        sm_type = str(sm.get("type") or "STANDARD").upper()
        created = sm.get("creationDate")
        created_iso = _to_utc_iso(created)

        # Only evaluate Standard state machines for migration
        if sm_type != "STANDARD":
            continue

        dims = [{"Name": "StateMachineArn", "Value": arn}]
        # ExecutionsStarted (Sum)
        batch.add_q(
            id_hint=f"exec_{idx}",
            namespace="AWS/States",
            metric="ExecutionsStarted",
            dims=dims,
            stat="Sum",
            period=3600,
        )
        # ExecutionTime (Average, ms)
        batch.add_q(
            id_hint=f"dur_{idx}",
            namespace="AWS/States",
            metric="ExecutionTime",
            dims=dims,
            stat="Average",
            period=3600,
        )

        items.append((arn, name, created_iso, sm_type))

    if not items:
        return []

    series = batch.execute(start, end)

    rows: List[Dict[str, Any]] = []
    for idx, (arn, name, created_iso, sm_type) in enumerate(items):
        exec_sum = _sum_series(series.get(f"exec_{idx}", []))
        dur_avg_ms = _avg_series(series.get(f"dur_{idx}", []))
        monthly_execs = exec_sum * scale

        # Skip low-volume workloads to avoid noise
        if monthly_execs < float(min_monthly_execs):
            continue

        # Estimate costs
        std_cost = _standard_monthly_cost(monthly_execs, states_per_execution, p_std_1k)
        exp_cost = _express_monthly_cost(
            monthly_execs, dur_avg_ms, assumed_payload_kb, p_exp_1m, p_exp_gbs
        )
        saving = max(0.0, std_cost - exp_cost)

        if saving <= 0.0:
            continue

        flags = ["ExpressCheaper"]
        signals = _signals_str(
            {
                "executions_sum": int(exec_sum),
                "avg_duration_ms": round(dur_avg_ms, 1),
                "payload_kb": int(assumed_payload_kb),
                "states_per_exec": round(states_per_execution, 2),
                "std_cost_usd": round(std_cost, 2),
                "exp_cost_usd": round(exp_cost, 2),
            }
        )

        try:
            # type: ignore[call-arg]
            chk.WRITE_ROW(
                writer=writer,
                resource_id=arn,
                name=name,
                owner_id=owner,  # type: ignore[arg-type]
                resource_type="SFNStateMachine",
                region=region,
                state="STANDARD",
                creation_date=created_iso,
                estimated_cost=round(std_cost, 2),
                potential_saving=round(saving, 2),
                flags=flags,
                confidence=75,
                signals=signals,
            )
        except Exception as exc:  # pylint: disable=broad-except
            log.warning("[sfn] write_row mismatch failed for %s: %s", arn, exc)

        rows.append(
            {
                "arn": arn,
                "name": name,
                "monthly_execs": int(monthly_execs),
                "std_cost": std_cost,
                "exp_cost": exp_cost,
                "saving": saving,
            }
        )

    return rows
