"""Checkers: AWS Commitments (Savings Plans + Reserved Instances).

This checker surfaces *purchase recommendations* from AWS Cost Explorer:
  - Savings Plans (Compute + EC2 Instance)
  - Reserved Instances (EC2, RDS, Redshift)

Output rows are account-level recommendations (not per-resource) and are
written once per scan to avoid duplicates across regional orchestrator loops.

"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from botocore.exceptions import ClientError

from aws_checkers import config
from aws_checkers.common import _logger, _signals_str
from core.retry import retry_with_backoff


# ------------------------------- extractors -------------------------------- #


def _extract_writer_ce(
    args: Tuple[Any, ...],
    kwargs: Dict[str, Any],
) -> Tuple[Any, Any]:
    """Extract (writer, costexplorer) from args/kwargs; raise if missing."""
    writer = kwargs.get("writer", args[0] if len(args) >= 1 else None)
    ce = (
        kwargs.get("costexplorer")
        or kwargs.get("ce")
        or kwargs.get("cost_explorer")
        or (args[1] if len(args) >= 2 else None)
    )
    if writer is None or ce is None:
        raise TypeError(
            "Expected 'writer' and 'costexplorer' "
            f"(got writer={writer!r}, costexplorer={ce!r})"
        )
    return writer, ce


def _writer_stream_id(writer: Any) -> int:
    """Best-effort stable identity for the underlying output stream."""
    for attr in ("f", "fp", "stream", "file", "buffer", "raw"):
        stream = getattr(writer, attr, None)
        if stream is not None:
            return id(stream)
    inner = getattr(writer, "writer", None)
    if inner is not None:
        for attr in ("f", "fp", "stream", "file", "buffer", "raw"):
            stream = getattr(inner, attr, None)
            if stream is not None:
                return id(stream)
        return id(inner)
    return id(writer)


# ------------------------------- formatting -------------------------------- #


def _to_float(val: Any) -> float:
    """Best-effort float conversion (handles strings, None, decimals)."""
    try:
        if val is None:
            return 0.0
        return float(val)
    except Exception:  # pylint: disable=broad-except
        return 0.0


def _pick_currency(amount: Any) -> str:
    """Return currency code if present; otherwise empty."""
    if isinstance(amount, dict):
        cur = amount.get("Unit") or amount.get("CurrencyCode")
        return str(cur) if cur else ""
    return ""


def _amount_value(amount: Any) -> float:
    """Return numeric value from Cost Explorer Amount-like structures."""
    if isinstance(amount, dict):
        return _to_float(amount.get("Amount") or amount.get("Value") or 0.0)
    return _to_float(amount)


def _maybe_list(val: Any) -> List[Any]:
    """Normalize a value into a list."""
    return list(val) if isinstance(val, list) else ([] if val is None else [val])


def _lookback_enum(days: int) -> str:
    """Map a day count to Cost Explorer LookbackPeriodInDays enum."""
    d = int(days)
    if d <= 7:
        return "SEVEN_DAYS"
    if d <= 30:
        return "THIRTY_DAYS"
    return "SIXTY_DAYS"


def _term_enum(years: int) -> str:
    """Map a year count to Cost Explorer term enum."""
    return "ONE_YEAR" if int(years) <= 1 else "THREE_YEARS"


# ----------------------------- API call helpers ---------------------------- #


def _ce_call(log: logging.Logger, fn, **kwargs) -> Optional[Dict[str, Any]]:
    """Call Cost Explorer and return dict response, logging errors."""
    try:
        resp = fn(**kwargs)
        return dict(resp) if resp else {}
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code", "")
        # AccessDenied is common if CE is not enabled/allowed.
        log.debug("[commitments] Cost Explorer call failed (%s): %s", code, exc)
        return None
    except Exception as exc:  # pylint: disable=broad-except
        log.debug("[commitments] Cost Explorer call error: %s", exc)
        return None


def _extract_sp_recs(resp: Dict[str, Any]) -> Tuple[Dict[str, Any], List[Dict[str, Any]]]:
    """Return (summary, details[]) for Savings Plans recommendation response."""
    root = resp.get("SavingsPlansPurchaseRecommendation") or {}
    summary = root.get("SavingsPlansPurchaseRecommendationSummary") or {}
    details = root.get("SavingsPlansPurchaseRecommendationDetails") or []
    return dict(summary), [dict(d) for d in _maybe_list(details)]


def _extract_ri_recs(resp: Dict[str, Any]) -> Tuple[Dict[str, Any], List[Dict[str, Any]]]:
    """Return (summary, recommendations[]) for RI recommendation response."""
    summary = resp.get("RecommendationSummary") or {}
    recs = resp.get("Recommendations") or []
    return dict(summary), [dict(r) for r in _maybe_list(recs)]


def _top_n_by_monthly_savings(recs: List[Dict[str, Any]], n: int) -> List[Dict[str, Any]]:
    """Pick top-N recommendations by estimated monthly savings (best effort)."""
    def key_fn(r: Dict[str, Any]) -> float:
        # Try a few known shapes
        if "EstimatedMonthlySavingsAmount" in r:
            return _to_float(r.get("EstimatedMonthlySavingsAmount"))
        if "EstimatedMonthlySavings" in r:
            return _amount_value(r.get("EstimatedMonthlySavings"))
        if "MonthlySavings" in r:
            return _amount_value(r.get("MonthlySavings"))
        return 0.0

    return sorted(recs, key=key_fn, reverse=True)[: max(1, int(n))]


def _lookback_enum(days: int) -> str:
    """Map an integer day lookback to Cost Explorer enums."""
    d = int(days)
    if d <= 7:
        return "SEVEN_DAYS"
    if d <= 30:
        return "THIRTY_DAYS"
    return "SIXTY_DAYS"


def _term_enum(years: int) -> str:
    """Map years to Cost Explorer term enums."""
    return "ONE_YEAR" if int(years) <= 1 else "THREE_YEARS"


# ------------------------------ main checker -------------------------------- #


_ALREADY_RAN: set[Tuple[int, str]] = set()


@retry_with_backoff(exceptions=(ClientError,))
def check_commitments_recommendations(  # pylint: disable=unused-argument
    *args: Any,
    logger: Optional[logging.Logger] = None,
    lookback_days: int = 30,
    term_years: int = 1,
    max_rows_per_type: int = 5,
    **kwargs: Any,
) -> None:
    """Emit commitment purchase recommendations from Cost Explorer.

    Writes a small number of account-level rows:
      - Savings Plans: Compute, EC2 Instance
      - Reserved Instances: EC2, RDS, Redshift

    Notes:
      - Cost Explorer is global; the orchestrator may call this per region.
        We guard to write only once per scan/output.
    """
    log = _logger(kwargs.get("logger") or logger)

    try:
        writer, ce = _extract_writer_ce(args, kwargs)
    except TypeError as exc:
        log.warning("[check_commitments_recommendations] Skipping: %s", exc)
        return

    owner = str(kwargs.get("account_id") or config.ACCOUNT_ID or "")
    if not (owner and config.WRITE_ROW):
        log.warning("[check_commitments_recommendations] Skipping: missing config.")
        return

    # Deduplicate across regional runs
    stream_id = _writer_stream_id(writer)
    run_key = (stream_id, owner)
    if run_key in _ALREADY_RAN:
        log.info("[commitments] Skipping duplicate run for account %s", owner)
        return
    _ALREADY_RAN.add(run_key)

    term_opt = _term_enum(term_years)
    lookback_opt = _lookback_enum(lookback_days)
    now_iso = datetime.now(timezone.utc).replace(microsecond=0).isoformat()

    def write_row(
        *,
        rec_type: str,
        rec_id: str,
        name: str,
        est_cost: float,
        saving: float,
        confidence: int,
        signals: Dict[str, Any],
    ) -> None:
        sig = _signals_str(signals)
        try:
            # type: ignore[call-arg]
            config.WRITE_ROW(
                writer=writer,
                resource_id=rec_id,
                name=name,
                owner_id=owner,
                resource_type="CommitmentRecommendation",
                estimated_cost=float(est_cost),
                potential_saving=float(saving),
                flags=[rec_type],
                confidence=int(confidence),
                signals=sig,
            )
        except Exception as exc:  # pylint: disable=broad-except
            log.warning("[commitments] write_row failed for %s: %s", rec_id, exc)

    # ----------------------------- Savings Plans ----------------------------- #

    sp_types = ["COMPUTE_SP", "EC2_INSTANCE_SP"]
    sp_payments = ["NO_UPFRONT", "PARTIAL_UPFRONT", "ALL_UPFRONT"]

    for sp_type in sp_types:
        for payment in sp_payments:
            resp = _ce_call(
                log,
                ce.get_savings_plans_purchase_recommendation,
                SavingsPlansType=sp_type,
                TermInYears=term_opt,
                PaymentOption=payment,
                LookbackPeriodInDays=lookback_opt,
            )
            if not resp:
                continue

            summary, details = _extract_sp_recs(resp)
            cur_spend = _to_float(summary.get("CurrentOnDemandSpend"))
            est_savings = _to_float(summary.get("EstimatedMonthlySavingsAmount"))
            est_savings_pct = _to_float(summary.get("EstimatedSavingsPercentage"))
            currency = _pick_currency(summary.get("EstimatedMonthlySavingsAmount"))

            # If the API returns no summary savings, try to infer from details.
            if est_savings <= 0.0 and details:
                est_savings = sum(
                    _to_float(d.get("EstimatedMonthlySavingsAmount")) for d in details
                )

            if est_savings <= 0.0:
                continue

            # Emit a single summary row per (type, payment, term)
            signals = {
                "GeneratedAt": now_iso,
                "Recommendation": "SavingsPlansPurchase",
                "SavingsPlansType": sp_type,
                "Term": term_opt,
                "PaymentOption": payment,
                "Lookback": lookback_opt,
                "Currency": currency or "",
                "CurrentOnDemandSpend": round(cur_spend, 2),
                "EstimatedSavingsPct": round(est_savings_pct, 1),
            }

            rec_id = f"SP:{sp_type}:{term_opt}:{payment}"
            name = f"Savings Plans ({sp_type}) {term_opt} {payment}"
            write_row(
                rec_type="SavingsPlansRecommendation",
                rec_id=rec_id,
                name=name,
                est_cost=cur_spend,
                saving=est_savings,
                confidence=85,
                signals=signals,
            )

            # Optionally emit top details (bounded)
            top = _top_n_by_monthly_savings(details, max_rows_per_type)
            for idx, d in enumerate(top, start=1):
                d_savings = _to_float(d.get("EstimatedMonthlySavingsAmount"))
                if d_savings <= 0.0:
                    continue
                d_commit = _to_float(d.get("HourlyCommitment"))
                d_util = _to_float(d.get("EstimatedUtilization"))
                d_est_cost = _to_float(d.get("EstimatedMonthlyCost"))
                d_family = d.get("InstanceFamily") or d.get("InstanceType") or ""
                d_region = d.get("Region") or ""

                d_sig = {
                    **signals,
                    "Rank": idx,
                    "HourlyCommitment": round(d_commit, 6),
                    "EstimatedUtilization": round(d_util, 1),
                    "EstimatedMonthlyCost": round(d_est_cost, 2),
                    "InstanceFamily": str(d_family),
                    "Region": str(d_region),
                }
                d_id = f"{rec_id}:D{idx}"
                d_name = f"{name} (detail {idx})"
                write_row(
                    rec_type="SavingsPlansRecommendationDetail",
                    rec_id=d_id,
                    name=d_name,
                    est_cost=d_est_cost,
                    saving=d_savings,
                    confidence=75,
                    signals=d_sig,
                )

    # ----------------------------- Reserved Instances ------------------------ #

    ri_services = [
        ("AmazonEC2", "EC2"),
        ("AmazonRDS", "RDS"),
        ("AmazonRedshift", "Redshift"),
    ]
    ri_payments = ["NO_UPFRONT", "PARTIAL_UPFRONT", "ALL_UPFRONT"]

    for svc, short in ri_services:
        for payment in ri_payments:
            resp = _ce_call(
                log,
                ce.get_reservation_purchase_recommendation,
                Service=svc,
                LookbackPeriodInDays=lookback_opt,
                TermInYears=term_opt,
                PaymentOption=payment,
            )
            if not resp:
                continue

            summary, recs = _extract_ri_recs(resp)
            savings = _amount_value(summary.get("TotalEstimatedMonthlySavingsAmount"))
            on_demand = _amount_value(summary.get("TotalOnDemandCost"))
            pct = _to_float(summary.get("TotalEstimatedMonthlySavingsPercentage"))
            currency = _pick_currency(summary.get("TotalEstimatedMonthlySavingsAmount"))

            if savings <= 0.0 and recs:
                # Some shapes expose savings per-recommendation
                savings = sum(
                    _amount_value(r.get("EstimatedMonthlySavings")) for r in recs
                )

            if savings <= 0.0:
                continue

            signals = {
                "GeneratedAt": now_iso,
                "Recommendation": "ReservedInstancesPurchase",
                "Service": short,
                "Term": term_opt,
                "PaymentOption": payment,
                "Lookback": lookback_opt,
                "Currency": currency or "",
                "CurrentOnDemandSpend": round(on_demand, 2),
                "EstimatedSavingsPct": round(pct, 1),
            }
            rec_id = f"RI:{short}:{term_opt}:{payment}"
            name = f"Reserved Instances ({short}) {term_opt} {payment}"

            write_row(
                rec_type="ReservedInstancesRecommendation",
                rec_id=rec_id,
                name=name,
                est_cost=on_demand,
                saving=savings,
                confidence=85,
                signals=signals,
            )

            # Emit a few top recommendations (bounded)
            top = _top_n_by_monthly_savings(recs, max_rows_per_type)
            for idx, r in enumerate(top, start=1):
                r_savings = _amount_value(r.get("EstimatedMonthlySavings"))
                if r_savings <= 0.0:
                    continue
                r_est_cost = _amount_value(r.get("EstimatedMonthlyCost"))

                r_details = r.get("RecommendationDetails") or {}
                inst_family = ""
                rec_region = ""
                if isinstance(r_details, dict):
                    inst_family = str(
                        r_details.get("InstanceFamily")
                        or r_details.get("InstanceType")
                        or ""
                    )
                    rec_region = str(r_details.get("Region") or "")

                r_sig = {
                    **signals,
                    "Rank": idx,
                    "EstimatedMonthlyCost": round(r_est_cost, 2),
                    "InstanceFamily": inst_family,
                    "Region": rec_region,
                }
                r_id = f"{rec_id}:D{idx}"
                r_name = f"{name} (detail {idx})"
                write_row(
                    rec_type="ReservedInstancesRecommendationDetail",
                    rec_id=r_id,
                    name=r_name,
                    est_cost=r_est_cost,
                    saving=r_savings,
                    confidence=75,
                    signals=r_sig,
                )

    log.info("[commitments] Completed commitments recommendations")
