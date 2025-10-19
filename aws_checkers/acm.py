"""Checkers: AWS Certificate Manager (ACM) – Certificates.

Checks included:

  - check_acm_expiring_certificates
      Certificates that are expired or expiring within N days.

  - check_acm_unused_certificates
      Certificates in ISSUED state that are not used by any resource.

  - check_acm_validation_issues
      Certificates stuck in validation or failed validation.

  - check_acm_renewal_problems
      Amazon-issued certs with renewal failed / pending validation too long.

Design:
  - Dependencies via finops_toolset.checkers.config.setup(...).
  - Tolerant signatures (accept positional/keyword) and graceful skips.
  - UTC datetimes; pylint-friendly; lines ≤ 100 chars.
  - Pricing (optional heuristic):
        "ACM": {"PRIVATE_CERT_MONTH": 0.75}
    Public ACM certs are $0; private certs (ACM PCA) incur per-cert monthly fees.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple

from botocore.exceptions import ClientError

from aws_checkers import config
from core.retry import retry_with_backoff


# --------------------------------- helpers -------------------------------- #

def _logger(fallback: Optional[logging.Logger]) -> logging.Logger:
    return fallback or config.LOGGER or logging.getLogger(__name__)


def _signals_str(pairs: Dict[str, object]) -> str:
    items: List[str] = []
    for k, v in pairs.items():
        if v is None or v == "":
            continue
        items.append(f"{k}={v}")
    return "|".join(items)


def _to_utc_iso(dt_obj: Optional[datetime]) -> Optional[str]:
    if not isinstance(dt_obj, datetime):
        return None
    if dt_obj.tzinfo is None:
        dt_obj = dt_obj.replace(tzinfo=timezone.utc)
    else:
        dt_obj = dt_obj.astimezone(timezone.utc)
    return dt_obj.replace(microsecond=0).isoformat()


def _extract_writer_acm(
    args: Tuple[Any, ...],
    kwargs: Dict[str, Any],
) -> Tuple[Any, Any]:
    """Accept writer/acm (positional or keyword)."""
    writer = kwargs.get("writer", args[0] if len(args) >= 1 else None)
    acm = kwargs.get("acm", args[1] if len(args) >= 2 else None)
    if writer is None or acm is None:
        raise TypeError(
            "Expected 'writer' and 'acm' "
            f"(got writer={writer!r}, acm={acm!r})"
        )
    return writer, acm


def _list_cert_summaries(acm, log: logging.Logger) -> List[Dict[str, Any]]:
    """Return all certificate summaries (best effort)."""
    out: List[Dict[str, Any]] = []
    try:
        p = acm.get_paginator("list_certificates")
        for page in p.paginate(
            CertificateStatuses=[
                "PENDING_VALIDATION",
                "ISSUED",
                "INACTIVE",
                "EXPIRED",
                "VALIDATION_TIMED_OUT",
                "REVOKED",
                "FAILED",
            ]
        ):
            out.extend(page.get("CertificateSummaryList", []) or [])
    except ClientError as exc:
        log.error("[acm] list_certificates failed: %s", exc)
    return out


def _describe_cert(acm, arn: str, log: logging.Logger) -> Dict[str, Any]:
    try:
        return acm.describe_certificate(CertificateArn=arn).get("Certificate", {}) or {}
    except ClientError as exc:
        log.debug("[acm] describe_certificate %s failed: %s", arn, exc)
        return {}


def _private_cert_month_price() -> float:
    # Heuristic default for ACM Private Certificate monthly fee (per cert)
    return float(config.safe_price("ACM", "PRIVATE_CERT_MONTH", 0.75))


def _domain_hint(cert: Dict[str, Any]) -> str:
    dom = cert.get("DomainName") or ""
    sans = cert.get("SubjectAlternativeNames") or []
    if not dom and sans:
        return str(sans[0])
    return str(dom)


def _is_private(cert: Dict[str, Any]) -> bool:
    return (cert.get("Type") or "").upper() == "PRIVATE"


def _owner_id_str() -> str:
    return str(config.ACCOUNT_ID) if config.ACCOUNT_ID is not None else ""


# ----------------------- 1) Expiring / expired certs --------------------- #

@retry_with_backoff(exceptions=(ClientError,))
def check_acm_expiring_certificates(  # pylint: disable=unused-argument
    *args,
    logger: Optional[logging.Logger] = None,
    days: int = 30,
    **kwargs,
) -> None:
    """Flag certificates that are expired or expiring within 'days' days."""
    log = _logger(kwargs.get("logger") or logger)

    try:
        writer, acm = _extract_writer_acm(args, kwargs)
    except TypeError as exc:
        log.warning("[check_acm_expiring_certificates] Skipping: %s", exc)
        return
    if not (config.ACCOUNT_ID and config.WRITE_ROW):
        log.warning("[check_acm_expiring_certificates] Skipping: checker config not provided.")
        return

    region = getattr(getattr(acm, "meta", None), "region_name", "") or ""
    now_utc = datetime.now(timezone.utc).replace(microsecond=0)
    cutoff = now_utc + timedelta(days=int(days))

    for s in _list_cert_summaries(acm, log):
        arn = s.get("CertificateArn") or ""
        if not arn:
            continue
        cert = _describe_cert(acm, arn, log)
        if not cert:
            continue

        not_after = cert.get("NotAfter")
        status = (cert.get("Status") or "").upper()
        in_use = cert.get("InUseBy") or []
        typ = cert.get("Type") or ""
        name = _domain_hint(cert)

        if not isinstance(not_after, datetime):
            continue
        exp_utc = not_after if not_after.tzinfo else not_after.astimezone(timezone.utc)
        exp_utc = exp_utc.replace(microsecond=0)

        flags: List[str] = []
        if exp_utc <= now_utc:
            flags.append("ACMCertificateExpired")
        elif exp_utc <= cutoff:
            flags.append("ACMCertificateExpiringSoon")
        else:
            continue

        # Public ACM certs are free; private certs have a monthly fee
        est = _private_cert_month_price() if _is_private(cert) else 0.0
        potential = est  # heuristic; expiring + private could be pruned/rotated

        signals = _signals_str(
            {
                "Region": region,
                "ARN": arn,
                "Domain": name,
                "Type": typ,
                "Status": status,
                "InUseCount": len(in_use),
                "NotAfter": _to_utc_iso(exp_utc),
                "LookaheadDays": days,
            }
        )

        try:
            # type: ignore[call-arg]
            config.WRITE_ROW(
                writer=writer,
                resource_id=arn,
                name=name or arn,
                owner_id=config.ACCOUNT_ID,  # type: ignore[arg-type]
                resource_type="ACMCertificate",
                estimated_cost=est,
                potential_saving=potential,
                flags=flags,
                confidence=100,
                signals=signals,
            )
        except Exception as exc:  # pylint: disable=broad-except
            log.warning("[acm] write_row expiring %s: %s", arn, exc)

        log.info("[acm] Wrote expiring cert: %s", arn)


# --------------------------- 2) Unused certs ----------------------------- #

@retry_with_backoff(exceptions=(ClientError,))
def check_acm_unused_certificates(  # pylint: disable=unused-argument
    *args,
    logger: Optional[logging.Logger] = None,
    **kwargs,
) -> None:
    """Flag ISSUED certificates that are not used by any resource."""
    log = _logger(kwargs.get("logger") or logger)

    try:
        writer, acm = _extract_writer_acm(args, kwargs)
    except TypeError as exc:
        log.warning("[check_acm_unused_certificates] Skipping: %s", exc)
        return
    if not (config.ACCOUNT_ID and config.WRITE_ROW and config.GET_PRICE):
        log.warning("[check_acm_unused_certificates] Skipping: checker config not provided.")
        return

    region = getattr(getattr(acm, "meta", None), "region_name", "") or ""
    for s in _list_cert_summaries(acm, log):
        arn = s.get("CertificateArn") or ""
        if not arn:
            continue
        cert = _describe_cert(acm, arn, log)
        if not cert:
            continue

        status = (cert.get("Status") or "").upper()
        if status != "ISSUED":
            continue

        in_use = cert.get("InUseBy") or []
        if in_use:
            continue

        typ = cert.get("Type") or ""
        name = _domain_hint(cert)
        not_after = cert.get("NotAfter")

        est = _private_cert_month_price() if _is_private(cert) else 0.0
        potential = est

        signals = _signals_str(
            {
                "Region": region,
                "ARN": arn,
                "Domain": name,
                "Type": typ,
                "Status": status,
                "InUseCount": len(in_use),
                "NotAfter": _to_utc_iso(not_after) if isinstance(not_after, datetime) else None,
            }
        )

        try:
            # type: ignore[call-arg]
            config.WRITE_ROW(
                writer=writer,
                resource_id=arn,
                name=name or arn,
                owner_id=config.ACCOUNT_ID,  # type: ignore[arg-type]
                resource_type="ACMCertificate",
                estimated_cost=est,
                potential_saving=potential,
                flags=["ACMCertificateUnused"],
                confidence=100,
                signals=signals,
            )
        except Exception as exc:  # pylint: disable=broad-except
            log.warning("[acm] write_row unused %s: %s", arn, exc)

        log.info("[acm] Wrote unused cert: %s", arn)


# ------------------------ 3) Validation issues --------------------------- #

@retry_with_backoff(exceptions=(ClientError,))
def check_acm_validation_issues(  # pylint: disable=unused-argument
    *args,
    logger: Optional[logging.Logger] = None,
    **kwargs,
) -> None:
    """Flag certificates pending/failed/timed-out validation."""
    log = _logger(kwargs.get("logger") or logger)

    try:
        writer, acm = _extract_writer_acm(args, kwargs)
    except TypeError as exc:
        log.warning("[check_acm_validation_issues] Skipping: %s", exc)
        return
    if not (config.ACCOUNT_ID and config.WRITE_ROW):
        log.warning("[check_acm_validation_issues] Skipping: checker config not provided.")
        return

    region = getattr(getattr(acm, "meta", None), "region_name", "") or ""
    bad_status = {"PENDING_VALIDATION", "FAILED", "VALIDATION_TIMED_OUT"}

    for s in _list_cert_summaries(acm, log):
        arn = s.get("CertificateArn") or ""
        if not arn:
            continue
        cert = _describe_cert(acm, arn, log)
        if not cert:
            continue

        status = (cert.get("Status") or "").upper()
        if status not in bad_status:
            continue

        name = _domain_hint(cert)
        typ = cert.get("Type") or ""
        vopts = cert.get("DomainValidationOptions") or []

        signals = _signals_str(
            {
                "Region": region,
                "ARN": arn,
                "Domain": name,
                "Type": typ,
                "Status": status,
                # keep short; details are visible in AWS console
                "ValidationDomainCount": len(vopts),
            }
        )

        try:
            # type: ignore[call-arg]
            config.WRITE_ROW(
                writer=writer,
                resource_id=arn,
                name=name or arn,
                owner_id=config.ACCOUNT_ID,  # type: ignore[arg-type]
                resource_type="ACMCertificate",
                estimated_cost=0.0,
                potential_saving=0.0,
                flags=["ACMCertificateValidationIssue"],
                confidence=100,
                signals=signals,
            )
        except Exception as exc:  # pylint: disable=broad-except
            log.warning("[acm] write_row validation %s: %s", arn, exc)

        log.info("[acm] Wrote validation issue: %s (%s)", arn, status)


# -------------------------- 4) Renewal problems -------------------------- #

@retry_with_backoff(exceptions=(ClientError,))
def check_acm_renewal_problems(  # pylint: disable=unused-argument
    *args,
    logger: Optional[logging.Logger] = None,
    **kwargs,
) -> None:
    """
    Flag Amazon-issued certificates where renewal failed or is pending validation.

    Uses Certificate.RenewalSummary.RenewalStatus when present.
    """
    log = _logger(kwargs.get("logger") or logger)

    try:
        writer, acm = _extract_writer_acm(args, kwargs)
    except TypeError as exc:
        log.warning("[check_acm_renewal_problems] Skipping: %s", exc)
        return
    if not (config.ACCOUNT_ID and config.WRITE_ROW):
        log.warning("[check_acm_renewal_problems] Skipping: checker config not provided.")
        return

    region = getattr(getattr(acm, "meta", None), "region_name", "") or ""

    for s in _list_cert_summaries(acm, log):
        arn = s.get("CertificateArn") or ""
        if not arn:
            continue
        cert = _describe_cert(acm, arn, log)
        if not cert:
            continue
        if (cert.get("Type") or "").upper() != "AMAZON_ISSUED":
            continue

        summ = cert.get("RenewalSummary") or {}
        rstatus = (summ.get("RenewalStatus") or "").upper()
        if rstatus not in {"FAILED", "PENDING_VALIDATION"}:
            continue

        name = _domain_hint(cert)
        typ = cert.get("Type") or ""
        status = (cert.get("Status") or "").upper()
        not_after = cert.get("NotAfter")

        signals = _signals_str(
            {
                "Region": region,
                "ARN": arn,
                "Domain": name,
                "Type": typ,
                "Status": status,
                "RenewalStatus": rstatus,
                "NotAfter": _to_utc_iso(not_after) if isinstance(not_after, datetime) else None,
            }
        )

        try:
            # type: ignore[call-arg]
            config.WRITE_ROW(
                writer=writer,
                resource_id=arn,
                name=name or arn,
                owner_id=config.ACCOUNT_ID,  # type: ignore[arg-type]
                resource_type="ACMCertificate",
                estimated_cost=0.0,
                potential_saving=0.0,
                flags=[
                    "ACMCertificateRenewalFailed"
                    if rstatus == "FAILED"
                    else "ACMCertificateRenewalPendingValidation"
                ],
                confidence=100,
                signals=signals,
            )
        except Exception as exc:  # pylint: disable=broad-except
            log.warning("[acm] write_row renewal %s: %s", arn, exc)

        log.info("[acm] Wrote renewal problem: %s (%s)", arn, rstatus)
