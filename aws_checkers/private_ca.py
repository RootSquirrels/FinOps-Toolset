"""Checker: AWS Certificate Manager Private CA (ACM PCA).

Enumerates Private Certificate Authorities and writes findings to CSV including:
  - Estimated_Cost_USD
  - Potential_Saving_USD (simple heuristic)
  - Flags (status-driven)
  - Signals (compact 'k=v' pairs joined with '|')

"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Dict, List, Optional

from botocore.exceptions import ClientError

from core.retry import retry_with_backoff
from aws_checkers import config


def _require_config() -> None:
    if not (config.ACCOUNT_ID and config.WRITE_ROW and config.GET_PRICE):
        raise RuntimeError(
            "Checkers not configured. Call "
            "finops_toolset.checkers.config.setup(account_id=..., write_row=..., "
            "get_price=..., logger=...) first."
        )


def _logger(fallback: Optional[logging.Logger]) -> logging.Logger:
    return fallback or config.LOGGER or logging.getLogger(__name__)


def _safe_price(service: str, key: str) -> float:
    try:
        # type: ignore[arg-type]
        return float(config.GET_PRICE(service, key))  # pylint: disable=not-callable
    except Exception:  # pylint: disable=broad-except
        return 0.0


def _to_utc_iso(dt_obj: Optional[datetime]) -> Optional[str]:
    """Return ISO-8601 (UTC, no microseconds) or None."""
    if not isinstance(dt_obj, datetime):
        return None
    if dt_obj.tzinfo is None:
        dt_obj = dt_obj.replace(tzinfo=timezone.utc)
    else:
        dt_obj = dt_obj.astimezone(timezone.utc)
    return dt_obj.replace(microsecond=0).isoformat()


def _signals_str(pairs: Dict[str, object]) -> str:
    """Build compact Signals cell from k=v pairs; skip Nones/empties."""
    items: List[str] = []
    for k, v in pairs.items():
        if v is None or v == "":
            continue
        items.append(f"{k}={v}")
    return "|".join(items)


def _ca_display_and_signals(acmpca, arn: str, region: str,
                            log: logging.Logger) -> (str, str): # type: ignore
    """
    Describe the CA to enrich name and build a Signals string.

    Signals include: Status, Type, Region, CommonName, KeyAlgorithm, SigningAlgorithm,
    CRL (bool), CreatedAt, NotBefore, NotAfter when available.
    """
    name = arn
    signals = ""
    try:
        resp = acmpca.describe_certificate_authority(CertificateAuthorityArn=arn)
        ca = resp.get("CertificateAuthority", {}) or {}

        cfg = ca.get("CertificateAuthorityConfiguration", {}) or {}
        subj = cfg.get("Subject", {}) or {}
        common_name = subj.get("CommonName") or ""

        name = common_name or arn

        signals = _signals_str(
            {
                "Status": ca.get("Status"),
                "Type": ca.get("Type"),
                "Region": region,
                "CommonName": common_name,
                "KeyAlgorithm": cfg.get("KeyAlgorithm"),
                "SigningAlgorithm": cfg.get("SigningAlgorithm"),
                "CRL": bool(((ca.get("RevocationConfiguration") or {}).get("CrlConfiguration") or {}).get("Enabled")),
                "CreatedAt": _to_utc_iso(ca.get("CreatedAt")),
                "NotBefore": _to_utc_iso(ca.get("NotBefore")),
                "NotAfter": _to_utc_iso(ca.get("NotAfter")),
            }
        )
    except ClientError as exc:
        log.debug("DescribeCertificateAuthority failed for %s: %s", arn, exc)
        signals = _signals_str({"Status": "Unknown", "Region": region})

    return name, signals


@retry_with_backoff(exceptions=(ClientError,))
def check_private_certificate_authorities(  # pylint: disable=unused-argument
    writer,
    acmpca,
    logger: Optional[logging.Logger] = None,
    **_kwargs,
) -> None:
    """
    Enumerate Private CAs and write CSV rows with Flags, Estimated_Cost_USD,
    Potential_Saving_USD and Signals.

    Flag mapping (simple, status-driven):
      ACTIVE               -> 'PrivateCAActive'         (monthly cost applies)
      DISABLED             -> 'PrivateCADisabled'
      EXPIRED              -> 'PrivateCAExpired'
      FAILED               -> 'PrivateCAFailed'
      PENDING_CERTIFICATE  -> 'PrivateCAPendingCertificate'

    Potential_Saving_USD heuristic:
      - For statuses other than ACTIVE, potential_saving = estimated_cost
        (i.e., eliminate the current bill for that CA).
      - For ACTIVE, set potential_saving = 0.0 by default (cannot infer usage here).
    """
    _require_config()
    log = _logger(logger)
    region = getattr(getattr(acmpca, "meta", None), "region_name", "") or ""

    try:
        paginator = acmpca.get_paginator("list_certificate_authorities")
        for page in paginator.paginate():
            for ca in page.get("CertificateAuthorities", []) or []:
                arn = ca.get("Arn")
                status = ca.get("Status")
                ca_type = ca.get("Type")
                created_at = _to_utc_iso(ca.get("CreatedAt"))
                not_before = _to_utc_iso(ca.get("NotBefore"))
                not_after = _to_utc_iso(ca.get("NotAfter"))

                if not arn:
                    continue

                # Choose flags and estimated monthly cost based on status
                flags: List[str] = []
                est_cost = 0.0

                if status == "ACTIVE":
                    flags.append("PrivateCAActive")
                    est_cost = _safe_price("ACMPCA", "ACTIVE_MONTH")
                elif status == "DISABLED":
                    flags.append("PrivateCADisabled")
                    est_cost = _safe_price("ACMPCA", "DISABLED_MONTH")
                elif status == "EXPIRED":
                    flags.append("PrivateCAExpired")
                    est_cost = _safe_price("ACMPCA", "EXPIRED_MONTH")  # 0.0 if key absent
                elif status == "FAILED":
                    flags.append("PrivateCAFailed")
                    est_cost = _safe_price("ACMPCA", "FAILED_MONTH")   # 0.0 if key absent
                elif status == "PENDING_CERTIFICATE":
                    flags.append("PrivateCAPendingCertificate")
                    est_cost = _safe_price("ACMPCA", "PENDING_CERT_MONTH")  # 0.0 if key absent
                else:
                    log.info(
                        "[check_private_certificate_authorities] Skipping CA: %s (status=%s)",
                        arn,
                        status,
                    )
                    continue

                name, signals_desc = _ca_display_and_signals(acmpca, arn, region, log)

                # Enrich Signals with fields already available from List*
                extra_signals = _signals_str(
                    {
                        "Status": status,
                        "Type": ca_type,
                        "Region": region,
                        "CreatedAt": created_at,
                        "NotBefore": not_before,
                        "NotAfter": not_after,
                    }
                )
                signals = "|".join([s for s in [signals_desc, extra_signals] if s])

                # Potential savings heuristic (ACTIVE assumed in-use)
                potential_saving = 0.0 if status == "ACTIVE" else est_cost

                # type: ignore[call-arg]
                config.WRITE_ROW(
                    writer=writer,
                    resource_id=arn,
                    name=name,
                    owner_id=config.ACCOUNT_ID,  # type: ignore[arg-type]
                    resource_type="ACMPrivateCA",
                    estimated_cost=est_cost,
                    potential_saving=potential_saving,
                    flags=flags,
                    confidence=100,
                    signals=signals,
                )

                log.info(
                    "[check_private_certificate_authorities] Wrote CA: %s (status=%s flags=%s est=%.2f save=%.2f)",
                    arn,
                    status,
                    flags,
                    est_cost,
                    potential_saving,
                )

    except ClientError as exc:
        log.error("Error checking Private Certificate Authorities: %s", exc)
        raise
