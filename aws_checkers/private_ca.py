"""Checker: AWS Certificate Manager Private CA (ACM PCA).

Enumerates Private Certificate Authorities and writes findings to CSV including:
  - Estimated_Cost_USD
  - Potential_Saving_USD (simple heuristic)
  - Flags (status-driven)
  - Signals (compact 'k=v' pairs joined with '|')

"""

from __future__ import annotations
import logging
from typing import Optional, Callable, Any, List

from botocore.exceptions import ClientError
from core.retry import retry_with_backoff
from aws_checkers import config
from aws_checkers.common import (
    _logger,
    _to_utc_iso,
)


@retry_with_backoff(exceptions=(ClientError,))
def check_private_certificate_authorities(  # pylint: disable=unused-argument
    writer,
    acmpca,
    logger: Optional[logging.Logger] = None,
    **kwargs: Any,
) -> None:
    """
    Enumerate Private CAs and write CSV rows with Flags, Estimated_Cost_USD,
    Potential_Saving_USD and Signals. If checker config or the acmpca client
    is missing, skip gracefully (log a warning) instead of raising.
    """
    # ---- Resolve deps from per-call overrides OR global config ----
    account_id: Optional[str] = kwargs.get("account_id") or config.ACCOUNT_ID
    write_row: Optional[Callable[..., None]] = kwargs.get("write_row") or config.WRITE_ROW
    get_price: Optional[Callable[[str, str], float]] = kwargs.get("get_price") or config.GET_PRICE
    log = _logger(kwargs.get("logger") or logger)

    # ---- Graceful skips for tests or misconfiguration ----
    if writer is None:
        log.warning("[check_private_certificate_authorities] Skipping: 'writer' is None.")
        return
    if acmpca is None:
        log.warning("[check_private_certificate_authorities] Skipping: 'acmpca' client not provided.")
        return
    if not (account_id and write_row and get_price):
        log.warning(
            "[check_private_certificate_authorities] Skipping: checker config not provided "
            "(call config.setup(...) or pass account_id/write_row/get_price)."
        )
        return

    region = getattr(getattr(acmpca, "meta", None), "region_name", "") or ""

    try:
        paginator = acmpca.get_paginator("list_certificate_authorities")
        for page in paginator.paginate():
            for ca in page.get("CertificateAuthorities", []) or []:
                arn = ca.get("Arn")
                status = ca.get("Status")
                ca_type = ca.get("Type")
                if not arn:
                    continue

                # Friendly name + extra signals (best effort)
                try:
                    d = acmpca.describe_certificate_authority(CertificateAuthorityArn=arn)
                    cfg = (d.get("CertificateAuthority", {})
                             .get("CertificateAuthorityConfiguration", {}) or {})
                    subj = cfg.get("Subject", {}) or {}
                    name = subj.get("CommonName") or arn
                    created = _to_utc_iso(d.get("CertificateAuthority", {}).get("CreatedAt"))
                    not_before = _to_utc_iso(d.get("CertificateAuthority", {}).get("NotBefore"))
                    not_after = _to_utc_iso(d.get("CertificateAuthority", {}).get("NotAfter"))
                except ClientError as exc:
                    log.debug("DescribeCertificateAuthority failed for %s: %s", arn, exc)
                    name, created, not_before, not_after = arn, None, None, None

                # Flags + estimated cost
                flags: List[str] = []
                est_cost = 0.0
                if status == "ACTIVE":
                    flags.append("PrivateCAActive")
                    est_cost = config.safe_price("ACMPCA", "ACTIVE_MONTH")
                elif status == "DISABLED":
                    flags.append("PrivateCADisabled")
                    est_cost = config.safe_price("ACMPCA", "DISABLED_MONTH")
                elif status == "EXPIRED":
                    flags.append("PrivateCAExpired")
                    est_cost = config.safe_price("ACMPCA", "EXPIRED_MONTH")
                elif status == "FAILED":
                    flags.append("PrivateCAFailed")
                    est_cost = config.safe_price("ACMPCA", "FAILED_MONTH")
                elif status == "PENDING_CERTIFICATE":
                    flags.append("PrivateCAPendingCertificate")
                    est_cost = config.safe_price("ACMPCA", "PENDING_CERT_MONTH")
                else:
                    log.info(
                        "[check_private_certificate_authorities] Skipping CA: %s (status=%s)",
                        arn, status,
                    )
                    continue

                signals = "|".join(
                    s for s in [
                        f"Status={status}",
                        f"Type={ca_type}",
                        f"Region={region}",
                        f"Name={name}",
                        f"CreatedAt={created}" if created else "",
                        f"NotBefore={not_before}" if not_before else "",
                        f"NotAfter={not_after}" if not_after else "",
                    ] if s
                )

                potential_saving = 0.0 if status == "ACTIVE" else est_cost

                # type: ignore[call-arg]  (write_row provided at runtime)
                write_row(
                    writer=writer,
                    resource_id=arn,
                    name=name,
                    owner_id=account_id,
                    resource_type="ACMPrivateCA",
                    estimated_cost=est_cost,
                    potential_saving=potential_saving,
                    flags=flags,
                    confidence=100,
                    signals=signals,
                )

                log.info(
                    "[check_private_certificate_authorities] Wrote CA: %s (status=%s flags=%s est=%.2f save=%.2f)",
                    arn, status, flags, est_cost, potential_saving,
                )

    except ClientError as exc:
        log.error("Error checking Private Certificate Authorities: %s", exc)
        raise
