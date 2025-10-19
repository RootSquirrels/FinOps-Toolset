"""Checkers: Amazon Route 53 (Hosted Zones & Health Checks).

Checks included:

  - check_route53_empty_public_zones
      Public hosted zones that only contain the default SOA/NS records.
      Estimates the monthly hosted-zone fee.

  - check_route53_private_zones_no_vpc_associations
      Private hosted zones with zero VPC associations. Estimates monthly fee.

  - check_route53_unused_health_checks
      Health checks that are not referenced by any record set. Estimates monthly fee.

  - check_route53_public_zones_dnssec_disabled
      Public hosted zones without DNSSEC enabled (hygiene).

Design:
  - Dependencies via finops_toolset.checkers.config.setup(...).
  - Tolerant signatures (positional/keyword), graceful skips, no return values.
  - UTC datetimes; pylint-friendly; lines ≤ 100 chars.

Pricing keys used (safe defaults if absent):
  "R53": {
      "PUBLIC_ZONE_MONTH": 0.50,
      "PRIVATE_ZONE_MONTH": 0.10,
      "HEALTH_CHECK_MONTH": 0.50
  }
"""

from __future__ import annotations

import logging
from typing import Any, Dict, Iterable, List, Optional, Tuple

from botocore.exceptions import ClientError

from aws_checkers import config
from core.retry import retry_with_backoff


# -------------------------------- helpers -------------------------------- #

def _logger(fallback: Optional[logging.Logger]) -> logging.Logger:
    return fallback or config.LOGGER or logging.getLogger(__name__)


def _signals_str(pairs: Dict[str, object]) -> str:
    items: List[str] = []
    for k, v in pairs.items():
        if v is None or v == "":
            continue
        items.append(f"{k}={v}")
    return "|".join(items)


def _extract_writer_r53(
    args: Tuple[Any, ...],
    kwargs: Dict[str, Any],
) -> Tuple[Any, Any]:
    """Accept writer/route53 (positional or keyword)."""
    writer = kwargs.get("writer", args[0] if len(args) >= 1 else None)
    r53 = kwargs.get("route53", args[1] if len(args) >= 2 else None)
    if writer is None or r53 is None:
        raise TypeError(
            "Expected 'writer' and 'route53' "
            f"(got writer={writer!r}, route53={r53!r})"
        )
    return writer, r53


def _public_zone_month() -> float:
    return float(config.safe_price("R53", "PUBLIC_ZONE_MONTH", 0.50))


def _private_zone_month() -> float:
    return float(config.safe_price("R53", "PRIVATE_ZONE_MONTH", 0.10))


def _health_check_month() -> float:
    return float(config.safe_price("R53", "HEALTH_CHECK_MONTH", 0.50))


def _list_hosted_zones(r53, log: logging.Logger) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    try:
        p = r53.get_paginator("list_hosted_zones")
        for page in p.paginate():
            out.extend(page.get("HostedZones", []) or [])
    except ClientError as exc:
        log.error("[r53] list_hosted_zones failed: %s", exc)
    return out


def _list_rrsets(r53, zone_id: str, log: logging.Logger) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    try:
        p = r53.get_paginator("list_resource_record_sets")
        for page in p.paginate(HostedZoneId=zone_id):
            out.extend(page.get("ResourceRecordSets", []) or [])
    except ClientError as exc:
        log.debug("[r53] list_resource_record_sets %s failed: %s", zone_id, exc)
    return out


def _get_hosted_zone(r53, zone_id: str, log: logging.Logger) -> Dict[str, Any]:
    try:
        return r53.get_hosted_zone(Id=zone_id) or {}
    except ClientError as exc:
        log.debug("[r53] get_hosted_zone %s failed: %s", zone_id, exc)
        return {}


def _zone_is_public(z: Dict[str, Any]) -> bool:
    # list_hosted_zones does not include VPCs; use the 'Config' flag when present
    cfg = z.get("Config") or {}
    return not bool(cfg.get("PrivateZone"))


def _zone_has_only_default_records(
    zone: Dict[str, Any],
    rrsets: List[Dict[str, Any]],
) -> bool:
    """True if zone only has apex NS+SOA (ignoring DNSSEC aux records)."""
    zname = (zone.get("Name") or "").rstrip(".").lower()
    if not zname:
        return False

    non_default_found = False
    apex_defaults = 0
    for rr in rrsets:
        rname = (rr.get("Name") or "").rstrip(".").lower()
        rtype = (rr.get("Type") or "").upper()

        # Ignore DNSSEC-related records if present.
        if rtype in {"DNSKEY", "DS", "NSEC", "NSEC3", "NSEC3PARAM"}:
            continue

        if rname == zname and rtype in {"NS", "SOA"}:
            apex_defaults += 1
            continue

        # Anything else means it's not empty.
        non_default_found = True
        break

    if non_default_found:
        return False
    # Some zones may miss one of the apex records during edits; be strict but tolerant.
    return apex_defaults >= 1 and not non_default_found


def _collect_used_health_check_ids(
    r53,
    zones: List[Dict[str, Any]],
    log: logging.Logger,
) -> set:
    used: set = set()
    for z in zones:
        zid = z.get("Id")
        if not zid:
            continue
        rrsets = _list_rrsets(r53, zid, log)
        for rr in rrsets:
            hcid = rr.get("HealthCheckId")
            if hcid:
                used.add(hcid)
    return used


def _list_health_checks(r53, log: logging.Logger) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    try:
        p = r53.get_paginator("list_health_checks")
        for page in p.paginate():
            out.extend(page.get("HealthChecks", []) or [])
    except ClientError as exc:
        log.error("[r53] list_health_checks failed: %s", exc)
    return out


# -------------------- 1) Empty public hosted zones (cost) ---------------- #

@retry_with_backoff(exceptions=(ClientError,))
def check_route53_empty_public_zones(  # pylint: disable=unused-argument
    *args,
    logger: Optional[logging.Logger] = None,
    **kwargs,
) -> None:
    """Flag public hosted zones that only contain apex NS/SOA (likely unused)."""
    log = _logger(kwargs.get("logger") or logger)

    try:
        writer, r53 = _extract_writer_r53(args, kwargs)
    except TypeError as exc:
        log.warning("[check_route53_empty_public_zones] Skipping: %s", exc)
        return
    if not (config.ACCOUNT_ID and config.WRITE_ROW and config.GET_PRICE):
        log.warning("[check_route53_empty_public_zones] Skipping: checker config not provided.")
        return

    zones = _list_hosted_zones(r53, log)
    if not zones:
        return

    for z in zones:
        zid = z.get("Id") or ""
        zname = (z.get("Name") or "").rstrip(".")
        if not zid or not _zone_is_public(z):
            continue

        rrsets = _list_rrsets(r53, zid, log)
        if not _zone_has_only_default_records(z, rrsets):
            continue

        est = _public_zone_month()
        potential = est

        try:
            # type: ignore[call-arg]
            config.WRITE_ROW(
                writer=writer,
                resource_id=zid,
                name=zname or zid,
                owner_id=config.ACCOUNT_ID,  # type: ignore[arg-type]
                resource_type="Route53HostedZone",
                estimated_cost=est,
                potential_saving=potential,
                flags=["Route53PublicZoneEmpty"],
                confidence=100,
                signals=_signals_str(
                    {
                        "ZoneId": zid,
                        "ZoneName": zname,
                        "RecordSets": len(rrsets),
                        "IsPublic": True,
                    }
                ),
            )
        except Exception as exc:  # pylint: disable=broad-except
            log.warning("[r53] write_row empty public zone %s: %s", zid, exc)

        log.info("[r53] Wrote empty public hosted zone: %s", zname or zid)


# -------- 2) Private zones with zero VPC associations (monthly fee) ------ #

@retry_with_backoff(exceptions=(ClientError,))
def check_route53_private_zones_no_vpc_associations(  # pylint: disable=unused-argument
    *args,
    logger: Optional[logging.Logger] = None,
    **kwargs,
) -> None:
    """Flag private hosted zones that have zero VPC associations."""
    log = _logger(kwargs.get("logger") or logger)

    try:
        writer, r53 = _extract_writer_r53(args, kwargs)
    except TypeError as exc:
        log.warning("[check_route53_private_zones_no_vpc_associations] Skipping: %s", exc)
        return
    if not (config.ACCOUNT_ID and config.WRITE_ROW and config.GET_PRICE):
        log.warning(
            "[check_route53_private_zones_no_vpc_associations] "
            "Skipping: checker config not provided."
        )
        return

    zones = _list_hosted_zones(r53, log)
    if not zones:
        return

    for z in zones:
        zid = z.get("Id") or ""
        if not zid or _zone_is_public(z):
            continue

        detail = _get_hosted_zone(r53, zid, log)
        hz = detail.get("HostedZone") or {}
        vpcs = detail.get("VPCs") or []

        if vpcs:
            continue

        zname = (hz.get("Name") or z.get("Name") or "").rstrip(".")
        est = _private_zone_month()
        potential = est

        try:
            # type: ignore[call-arg]
            config.WRITE_ROW(
                writer=writer,
                resource_id=zid,
                name=zname or zid,
                owner_id=config.ACCOUNT_ID,  # type: ignore[arg-type]
                resource_type="Route53HostedZone",
                estimated_cost=est,
                potential_saving=potential,
                flags=["Route53PrivateZoneNoVPCs"],
                confidence=100,
                signals=_signals_str(
                    {
                        "ZoneId": zid,
                        "ZoneName": zname,
                        "AssociatedVPCs": 0,
                        "IsPublic": False,
                    }
                ),
            )
        except Exception as exc:  # pylint: disable=broad-except
            log.warning("[r53] write_row private zone no VPCs %s: %s", zid, exc)

        log.info("[r53] Wrote private hosted zone with no VPCs: %s", zname or zid)


# ---------------- 3) Unused health checks (monthly fee) ------------------ #

@retry_with_backoff(exceptions=(ClientError,))
def check_route53_unused_health_checks(  # pylint: disable=unused-argument
    *args,
    logger: Optional[logging.Logger] = None,
    **kwargs,
) -> None:
    """
    Flag Route 53 health checks that are not referenced by any record set.
    """
    log = _logger(kwargs.get("logger") or logger)

    try:
        writer, r53 = _extract_writer_r53(args, kwargs)
    except TypeError as exc:
        log.warning("[check_route53_unused_health_checks] Skipping: %s", exc)
        return
    if not (config.ACCOUNT_ID and config.WRITE_ROW and config.GET_PRICE):
        log.warning("[check_route53_unused_health_checks] Skipping: checker config not provided.")
        return

    zones = _list_hosted_zones(r53, log)
    if zones is None:
        zones = []

    used_ids = _collect_used_health_check_ids(r53, zones, log)
    checks = _list_health_checks(r53, log)

    for hc in checks:
        hcid = hc.get("Id") or ""
        name = hc.get("HealthCheckConfig", {}).get("FullyQualifiedDomainName") or hcid
        if not hcid:
            continue
        if hcid in used_ids:
            continue

        est = _health_check_month()
        potential = est

        try:
            # type: ignore[call-arg]
            config.WRITE_ROW(
                writer=writer,
                resource_id=hcid,
                name=str(name),
                owner_id=config.ACCOUNT_ID,  # type: ignore[arg-type]
                resource_type="Route53HealthCheck",
                estimated_cost=est,
                potential_saving=potential,
                flags=["Route53HealthCheckUnused"],
                confidence=100,
                signals=_signals_str(
                    {"HealthCheckId": hcid, "ReferencedByRecords": 0}
                ),
            )
        except Exception as exc:  # pylint: disable=broad-except
            log.warning("[r53] write_row unused health check %s: %s", hcid, exc)

        log.info("[r53] Wrote unused health check: %s", hcid)


# ------------- 4) Public zones without DNSSEC enabled (hygiene) ---------- #

@retry_with_backoff(exceptions=(ClientError,))
def check_route53_public_zones_dnssec_disabled(  # pylint: disable=unused-argument
    *args,
    logger: Optional[logging.Logger] = None,
    **kwargs,
) -> None:
    """Flag public hosted zones that do not have DNSSEC enabled (best-effort)."""
    log = _logger(kwargs.get("logger") or logger)

    try:
        writer, r53 = _extract_writer_r53(args, kwargs)
    except TypeError as exc:
        log.warning("[check_route53_public_zones_dnssec_disabled] Skipping: %s", exc)
        return
    if not (config.ACCOUNT_ID and config.WRITE_ROW):
        log.warning(
            "[check_route53_public_zones_dnssec_disabled] "
            "Skipping: checker config not provided."
        )
        return

    zones = _list_hosted_zones(r53, log)
    if not zones:
        return

    for z in zones:
        zid = z.get("Id") or ""
        zname = (z.get("Name") or "").rstrip(".")
        if not zid or not _zone_is_public(z):
            continue

        enabled = False
        try:
            resp = r53.get_dnssec(HostedZoneId=zid)
            status = (resp.get("Status") or {}).get("ServeSignature") or ""
            enabled = str(status).upper() in {"ENABLED", "ENABLING", "SIGNING"}
        except ClientError as exc:
            # If API errors (e.g., not supported), treat as not enabled only if we got a
            # valid response previously. In doubt, just continue without flagging.
            log.debug("[r53] get_dnssec %s failed: %s", zid, exc)
            continue

        if enabled:
            continue

        try:
            # type: ignore[call-arg]
            config.WRITE_ROW(
                writer=writer,
                resource_id=zid,
                name=zname or zid,
                owner_id=config.ACCOUNT_ID,  # type: ignore[arg-type]
                resource_type="Route53HostedZone",
                estimated_cost=0.0,
                potential_saving=0.0,
                flags=["Route53PublicZoneDNSSECDisabled"],
                confidence=100,
                signals=_signals_str({"ZoneId": zid, "ZoneName": zname, "DNSSECEnabled": False}),
            )
        except Exception as exc:  # pylint: disable=broad-except
            log.warning("[r53] write_row dnssec disabled %s: %s", zid, exc)

        log.info("[r53] Wrote DNSSEC-disabled public zone: %s", zname or zid)
