"""Checkers: EC2 Graviton candidates.

This checker identifies Linux/Unix EC2 instances that have a clear Graviton (arm64)
instance-type equivalent and estimates potential monthly savings using AWS Pricing
(On-Demand Linux, shared tenancy).

Conservative compatibility rules (to avoid false positives):
- Only consider instances in state "running".
- Skip Windows instances.
- Only consider families with well-known 1:1 Graviton counterpart and verify the
  target instance type exists (DescribeInstanceTypes).

Notes:
- The AWS Pricing API is global (us-east-1) and can be slow if abused. We cache
  prices per (region, instance_type) and only query the distinct types seen.
- Savings are estimated assuming the instance runs all month (HOURS_PER_MONTH).
"""

from __future__ import annotations

import json
import logging
from typing import Any, Dict, Iterable, List, Optional, Tuple

from botocore.exceptions import ClientError

from aws_checkers import config
from aws_checkers.common import _logger, _signals_str
from core.retry import retry_with_backoff
from finops_toolset import config as const


# ----------------------------- region mapping ----------------------------- #

# AWS Pricing uses "location" strings (not region codes).
_REGION_TO_LOCATION: Dict[str, str] = {
    "us-east-1": "US East (N. Virginia)",
    "us-east-2": "US East (Ohio)",
    "us-west-1": "US West (N. California)",
    "us-west-2": "US West (Oregon)",
    "ca-central-1": "Canada (Central)",
    "eu-west-1": "EU (Ireland)",
    "eu-west-2": "EU (London)",
    "eu-west-3": "EU (Paris)",
    "eu-central-1": "EU (Frankfurt)",
    "eu-central-2": "EU (Zurich)",
    "eu-north-1": "EU (Stockholm)",
    "eu-south-1": "EU (Milan)",
    "eu-south-2": "EU (Spain)",
    "ap-south-1": "Asia Pacific (Mumbai)",
    "ap-south-2": "Asia Pacific (Hyderabad)",
    "ap-northeast-1": "Asia Pacific (Tokyo)",
    "ap-northeast-2": "Asia Pacific (Seoul)",
    "ap-northeast-3": "Asia Pacific (Osaka)",
    "ap-southeast-1": "Asia Pacific (Singapore)",
    "ap-southeast-2": "Asia Pacific (Sydney)",
    "ap-southeast-3": "Asia Pacific (Jakarta)",
    "ap-southeast-4": "Asia Pacific (Melbourne)",
    "sa-east-1": "South America (São Paulo)",
    "af-south-1": "Africa (Cape Town)",
    "me-south-1": "Middle East (Bahrain)",
    "me-central-1": "Middle East (UAE)",
}


# ------------------------- instance family mapping ------------------------ #

# Map x86 families to their closest Graviton equivalents (same class & generation).
# Keep conservative: only clear, widely used mappings.
_X86_TO_ARM_FAMILY: Dict[str, str] = {
    "t3": "t4g",
    "t3a": "t4g",
    "m5": "m6g",
    "m5a": "m6g",
    "m5n": "m6gn",
    "c5": "c6g",
    "c5a": "c6g",
    "c5n": "c6gn",
    "r5": "r6g",
    "r5a": "r6g",
    "r5n": "r6gn",
}


def _parse_instance_type(instance_type: str) -> Optional[Tuple[str, str]]:
    """Split an instance type into (family, size) or return None."""
    parts = (instance_type or "").split(".")
    if len(parts) != 2:
        return None
    fam, size = parts[0].strip(), parts[1].strip()
    if not fam or not size:
        return None
    return fam, size


def _is_windows(instance: Dict[str, Any]) -> bool:
    """Best-effort check for Windows instances."""
    platform = (instance.get("Platform") or "").lower()
    if platform == "windows":
        return True
    details = (instance.get("PlatformDetails") or "").lower()
    return "windows" in details


def _instance_name(tags: Iterable[Dict[str, Any]]) -> str:
    for t in tags or []:
        if (t.get("Key") or "") == "Name" and t.get("Value"):
            return str(t["Value"])
    return ""


# ----------------------------- AWS Pricing API ---------------------------- #

_PRICE_CACHE: Dict[Tuple[str, str], float] = {}  # (region, instance_type) -> hourly
_TYPE_EXISTS_CACHE: Dict[Tuple[int, str], bool] = {}  # (id(ec2), itype) -> exists


def _safe_float(value: Any) -> Optional[float]:
    try:
        return float(value)
    except Exception:  # pylint: disable=broad-except
        return None


def _pricing_filters(instance_type: str, location: str) -> List[Dict[str, str]]:
    return [
        {"Type": "TERM_MATCH", "Field": "instanceType", "Value": instance_type},
        {"Type": "TERM_MATCH", "Field": "location", "Value": location},
        {"Type": "TERM_MATCH", "Field": "operatingSystem", "Value": "Linux"},
        {"Type": "TERM_MATCH", "Field": "tenancy", "Value": "Shared"},
        {"Type": "TERM_MATCH", "Field": "preInstalledSw", "Value": "NA"},
        {"Type": "TERM_MATCH", "Field": "capacitystatus", "Value": "Used"},
    ]


def _extract_ondemand_hourly_price(product: Dict[str, Any]) -> Optional[float]:
    """Parse a Pricing JSON product into a USD hourly price."""
    terms = product.get("terms", {}) or {}
    on_demand = terms.get("OnDemand", {}) or {}
    for _, term in on_demand.items():
        dims = term.get("priceDimensions", {}) or {}
        for _, dim in dims.items():
            price_per_unit = (dim.get("pricePerUnit", {}) or {}).get("USD")
            val = _safe_float(price_per_unit)
            if val is not None:
                return val
    return None


def _get_hourly_price(
    pricing,
    region: str,
    instance_type: str,
    log: logging.Logger,
) -> Optional[float]:
    """Cached AWS Pricing lookup for On-Demand Linux hourly compute price."""
    key = (region, instance_type)
    if key in _PRICE_CACHE:
        return _PRICE_CACHE[key]

    location = _REGION_TO_LOCATION.get(region)
    if not location:
        log.debug("[graviton] No Pricing location mapping for %s", region)
        return None

    try:
        resp = pricing.get_products(
            ServiceCode="AmazonEC2",
            Filters=_pricing_filters(instance_type, location),
            MaxResults=1,
        )
    except ClientError as exc:
        log.debug(
            "[graviton] pricing.get_products failed for %s %s: %s",
            region,
            instance_type,
            exc,
        )
        return None

    price_list = resp.get("PriceList") or []
    if not price_list:
        return None

    try:
        parsed = json.loads(price_list[0])
    except Exception as exc:  # pylint: disable=broad-except
        log.debug("[graviton] pricing JSON parse failed for %s: %s", instance_type, exc)
        return None

    hourly = _extract_ondemand_hourly_price(parsed)
    if hourly is None:
        return None

    _PRICE_CACHE[key] = hourly
    return hourly


def _instance_type_exists(ec2, instance_type: str, log: logging.Logger) -> bool:
    """Verify instance type exists via DescribeInstanceTypes (cached)."""
    key = (id(ec2), instance_type)
    if key in _TYPE_EXISTS_CACHE:
        return _TYPE_EXISTS_CACHE[key]

    try:
        ec2.describe_instance_types(InstanceTypes=[instance_type])
        _TYPE_EXISTS_CACHE[key] = True
        return True
    except ClientError as exc:
        code = (exc.response.get("Error", {}) or {}).get("Code", "")
        if code in ("UnauthorizedOperation", "AccessDenied", "AccessDeniedException"):
            guess = instance_type.split(".")[0].endswith("g")
            _TYPE_EXISTS_CACHE[key] = guess
            return guess
        log.debug("[graviton] describe_instance_types failed for %s: %s", instance_type, exc)
        _TYPE_EXISTS_CACHE[key] = False
        return False


# -------------------------- extractors (template) -------------------------- #


def _extract_writer_ec2_pricing(
    args: Tuple[Any, ...],
    kwargs: Dict[str, Any],
) -> Tuple[Any, Any, Any]:
    """
    Extract (writer, ec2, pricing) in a run_check-compatible way.
    """
    writer = kwargs.get("writer")
    if writer is None and args:
        writer = args[0]

    ec2 = kwargs.get("ec2")
    pricing_client = kwargs.get("pricing")

    if writer is None or ec2 is None or pricing_client is None:
        raise TypeError(
            "Expected 'writer', 'ec2', and 'pricing' "
            f"(got writer={writer!r}, ec2={ec2!r}, pricing={pricing_client!r})"
        )

    return writer, ec2, pricing_client


# --------------------------------- checker -------------------------------- #


@retry_with_backoff(exceptions=(ClientError,))
def check_ec2_graviton_candidates(  # pylint: disable=unused-argument
    region: str,
    *args: Any,
    logger: Optional[logging.Logger] = None,
    min_monthly_saving_usd: float = 5.0,
    **kwargs: Any,
) -> None:
    """Identify Graviton migration candidates and write one row per instance."""
    log = _logger(kwargs.get("logger") or logger)

    try:
        writer, ec2, pricing_client = _extract_writer_ec2_pricing(args, kwargs)
    except TypeError as exc:
        log.warning("[check_ec2_graviton_candidates] Skipping: %s", exc)
        return

    owner = str(config.ACCOUNT_ID or "")
    if not (owner and config.WRITE_ROW):
        log.warning("[check_ec2_graviton_candidates] Skipping: missing config.")
        return

    # Enumerate running instances
    instances: List[Dict[str, Any]] = []
    try:
        paginator = ec2.get_paginator("describe_instances")
        for page in paginator.paginate(
            Filters=[{"Name": "instance-state-name", "Values": ["running"]}]
        ):
            for resv in page.get("Reservations", []) or []:
                for inst in resv.get("Instances", []) or []:
                    instances.append(inst)
    except ClientError as exc:
        log.warning("[graviton] describe_instances failed in %s: %s", region, exc)
        return

    if not instances:
        log.info("[graviton] No running instances in %s", region)
        return

    hours = float(getattr(const, "HOURS_PER_MONTH", 730.0))
    emitted = 0

    for inst in instances:
        if _is_windows(inst):
            continue

        itype = str(inst.get("InstanceType") or "")
        parsed = _parse_instance_type(itype)
        if not parsed:
            continue
        fam, size = parsed

        # Skip instances already on Graviton families
        if fam.endswith("g") or fam.startswith("a1"):
            continue

        target_family = _X86_TO_ARM_FAMILY.get(fam)
        if not target_family:
            continue

        target_type = f"{target_family}.{size}"
        if not _instance_type_exists(ec2, target_type, log):
            continue

        # Pricing lookups
        cur_hourly = _get_hourly_price(pricing_client, region, itype, log)
        tgt_hourly = _get_hourly_price(pricing_client, region, target_type, log)
        if cur_hourly is None or tgt_hourly is None:
            continue

        monthly_cost = cur_hourly * hours
        monthly_saving = max(0.0, (cur_hourly - tgt_hourly) * hours)
        if monthly_saving < float(min_monthly_saving_usd):
            continue

        instance_id = str(inst.get("InstanceId") or "")
        name = _instance_name(inst.get("Tags") or []) or instance_id

        signals = {
            "region": region,
            "instance_type": itype,
            "target_type": target_type,
            "hourly_x86": round(cur_hourly, 6),
            "hourly_arm": round(tgt_hourly, 6),
            "hours_per_month": round(hours, 1),
            "pricing_model": "OnDemand/Linux/Shared",
        }

        try:
            # type: ignore[call-arg]
            config.WRITE_ROW(
                writer=writer,
                resource_id=instance_id,
                name=name,
                resource_type="EC2Instance",
                region=region,
                owner_id=owner,
                flags=["EC2GravitonCandidate"],
                estimated_cost=round(monthly_cost, 2),
                potential_saving=round(monthly_saving, 2),
                confidence=80,
                signals=_signals_str(signals),
                state=str((inst.get("State") or {}).get("Name") or ""),
                creation_date="",
                instance_type=itype,
                target_instance_type=target_type,
            )
            emitted += 1
        except Exception as exc:  # pylint: disable=broad-except
            log.debug("[graviton] failed to write row for %s: %s", instance_id, exc)

    log.info(
        "[graviton] Completed check_ec2_graviton_candidates in %s (rows=%d)",
        region,
        emitted,
    )
