"""Checkers: CloudTrail (redundant org trails, S3 + CW Logs duplication)."""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional, Tuple

from botocore.client import BaseClient
from botocore.exceptions import ClientError

from aws_checkers.common import _logger, _signals_str, _to_utc_iso
from aws_checkers import config as chk
from core.retry import retry_with_backoff


# ---------------------------------------------------------------------------
# Call normalization & Extractors
# ---------------------------------------------------------------------------

def _split_region_from_args(
    args: Tuple[Any, ...],
    kwargs: Dict[str, Any],
) -> Tuple[Optional[str], Tuple[Any, ...]]:
    """Normalize region + remaining args for orchestrator and legacy calls.

    Returns:
      (region, remaining_args)

    Accepted patterns:
      - Orchestrator: fn(writer, **kwargs) -> region may be in kwargs (optional)
      - Legacy: fn(region, writer, ...) -> first arg is region str
    """
    region_kw = kwargs.get("region")
    if isinstance(region_kw, str) and region_kw:
        return region_kw, args

    if args and isinstance(args[0], str) and len(args) >= 2:
        return str(args[0]), args[1:]

    return None, args


def _infer_region_from_client(client: Optional[BaseClient]) -> str:
    """Infer region from boto3 client meta; fallback to 'GLOBAL'."""
    if client is None:
        return "GLOBAL"
    region = getattr(getattr(client, "meta", None), "region_name", None)
    return str(region) if region else "GLOBAL"


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
# CloudTrail helpers
# ---------------------------------------------------------------------------

def _list_trails(ct: BaseClient) -> List[Dict[str, Any]]:
    """List all trails (include shadow trails) with pagination."""
    trails: List[Dict[str, Any]] = []
    token: Optional[str] = None

    while True:
        params: Dict[str, Any] = {"IncludeShadowTrails": True}
        if token:
            params["NextToken"] = token

        resp = ct.list_trails(**params)
        trails.extend(resp.get("Trails", []) or [])

        token = resp.get("NextToken")
        if not token:
            break

    return trails


def _get_trail(ct: BaseClient, arn: str) -> Dict[str, Any]:
    """Get full trail definition."""
    return ct.get_trail(Name=arn).get("Trail", {})  # type: ignore[return-value]


def _get_trail_status(ct: BaseClient, arn: str) -> Dict[str, Any]:
    """Get trail status (IsLogging, etc.)."""
    return ct.get_trail_status(Name=arn)  # type: ignore[return-value]


def _get_insight_enabled(ct: BaseClient, arn: str) -> bool:
    """Return True if CloudTrail Insights are enabled for the trail."""
    try:
        sel = ct.get_insight_selectors(TrailName=arn)  # type: ignore[call-arg]
        for s in sel.get("InsightSelectors", []) or []:
            if s.get("InsightType"):
                return True
    except Exception:  # pylint: disable=broad-except
        # Old accounts / permissions may not support this call. Assume disabled.
        return False
    return False


def _resolve_owner_id(account_id: Optional[str]) -> str:
    """Resolve owner/account id for writer rows."""
    return str(account_id or chk.ACCOUNT_ID or "")


# ---------------------------------------------------------------------------
# Check 1: Redundant organization / multi-region trails
# ---------------------------------------------------------------------------

@retry_with_backoff(exceptions=(ClientError,))
def check_cloudtrail_redundant_trails(  # noqa: D401
    *args: Any,
    logger: Optional[logging.Logger] = None,
    account_id: Optional[str] = None,
    **kwargs: Any,
) -> List[Dict[str, Any]]:
    """Flag redundant trails covering the same scope (org & multi-region)."""
    log = _logger(kwargs.get("logger") or logger)

    region, norm_args = _split_region_from_args(args, kwargs)

    try:
        writer, ct = _extract_writer_client(norm_args, kwargs)
    except TypeError as exc:
        log.warning("[check_cloudtrail_redundant_trails] Skipping: %s", exc)
        return []

    if not region:
        region = _infer_region_from_client(ct)

    owner = _resolve_owner_id(account_id)
    if not (owner and chk.WRITE_ROW):
        log.warning("[check_cloudtrail_redundant_trails] Skipping: missing config.")
        return []

    trails_summ = _list_trails(ct)
    if not trails_summ:
        return []

    # Build full trail info + status
    trails: List[Dict[str, Any]] = []
    for t in trails_summ:
        arn = str(t.get("TrailARN") or "")
        if not arn:
            continue
        try:
            full = _get_trail(ct, arn)
            status = _get_trail_status(ct, arn)
        except ClientError as exc:
            log.warning("[cloudtrail] get_trail/get_status failed for %s: %s", arn, exc)
            continue
        full["_Status"] = status
        trails.append(full)

    if not trails:
        return []

    # Identify redundancy:
    # - Org trails: more than one active IsOrganizationTrail=True & status.IsLogging=True
    # - Multi-region overlap: multiple active IsMultiRegionTrail=True
    org_active = [
        x
        for x in trails
        if bool(x.get("IsOrganizationTrail"))
        and bool(x.get("_Status", {}).get("IsLogging"))
    ]
    mr_active = [
        x
        for x in trails
        if bool(x.get("IsMultiRegionTrail"))
        and bool(x.get("_Status", {}).get("IsLogging"))
    ]

    rows: List[Dict[str, Any]] = []

    # For organization duplicates, flag all beyond the first (keep one canonical)
    if len(org_active) > 1:
        keep = org_active[0].get("TrailARN")
        for x in org_active[1:]:
            arn = str(x.get("TrailARN"))
            name = str(x.get("Name") or arn)
            created = _to_utc_iso(x.get("CreationTime"))
            flags = ["OrgTrailDuplicate"]
            signals = _signals_str(
                {
                    "trails_count": len(org_active),
                    "keep_arn": keep,
                    "multi_region": bool(x.get("IsMultiRegionTrail")),
                    "insight_enabled": _get_insight_enabled(ct, arn),
                }
            )
            try:
                chk.WRITE_ROW(  # type: ignore[call-arg]
                    writer=writer,
                    resource_id=arn,
                    name=name,
                    owner_id=owner,  # type: ignore[arg-type]
                    resource_type="CloudTrail",
                    region=region,
                    state="Active",
                    creation_date=created,
                    estimated_cost="",
                    potential_saving=None,  # no reliable volume → conservative
                    flags=flags,
                    confidence=85,
                    signals=signals,
                )
            except Exception as exc:  # pylint: disable=broad-except
                log.warning("[cloudtrail] write_row(org-dup) failed: %s", exc)

            rows.append({"arn": arn, "name": name, "reason": "OrgTrailDuplicate"})

    # For multi-region overlap, flag all beyond the first (keep one canonical)
    if len(mr_active) > 1:
        keep = mr_active[0].get("TrailARN")
        for x in mr_active[1:]:
            arn = str(x.get("TrailARN"))
            name = str(x.get("Name") or arn)
            created = _to_utc_iso(x.get("CreationTime"))
            flags = ["MultiRegionOverlap"]
            signals = _signals_str(
                {
                    "trails_count": len(mr_active),
                    "keep_arn": keep,
                    "is_org_trail": bool(x.get("IsOrganizationTrail")),
                    "insight_enabled": _get_insight_enabled(ct, arn),
                }
            )
            try:
                chk.WRITE_ROW(  # type: ignore[call-arg]
                    writer=writer,
                    resource_id=arn,
                    name=name,
                    owner_id=owner,  # type: ignore[arg-type]
                    resource_type="CloudTrail",
                    region=region,
                    state="Active",
                    creation_date=created,
                    estimated_cost="",
                    potential_saving=None,
                    flags=flags,
                    confidence=80,
                    signals=signals,
                )
            except Exception as exc:  # pylint: disable=broad-except
                log.warning("[cloudtrail] write_row(mr-dup) failed: %s", exc)

            rows.append({"arn": arn, "name": name, "reason": "MultiRegionOverlap"})

    return rows


# ---------------------------------------------------------------------------
# Check 2: S3 + CloudWatch Logs duplication
# ---------------------------------------------------------------------------

@retry_with_backoff(exceptions=(ClientError,))
def check_cloudtrail_s3_cwlogs_duplication(  # noqa: D401
    *args: Any,
    logger: Optional[logging.Logger] = None,
    account_id: Optional[str] = None,
    **kwargs: Any,
) -> List[Dict[str, Any]]:
    """Flag trails duplicating delivery: S3 and CloudWatch Logs both enabled.

    Savings require volume estimates; this checker is conservative and emits
    potential_saving=None while surfacing price *rates* in signals.
    """
    log = _logger(kwargs.get("logger") or logger)

    region, norm_args = _split_region_from_args(args, kwargs)

    try:
        writer, ct = _extract_writer_client(norm_args, kwargs)
    except TypeError as exc:
        log.warning("[check_cloudtrail_s3_cwlogs_duplication] Skipping: %s", exc)
        return []

    if not region:
        region = _infer_region_from_client(ct)

    owner = _resolve_owner_id(account_id)
    if not (owner and chk.WRITE_ROW):
        log.warning("[check_cloudtrail_s3_cwlogs_duplication] Skipping: missing config.")
        return []

    trails_summ = _list_trails(ct)
    if not trails_summ:
        return []

    rows: List[Dict[str, Any]] = []

    # Price rates (for context in signals)
    try:
        cwl_ing_gb = float(chk.safe_price("CWL", "LOG_INGEST_GB", 0.0))  # type: ignore[arg-type]
    except Exception:  # pylint: disable=broad-except
        cwl_ing_gb = 0.0
    try:
        s3_gb_mo = float(chk.safe_price("S3", "STANDARD_GB_MONTH", 0.0))  # type: ignore[arg-type]
    except Exception:  # pylint: disable=broad-except
        s3_gb_mo = 0.0

    for t in trails_summ:
        arn = str(t.get("TrailARN") or "")
        if not arn:
            continue

        try:
            full = _get_trail(ct, arn)
            status = _get_trail_status(ct, arn)
        except ClientError as exc:
            log.warning("[cloudtrail] get_trail/get_status failed for %s: %s", arn, exc)
            continue

        is_logging = bool(status.get("IsLogging"))
        if not is_logging:
            continue

        s3_bucket = full.get("S3BucketName")
        cw_group = full.get("CloudWatchLogsLogGroupArn")
        cw_role = full.get("CloudWatchLogsRoleArn")
        cw_enabled = bool(cw_group and cw_role)

        # Duplication when both sinks are enabled
        if s3_bucket and cw_enabled:
            name = str(full.get("Name") or arn)
            created = _to_utc_iso(full.get("CreationTime"))
            insight = _get_insight_enabled(ct, arn)

            flags = ["DuplicationS3andCWL"]
            signals = _signals_str(
                {
                    "multi_region": bool(full.get("IsMultiRegionTrail")),
                    "insight_enabled": insight,
                    "cwlogs_enabled": cw_enabled,
                    "cwl_ingest_usd_per_gb": cwl_ing_gb,
                    "s3_storage_usd_per_gb_mo": s3_gb_mo,
                }
            )

            try:
                chk.WRITE_ROW(  # type: ignore[call-arg]
                    writer=writer,
                    resource_id=arn,
                    name=name,
                    owner_id=owner,  # type: ignore[arg-type]
                    resource_type="CloudTrail",
                    region=region,
                    state="Active",
                    creation_date=created,
                    estimated_cost="",
                    potential_saving=None,  # unknown volume; conservative
                    flags=flags,
                    confidence=70,
                    signals=signals,
                )
            except Exception as exc:  # pylint: disable=broad-except
                log.warning("[cloudtrail] write_row(dup) failed: %s", exc)

            rows.append({"arn": arn, "name": name, "reason": "DuplicationS3andCWL"})

    return rows
