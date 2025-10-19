"""Checker: AWS KMS Customer-Managed Keys (CMKs).

Finds customer-managed KMS keys and flags those that appear unused within a
lookback window using CloudTrail, plus other hygiene issues (disabled, pending
deletion, rotation disabled). Outputs Flags, Estimated_Cost_USD, Potential_Saving_USD,
and a compact Signals string.

"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple

from botocore.exceptions import ClientError

from core.retry import retry_with_backoff
from aws_checkers import config


# ----------------------------- helpers --------------------------------- #

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


def _signals_str(pairs: Dict[str, object]) -> str:
    """Build compact Signals cell from k=v pairs; skip Nones/empties."""
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


def _extract_writer_kms_cloudtrail(
    args: Tuple[Any, ...],
    kwargs: Dict[str, Any],
) -> Tuple[Any, Any, Any]:
    """Accept writer/kms/cloudtrail passed positionally or by keyword; prefer keywords."""
    writer = kwargs.get("writer", args[0] if len(args) >= 1 else None)
    kms = kwargs.get("kms", args[1] if len(args) >= 2 else None)
    cloudtrail = kwargs.get("cloudtrail", args[2] if len(args) >= 3 else None)
    if writer is None or kms is None or cloudtrail is None:
        raise TypeError(
            "check_kms_customer_managed_keys expected 'writer', 'kms', and 'cloudtrail' "
            f"(got writer={writer!r}, kms={kms!r}, cloudtrail={cloudtrail!r})"
        )
    return writer, kms, cloudtrail


# KMS data-plane operations that indicate real usage.
_USAGE_EVENTS: frozenset[str] = frozenset(
    {
        "Encrypt",
        "Decrypt",
        "ReEncrypt",
        "ReEncryptFrom",
        "ReEncryptTo",
        "GenerateDataKey",
        "GenerateDataKeyWithoutPlaintext",
        "GenerateDataKeyPair",
        "GenerateDataKeyPairWithoutPlaintext",
        "Sign",
        "Verify",
        # For asymmetric keys:
        "GetPublicKey",
    }
)


def _cloudtrail_has_recent_kms_usage(
    cloudtrail,
    key_arn: str,
    key_id: str,
    start_time: datetime,
    end_time: datetime,
    log: logging.Logger,
) -> bool:
    """
    Return True if CloudTrail shows at least one usage event for the key
    between start_time and end_time (inclusive).
    Tries both ResourceName=key_arn and ResourceName=key_id.
    """
    def _lookup(resource_name: str) -> bool:
        paginator = cloudtrail.get_paginator("lookup_events")
        for page in paginator.paginate(
            LookupAttributes=[{"AttributeKey": "ResourceName", "AttributeValue": resource_name}],
            StartTime=start_time,
            EndTime=end_time,
        ):
            for event in page.get("Events", []):
                try:
                    if event.get("EventSource") != "kms.amazonaws.com":
                        continue
                    # EventName is directly on the event; still, be defensive:
                    event_name = event.get("EventName")
                    if event_name in _USAGE_EVENTS:
                        return True
                    # Fallback: parse CloudTrail event JSON for deeper signals if needed
                    event_data = event.get("CloudTrailEvent")
                    if event_data:
                        data = json.loads(event_data)
                        name = data.get("eventName")
                        if name in _USAGE_EVENTS:
                            return True
                except Exception:  # pylint: disable=broad-except
                    # If parsing fails, just ignore this event
                    continue
        return False

    # Try matching by ARN first, then by key_id.
    if _lookup(key_arn):
        return True
    if _lookup(key_id):
        return True
    log.debug("[kms usage] No usage found for %s in CloudTrail within window.", key_arn)
    return False


def _first_alias_for_key(kms, key_id: str) -> Optional[str]:
    """Return the first alias name (e.g., 'alias/app/key'), if any."""
    try:
        resp = kms.list_aliases(KeyId=key_id)
        for alias in resp.get("Aliases", []) or []:
            name = alias.get("AliasName")
            if name:
                return name
    except ClientError:
        # Ignore alias lookup errors
        return None
    return None


# ------------------------------ checker -------------------------------- #

@retry_with_backoff(exceptions=(ClientError,))
def check_kms_customer_managed_keys(  # pylint: disable=unused-argument
    *args,
    logger: Optional[logging.Logger] = None,
    lookback_days: int = 90,
    **kwargs,
) -> None:
    """
    Enumerate customer-managed KMS keys and write CSV rows with Flags, Estimated_Cost_USD,
    Potential_Saving_USD and Signals.

    Flags:
      - CustomerManagedKeyUnused          (no data-plane usage in lookback window)
      - CustomerManagedKeyDisabled        (KeyState != 'Enabled')
      - CustomerManagedKeyPendingDeletion (KeyState == 'PendingDeletion')
      - CustomerManagedKeyNoRotation      (rotation is False, when queryable)

    Potential savings heuristic:
      - If key is pending deletion or disabled: potential_saving = estimated_cost
      - Else if unused in lookback window:     potential_saving = estimated_cost
      - Else:                                  potential_saving = 0.0
    """
    _require_config()
    log = _logger(logger)

    writer, kms, cloudtrail = _extract_writer_kms_cloudtrail(args, kwargs)

    region = getattr(getattr(kms, "meta", None), "region_name", "") or ""
    now_utc = datetime.now(timezone.utc).replace(microsecond=0)
    start_time = now_utc - timedelta(days=lookback_days)

    # Base monthly price per CMK (fallback to 0.0 if not found in pricebook)
    price_per_key = _safe_price("KMS", "CMK_MONTH")

    try:
        key_paginator = kms.get_paginator("list_keys")
        for key_page in key_paginator.paginate():
            for key_ref in key_page.get("Keys", []) or []:
                key_id = key_ref.get("KeyId")
                if not key_id:
                    continue

                # Describe to filter for CUSTOMER-managed + richer metadata
                try:
                    meta_resp = kms.describe_key(KeyId=key_id)
                except ClientError as exc:
                    log.debug("DescribeKey failed for %s: %s", key_id, exc)
                    continue

                meta = (meta_resp or {}).get("KeyMetadata", {}) or {}
                key_manager = meta.get("KeyManager")  # 'CUSTOMER' or 'AWS'
                if key_manager != "CUSTOMER":
                    continue  # we only report customer-managed keys

                key_arn = meta.get("Arn", key_id)
                key_state = meta.get("KeyState")
                enabled = key_state == "Enabled"
                pending_deletion = key_state == "PendingDeletion"
                key_spec = meta.get("KeySpec")
                key_usage = meta.get("KeyUsage")
                origin = meta.get("Origin")
                multi_region = bool(meta.get("MultiRegion"))
                creation_date = meta.get("CreationDate")
                deletion_date = meta.get("DeletionDate")
                rotation_enabled: Optional[bool] = None

                # Rotation is only supported for certain symmetric keys; ignore errors.
                try:
                    rot_resp = kms.get_key_rotation_status(KeyId=key_id)
                    rotation_enabled = bool(rot_resp.get("KeyRotationEnabled"))
                except ClientError:
                    rotation_enabled = None

                alias_name = _first_alias_for_key(kms, key_id)

                # Determine usage in CloudTrail within the lookback window
                used_recently = _cloudtrail_has_recent_kms_usage(
                    cloudtrail=cloudtrail,
                    key_arn=key_arn,
                    key_id=key_id,
                    start_time=start_time,
                    end_time=now_utc,
                    log=log,
                )

                flags: List[str] = []
                if not used_recently:
                    flags.append("CustomerManagedKeyUnused")
                if not enabled:
                    flags.append("CustomerManagedKeyDisabled")
                if pending_deletion:
                    flags.append("CustomerManagedKeyPendingDeletion")
                if rotation_enabled is False:
                    flags.append("CustomerManagedKeyNoRotation")

                estimated_cost = price_per_key
                potential_saving = 0.0
                if pending_deletion or (not enabled) or (not used_recently):
                    potential_saving = estimated_cost

                signals = _signals_str(
                    {
                        "Region": region,
                        "KeyId": key_id,
                        "Arn": key_arn,
                        "Alias": alias_name or "",
                        "KeyState": key_state,
                        "Enabled": enabled,
                        "Manager": key_manager,
                        "MultiRegion": multi_region,
                        "KeySpec": key_spec,
                        "KeyUsage": key_usage,
                        "Origin": origin,
                        "RotationEnabled": rotation_enabled,
                        "CreationDate": _to_utc_iso(creation_date),
                        "DeletionDate": _to_utc_iso(deletion_date),
                        "UsedRecently": used_recently,
                        "LookbackDays": lookback_days,
                    }
                )

                # type: ignore[call-arg]
                config.WRITE_ROW(
                    writer=writer,
                    resource_id=key_arn,
                    name=alias_name or key_arn,  # prefer alias for readability
                    owner_id=config.ACCOUNT_ID,  # type: ignore[arg-type]
                    resource_type="KMSCustomerManagedKey",
                    estimated_cost=estimated_cost,
                    potential_saving=potential_saving,
                    flags=flags if flags else [""],  
                    confidence=100,
                    signals=signals,
                )

                log.info(
                    "[check_kms_customer_managed_keys] Wrote key: %s (flags=%s est=%.2f save=%.2f)",
                    key_arn,
                    flags,
                    estimated_cost,
                    potential_saving,
                )

    except ClientError as exc:
        log.error("Error checking KMS Customer-Managed Keys: %s", exc)
        raise
