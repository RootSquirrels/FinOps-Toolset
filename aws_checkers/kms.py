"""Checkers: AWS KMS – Customer Managed Keys.

Contains:
  - check_kms_customer_managed_keys:
      Flags unused/disabled/pending-deletion/no-rotation/no-alias keys and
      estimates monthly key cost and potential savings.

Performance:
  - Only one CloudTrail lookup per key (by ResourceName).
  - Never raises on CloudTrail errors → avoids function-level backoff retries.
  - Aliases fetched once and mapped to KeyIds.

Design:
  - Dependencies via finops_toolset.checkers.config.setup(...).
  - Tolerant signature for run_check; no returns.
  - Timezone-aware datetimes; lazy %s logging; lines ≤ 100 chars.
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


def _extract_writer_kms_ct(
    args: Tuple[Any, ...],
    kwargs: Dict[str, Any],
) -> Tuple[Any, Any, Any]:
    """Accept writer/kms/cloudtrail (positional or keyword)."""
    writer = kwargs.get("writer", args[0] if len(args) >= 1 else None)
    kms = kwargs.get("kms", args[1] if len(args) >= 2 else None)
    cloudtrail = kwargs.get("cloudtrail", args[2] if len(args) >= 3 else None)
    if writer is None or kms is None or cloudtrail is None:
        raise TypeError(
            "Expected 'writer', 'kms' and 'cloudtrail' "
            f"(got writer={writer!r}, kms={kms!r}, cloudtrail={cloudtrail!r})"
        )
    return writer, kms, cloudtrail


def _list_customer_keys(kms, log: logging.Logger) -> List[str]:
    """List KeyIds for CUSTOMER managed keys."""
    key_ids: List[str] = []
    try:
        paginator = kms.get_paginator("list_keys")
        for page in paginator.paginate():
            for k in page.get("Keys", []) or []:
                kid = k.get("KeyId")
                if not kid:
                    continue
                # Filter after describe_key
                try:
                    md = kms.describe_key(KeyId=kid).get("KeyMetadata", {}) or {}
                    if (md.get("KeyManager") or "").upper() == "CUSTOMER":
                        key_ids.append(kid)
                except ClientError as exc:  # skip keys we cannot describe
                    log.debug("[kms] describe_key failed for %s: %s", kid, exc)
    except ClientError as exc:
        log.error("[kms] list_keys failed: %s", exc)
    return key_ids


def _alias_map(kms, log: logging.Logger) -> Dict[str, List[str]]:
    """Return {TargetKeyId: [alias/...]} across the account/region."""
    out: Dict[str, List[str]] = {}
    try:
        paginator = kms.get_paginator("list_aliases")
        for page in paginator.paginate():
            for a in page.get("Aliases", []) or []:
                tgt = a.get("TargetKeyId")
                name = a.get("AliasName")
                if tgt and name:
                    out.setdefault(tgt, []).append(name)
    except ClientError as exc:
        log.debug("[kms] list_aliases failed: %s", exc)
    return out


def _rotation_eligible(md: Dict[str, Any]) -> bool:
    """Only symmetric CMKs support automatic rotation."""
    spec = (md.get("KeySpec") or "").upper()
    # SYMMETRIC_DEFAULT is the common one for AES-256 keys
    return spec.startswith("SYMMETRIC")


def _rotation_enabled(kms, key_id: str, log: logging.Logger) -> Optional[bool]:
    try:
        resp = kms.get_key_rotation_status(KeyId=key_id)
        return bool(resp.get("KeyRotationEnabled"))
    except ClientError as exc:
        # For asymmetric keys/KMS constraints, this may fail → treat as unknown
        log.debug("[kms] get_key_rotation_status failed for %s: %s", key_id, exc)
        return None


def _latest_kms_use_fast(
    cloudtrail,
    key_arn: str,
    lookback_days: int,
    log: logging.Logger,
) -> Optional[datetime]:
    """
    Best-effort 'last used' from CloudTrail with a single LookupEvents call.
    Returns a timezone-aware datetime or None. Never raises.
    """
    if cloudtrail is None:
        return None

    end = datetime.now(timezone.utc).replace(microsecond=0)
    start = end - timedelta(days=int(lookback_days))

    try:
        resp = cloudtrail.lookup_events(
            LookupAttributes=[
                {"AttributeKey": "ResourceName", "AttributeValue": key_arn}
            ],
            StartTime=start,
            EndTime=end,
            MaxResults=50,  # one page only
        )
    except ClientError as exc:
        log.debug("[kms] lookup_events skipped for %s: %s", key_arn, exc)
        return None

    latest = None
    for e in resp.get("Events") or []:
        et = e.get("EventTime")
        if isinstance(et, datetime):
            et = et if et.tzinfo else et.replace(tzinfo=timezone.utc)
            latest = et if latest is None else max(latest, et)
    return latest


# ------------------------------ main checker ----------------------------- #

@retry_with_backoff(exceptions=(ClientError,))
def check_kms_customer_managed_keys(  # pylint: disable=unused-argument
    *args,
    logger: Optional[logging.Logger] = None,
    lookback_days: int = 90,
    use_cloudtrail: bool = True,
    **kwargs,
) -> None:
    """
    Flag:
      - KMSKeyUnused            : no CloudTrail events in lookback window
      - KMSKeyDisabled          : key state != Enabled
      - KMSKeyPendingDeletion   : key is PendingDeletion
      - KMSKeyNoRotation        : rotation not enabled (if eligible)
      - KMSKeyNoAlias           : key has no aliases

    Estimated cost:
      - price("KMS","CMK_MONTH") per key (heuristic)
      - potential_saving = estimated_cost if unused (heuristic)
    """
    log = _logger(kwargs.get("logger") or logger)

    try:
        writer, kms, cloudtrail = _extract_writer_kms_ct(args, kwargs)
    except TypeError as exc:
        log.warning("[check_kms_customer_managed_keys] Skipping: %s", exc)
        return
    if not (config.ACCOUNT_ID and config.WRITE_ROW and config.GET_PRICE):
        log.warning("[check_kms_customer_managed_keys] Skipping: checker config not provided.")
        return

    region = getattr(getattr(kms, "meta", None), "region_name", "") or ""

    # Preload aliases for all keys to avoid per-key calls
    aliases_by_key = _alias_map(kms, log)

    # List CUSTOMER keys
    key_ids = _list_customer_keys(kms, log)
    if not key_ids:
        log.info("[check_kms_customer_managed_keys] No customer keys in %s", region)
        return

    price_key_month = config.safe_price("KMS", "CMK_MONTH", 1.0)

    for kid in key_ids:
        try:
            d = kms.describe_key(KeyId=kid).get("KeyMetadata", {}) or {}
        except ClientError as exc:
            log.debug("[kms] describe_key failed for %s: %s", kid, exc)
            continue

        arn = d.get("Arn") or kid
        state = (d.get("KeyState") or "").upper()
        created = d.get("CreationDate")
        deletion_date = d.get("DeletionDate")
        key_spec = d.get("KeySpec")
        multi_region = bool(d.get("MultiRegion"))
        manager = d.get("KeyManager")
        origin = d.get("Origin")
        aliases = aliases_by_key.get(kid, [])  # may be empty

        # Rotation
        rot_enabled = None
        if _rotation_eligible(d):
            rot_enabled = _rotation_enabled(kms, kid, log)

        # CloudTrail last use (fast/optional)
        last_used_dt = None
        if use_cloudtrail:
            last_used_dt = _latest_kms_use_fast(cloudtrail, arn, lookback_days, log)

        # Flags
        flags: List[str] = []
        if state != "ENABLED":
            flags.append("KMSKeyDisabled")
        if state == "PENDINGDELETION":
            flags.append("KMSKeyPendingDeletion")
        if _rotation_eligible(d) and rot_enabled is False:
            flags.append("KMSKeyNoRotation")
        if not aliases:
            flags.append("KMSKeyNoAlias")

        unused = False
        if use_cloudtrail:
            if last_used_dt is None:
                unused = True
            else:
                cutoff = datetime.now(timezone.utc) - timedelta(days=int(lookback_days))
                unused = last_used_dt < cutoff
        if unused:
            flags.append("KMSKeyUnused")

        if not flags:
            log.info("[kms] Processed key: %s (no flags)", kid)
            continue

        estimated_cost = float(price_key_month)
        potential_saving = estimated_cost if unused else 0.0

        signals = _signals_str(
            {
                "Region": region,
                "KeyId": kid,
                "Arn": arn,
                "State": state,
                "KeySpec": key_spec,
                "Manager": manager,
                "Origin": origin,
                "MultiRegion": multi_region,
                "Aliases": ",".join(aliases),
                "CreatedAt": _to_utc_iso(created) if isinstance(created, datetime) else None,
                "DeletionAt": _to_utc_iso(deletion_date)
                if isinstance(deletion_date, datetime) else None,
                "LastUsedAt": _to_utc_iso(last_used_dt) if last_used_dt else None,
                "LookbackDays": lookback_days,
                "RotationEligible": _rotation_eligible(d),
                "RotationEnabled": rot_enabled,
            }
        )

        # Name hint: first alias without 'alias/' prefix, else KeyId
        name = aliases[0].split("/", 1)[-1] if aliases else kid

        try:
            # type: ignore[call-arg]
            config.WRITE_ROW(
                writer=writer,
                resource_id=arn,
                name=name,
                owner_id=config.ACCOUNT_ID,  # type: ignore[arg-type]
                resource_type="KMSKey",
                estimated_cost=estimated_cost,
                potential_saving=potential_saving,
                flags=flags,
                confidence=100,
                signals=signals,
            )
        except Exception as exc:  # pylint: disable=broad-except
            log.warning("[kms] write_row failed for %s: %s", kid, exc)

        log.info("[kms] Wrote key: %s (flags=%s)", kid, flags)
