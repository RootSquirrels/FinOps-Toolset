"""Checkers: Amazon S3 – lifecycle/encryption/PAB/IA tiering/multipart/emptiness.

New:
- CloudWatchBatcher enrichment for BucketSizeBytes & NumberOfObjects (per bucket region).
- Estimated monthly storage cost from size breakdown (per storage class).
- Potential saving heuristics for lifecycle/tiering checks.

Design
- Single per-client S3 inventory cache (no redundant S3 calls).
- Regional CloudWatch queries only for buckets whose region == cloudwatch.meta.region_name.
- Tag enrichment always present (TagAppId/TagApp/TagEnv), "NULL" when missing.
- Lines ≤ 100, f-strings (no lazy %% formatting), pylint-friendly.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple

from botocore.exceptions import ClientError

from aws_checkers import config
from aws_checkers.common import (
    _logger,
)
from core.retry import retry_with_backoff
from core.cloudwatch import CloudWatchBatcher

# ------------------------------ module caches ----------------------------- #

_INV_CACHE: Dict[int, Dict[str, Dict[str, Any]]] = {}

# ------------------------------ pricing helpers --------------------------- #

# StorageType -> (config price key, default $/GB-month)
_S3_PRICE_KEYS: Dict[str, Tuple[str, float]] = {
    "StandardStorage": ("STANDARD_GB_MONTH", 0.023),
    "StandardIAStorage": ("STANDARD_IA_GB_MONTH", 0.0125),
    "OneZoneIAStorage": ("ONEZONE_IA_GB_MONTH", 0.01),
    "IntelligentTieringFAStorage": ("INTELLIGENT_TIERING_FA_GB_MONTH", 0.023),
    "IntelligentTieringIAStorage": ("INTELLIGENT_TIERING_IA_GB_MONTH", 0.0125),
    "GlacierInstantRetrievalStorage": ("GLACIER_IR_GB_MONTH", 0.004),
    "GlacierStorage": ("GLACIER_GB_MONTH", 0.004),
    "DeepArchiveStorage": ("DEEP_ARCHIVE_GB_MONTH", 0.00099),
    # Add any others you need; RRS omitted by design
}

def _p_s3(key: str, default: float) -> float:
    return float(config.safe_price("S3", key, default))

def _gb(bytes_val: float) -> float:
    return float(bytes_val) / (1024.0 ** 3)

# Heuristics (tunable via pricing map if you want)
# Fraction of StandardStorage we assume could move to IA under lifecycle policies.
def _tiering_pct_default() -> float:
    return float(config.safe_price("S3", "TIERING_PCT", 0.20))

def _tiering_pct_no_lifecycle_default() -> float:
    return float(config.safe_price("S3", "NO_LIFECYCLE_TIERING_PCT", 0.15))

# -------------------------------- helpers -------------------------------- #

def _nonnull_tag(val: Optional[str]) -> str:
    return "NULL" if not val else val

def _extract_writer_s3(
    args: Tuple[Any, ...],
    kwargs: Dict[str, Any],
) -> Tuple[Any, Any]:
    writer = kwargs.get("writer", args[0] if len(args) >= 1 else None)
    s3 = kwargs.get("s3", args[1] if len(args) >= 2 else None)
    if writer is None or s3 is None:
        raise TypeError(f"Expected 'writer' and 's3' (got writer={writer!r}, s3={s3!r})")
    return writer, s3

def _extract_writer_s3_cw(
    args: Tuple[Any, ...],
    kwargs: Dict[str, Any],
) -> Tuple[Any, Any, Optional[Any]]:
    writer = kwargs.get("writer", args[0] if len(args) >= 1 else None)
    s3 = kwargs.get("s3", args[1] if len(args) >= 2 else None)
    cloudwatch = kwargs.get("cloudwatch", args[2] if len(args) >= 3 else None)
    if writer is None or s3 is None:
        raise TypeError(f"Expected 'writer' and 's3' (got writer={writer!r}, s3={s3!r})")
    return writer, s3, cloudwatch

def _pick_tag(tags: Dict[str, str], keys: List[str]) -> Optional[str]:
    low = {k.lower(): v for k, v in tags.items()}
    for k in keys:
        v = low.get(k.lower())
        if v:
            return v
    return None

def _bucket_region(s3, name: str, log: logging.Logger) -> str:
    try:
        r = s3.get_bucket_location(Bucket=name) or {}
        loc = r.get("LocationConstraint")
        return "us-east-1" if not loc else str(loc)
    except ClientError as exc:
        log.debug(f"[s3] get_bucket_location {name} failed: {exc}")
        return getattr(getattr(s3, "meta", None), "region_name", "") or ""

def _bucket_versioning_enabled(s3, name: str, log: logging.Logger) -> bool:
    try:
        v = s3.get_bucket_versioning(Bucket=name) or {}
        return str(v.get("Status", "")).upper() == "ENABLED"
    except ClientError as exc:
        log.debug(f"[s3] get_bucket_versioning {name} failed: {exc}")
        return False

def _bucket_lifecycle_info(s3, name: str, log: logging.Logger) -> Dict[str, Any]:
    out: Dict[str, Any] = {
        "count": 0,
        "has_ia_transition": False,
        "has_glacier_transition": False,
        "abort_incomplete_days": None,
    }
    try:
        r = s3.get_bucket_lifecycle_configuration(Bucket=name) or {}
        rules = r.get("Rules", []) or []
        out["count"] = len(rules)

        def _class_is_ia(sc: str) -> bool:
            s = sc.upper()
            return "STANDARD_IA" in s or "ONEZONE_IA" in s or "INTELLIGENT_TIERING" in s

        def _class_is_glacier(sc: str) -> bool:
            s = sc.upper()
            return "GLACIER" in s or "DEEP_ARCHIVE" in s

        for rule in rules:
            for tr in rule.get("Transitions", []) or []:
                sc = str(tr.get("StorageClass", "")).upper()
                if _class_is_ia(sc):
                    out["has_ia_transition"] = True
                if _class_is_glacier(sc):
                    out["has_glacier_transition"] = True
            abort_cfg = (rule.get("AbortIncompleteMultipartUpload") or {})
            days = abort_cfg.get("DaysAfterInitiation")
            if isinstance(days, int):
                prev = out["abort_incomplete_days"]
                out["abort_incomplete_days"] = min(days, prev) if isinstance(prev, int) else days
        return out
    except ClientError as exc:
        err = (exc.response or {}).get("Error", {}) if hasattr(exc, "response") else {}
        code = str(err.get("Code", ""))
        if code in ("NoSuchLifecycleConfiguration", "NoSuchLifecycleConfigurationFault"):
            return out
        log.debug(f"[s3] get_bucket_lifecycle_configuration {name} failed: {exc}")
        return out

def _bucket_tags(s3, name: str, log: logging.Logger) -> Dict[str, str]:
    try:
        r = s3.get_bucket_tagging(Bucket=name) or {}
        tagset = r.get("TagSet", []) or []
        out: Dict[str, str] = {}
        for t in tagset:
            k, v = t.get("Key"), t.get("Value")
            if k:
                out[str(k)] = "" if v is None else str(v)
        return out
    except ClientError as exc:
        log.debug(f"[s3] get_bucket_tagging {name} failed: {exc}")
        return {}

def _bucket_encryption_enabled(s3, name: str, log: logging.Logger) -> bool:
    try:
        r = s3.get_bucket_encryption(Bucket=name) or {}
        rules = (r.get("ServerSideEncryptionConfiguration") or {}).get("Rules", []) or []
        for rule in rules:
            sse = (rule.get("ApplyServerSideEncryptionByDefault") or {}).get("SSEAlgorithm")
            if sse:
                return True
        return False
    except ClientError as exc:
        err = (exc.response or {}).get("Error", {}) if hasattr(exc, "response") else {}
        code = str(err.get("Code", ""))
        if code in ("ServerSideEncryptionConfigurationNotFoundError",):
            return False
        log.debug(f"[s3] get_bucket_encryption {name} failed: {exc}")
        return False

def _bucket_pab_config(s3, name: str, log: logging.Logger) -> Dict[str, bool]:
    try:
        r = s3.get_public_access_block(Bucket=name) or {}
        return (r.get("PublicAccessBlockConfiguration") or {}) if r else {}
    except ClientError as exc:
        log.debug(f"[s3] get_public_access_block {name} failed: {exc}")
        return {}

def _bucket_logging_enabled(s3, name: str, log: logging.Logger) -> bool:
    try:
        r = s3.get_bucket_logging(Bucket=name) or {}
        return bool((r.get("LoggingEnabled") or {}).get("TargetBucket"))
    except ClientError as exc:
        log.debug(f"[s3] get_bucket_logging {name} failed: {exc}")
        return False

def _build_inventory(s3, log: logging.Logger) -> Dict[str, Dict[str, Any]]:
    key = id(s3)
    if key in _INV_CACHE:
        return _INV_CACHE[key]

    inv: Dict[str, Dict[str, Any]] = {}
    try:
        resp = s3.list_buckets() or {}
        buckets = resp.get("Buckets", []) or []
    except ClientError as exc:
        log.error(f"[s3] list_buckets failed: {exc}")
        buckets = []

    for b in buckets:
        name = b.get("Name")
        if not name:
            continue
        region = _bucket_region(s3, name, log)
        versioning = _bucket_versioning_enabled(s3, name, log)
        lc = _bucket_lifecycle_info(s3, name, log)
        tags = _bucket_tags(s3, name, log)
        enc = _bucket_encryption_enabled(s3, name, log)
        pab_cfg = _bucket_pab_config(s3, name, log)
        logging_on = _bucket_logging_enabled(s3, name, log)

        inv[name] = {
            "region": region,
            "versioning": versioning,
            "lifecycle": lc,
            "tags": tags,
            "encryption": enc,
            "pab": pab_cfg,
            "logging": logging_on,
        }

    _INV_CACHE[key] = inv
    return inv

def _tag_triplet(tags: Dict[str, str]) -> Tuple[str, str, str]:
    app_id = _pick_tag(tags, ["app_id", "application_id", "app-id"])
    app = _pick_tag(tags, ["app", "application", "service"])
    env = _pick_tag(tags, ["environment", "env", "stage"])
    return _nonnull_tag(app_id), _nonnull_tag(app), _nonnull_tag(env)

# ------------------------- CloudWatch enrichment -------------------------- #

def _latest_from_result(res: Any) -> Optional[float]:
    # Accepts list[(ts, val)] or dict with 'Values'
    if res is None:
        return None
    if isinstance(res, list) and res:
        try:
            return float(res[-1][1])
        except Exception:  # pylint: disable=broad-except
            return None
    if isinstance(res, dict):
        vals = res.get("Values") or res.get("values") or []
        if vals:
            try:
                return float(vals[-1])
            except Exception:  # pylint: disable=broad-except
                return None
    return None

def _cw_sizes_for_region(
    cloudwatch,
    region: str,
    buckets: List[str],
    now_utc: datetime,
    log: logging.Logger,
) -> Dict[str, Dict[str, Any]]:
    """Query S3 metrics (BucketSizeBytes & NumberOfObjects) for given region buckets."""
    out: Dict[str, Dict[str, Any]] = {b: {"bytes": {}, "objects": None} for b in buckets}
    if not cloudwatch:
        return out

    cw_region = getattr(getattr(cloudwatch, "meta", None), "region_name", "") or ""
    if cw_region != region:
        # We only query metrics when CW client matches bucket region to avoid cross-region calls.
        return out

    # S3 metrics are daily; grab last 3 days to reduce nulls.
    start = (now_utc - timedelta(days=3)).replace(microsecond=0)
    end = now_utc.replace(microsecond=0)
    period = 86400
    try:
        cw = CloudWatchBatcher(region=region, client=cloudwatch)
        # NumberOfObjects (StorageType=AllStorageTypes)
        for b in buckets:
            dims = [("BucketName", b), ("StorageType", "AllStorageTypes")]
            cw.add_q(
                id_hint=f"obj_{b}",
                namespace="AWS/S3",
                metric="NumberOfObjects",
                dims=dims,
                stat="Average",
                period=period,
            )
        # BucketSizeBytes per StorageType we care about
        for b in buckets:
            for st in _S3_PRICE_KEYS.keys():
                dims = [("BucketName", b), ("StorageType", st)]
                cw.add_q(
                    id_hint=f"size_{b}_{st}",
                    namespace="AWS/S3",
                    metric="BucketSizeBytes",
                    dims=dims,
                    stat="Average",
                    period=period,
                )
        results = cw.execute(start=start, end=end)
    except ClientError as exc:
        log.debug(f"[s3] CloudWatch metrics unavailable in {region}: {exc}")
        return out
    except Exception as exc:  # pylint: disable=broad-except
        log.debug(f"[s3] CloudWatch batch error {region}: {exc}")
        return out

    # Parse results
    for b in buckets:
        # objects
        val = _latest_from_result(results.get(f"obj_{b}"))
        if val is not None:
            out[b]["objects"] = int(val)
        # sizes by class
        for st in _S3_PRICE_KEYS.keys():
            v = _latest_from_result(results.get(f"size_{b}_{st}"))
            if v is not None and v >= 0.0:
                out[b]["bytes"][st] = float(v)

    return out

def _storage_monthly_cost(bytes_by_class: Dict[str, float]) -> float:
    total = 0.0
    for st, (price_key, default_price) in _S3_PRICE_KEYS.items():
        b = float(bytes_by_class.get(st, 0.0))
        if b <= 0.0:
            continue
        gb_val = _gb(b)
        total += gb_val * _p_s3(price_key, default_price)
    return total

def _potential_tiering_saving(
    bytes_by_class: Dict[str, float],
    pct: float,
) -> float:
    std_b = float(bytes_by_class.get("StandardStorage", 0.0))
    if std_b <= 0.0 or pct <= 0.0:
        return 0.0
    std_gb = _gb(std_b)
    # Move 'pct' of Standard to Standard-IA as a heuristic
    price_std = _p_s3("STANDARD_GB_MONTH", 0.023)
    price_ia = _p_s3("STANDARD_IA_GB_MONTH", 0.0125)
    diff = max(0.0, price_std - price_ia)
    return std_gb * pct * diff

# ------------------------------- checkers -------------------------------- #

@retry_with_backoff(exceptions=(ClientError,))
def check_s3_lifecycle_hygiene(  # pylint: disable=unused-argument
    *args,
    logger: Optional[logging.Logger] = None,
    **kwargs,
) -> None:
    """
    Emit a single lifecycle hygiene row per bucket.

    Flags:
      - S3VersioningNoLifecycle  (versioning=Enabled & lifecycle.count == 0)
      - S3NoLifecycle            (versioning!=Enabled & lifecycle.count == 0)

    Uses CloudWatch (if provided) to include size/object counts and cost estimates.
    """
    log = _logger(kwargs.get("logger") or logger)
    try:
        writer, s3, cloudwatch = _extract_writer_s3_cw(args, kwargs)
    except TypeError as exc:
        log.warning(f"[check_s3_lifecycle_hygiene] Skipping: {exc}")
        return
    if not (config.ACCOUNT_ID and config.WRITE_ROW):
        log.warning("[check_s3_lifecycle_hygiene] Skipping: checker config not provided.")
        return

    inv = _build_inventory(s3, log)
    # Group buckets by region for CW queries
    region_buckets: Dict[str, List[str]] = {}
    for b, info in inv.items():
        if int((info.get("lifecycle") or {}).get("count") or 0) == 0:
            region_buckets.setdefault(str(info.get("region") or ""), []).append(b)

    now_utc = datetime.now(timezone.utc)
    cw_data: Dict[str, Dict[str, Any]] = {}
    for region, buckets in region_buckets.items():
        cw_data.update(_cw_sizes_for_region(cloudwatch, region, buckets, now_utc, log))

    pct = _tiering_pct_no_lifecycle_default()
    for bucket, info in inv.items():
        lc = info.get("lifecycle") or {}
        count = int(lc.get("count") or 0)
        if count > 0:
            continue

        region = str(info.get("region") or "")
        versioning = bool(info.get("versioning"))
        tags = info.get("tags") or {}
        app_id, app, env = _tag_triplet(tags)

        sizes = cw_data.get(bucket, {})
        by_class = sizes.get("bytes", {}) if isinstance(sizes, dict) else {}
        objects = sizes.get("objects") if isinstance(sizes, dict) else None

        est = _storage_monthly_cost(by_class) if by_class else 0.0
        pot = _potential_tiering_saving(by_class, pct) if by_class else 0.0

        flags = ["S3VersioningNoLifecycle" if versioning else "S3NoLifecycle"]
        signals = {
            "Region": region,
            "Bucket": bucket,
            "LifecycleRules": count,
            "VersioningEnabled": versioning,
            "Objects": objects if objects is not None else "NULL",
            "SizeGB": round(sum(_gb(v) for v in by_class.values()), 3) if by_class else "NULL",
            "TieringPctHeuristic": pct,
        }
        config.WRITE_ROW(
            resource_id=bucket,
            resource_type="S3Bucket",
            writer=writer,
            name=bucket,
            region=region,
            owner_id=config.ACCOUNT_ID,
            flags=flags,
            signals=signals,
            app_id=app_id,
            app=app,
            env=env,
            estimated_cost=est,
            potential_saving=pot,
        )
        log.info(f"[s3] Wrote lifecycle hygiene for bucket: {bucket}")

@retry_with_backoff(exceptions=(ClientError,))
def check_s3_no_default_encryption(  # pylint: disable=unused-argument
    *args,
    logger: Optional[logging.Logger] = None,
    **kwargs,
) -> None:
    """Flag buckets without default SSE (KMS or S3-managed)."""
    log = _logger(kwargs.get("logger") or logger)
    try:
        writer, s3, cloudwatch = _extract_writer_s3_cw(args, kwargs)
    except TypeError as exc:
        log.warning(f"[check_s3_no_default_encryption] Skipping: {exc}")
        return
    if not (config.ACCOUNT_ID and config.WRITE_ROW):
        log.warning("[check_s3_no_default_encryption] Skipping: checker config not provided.")
        return

    inv = _build_inventory(s3, log)
    # Optional cost context
    region_buckets: Dict[str, List[str]] = {}
    for b, info in inv.items():
        if not bool(info.get("encryption")):
            region_buckets.setdefault(str(info.get("region") or ""), []).append(b)

    now_utc = datetime.now(timezone.utc)
    cw_data: Dict[str, Dict[str, Any]] = {}
    for region, buckets in region_buckets.items():
        cw_data.update(_cw_sizes_for_region(cloudwatch, region, buckets, now_utc, log))

    for bucket, info in inv.items():
        if bool(info.get("encryption")):
            continue

        region = str(info.get("region") or "")
        tags = info.get("tags") or {}
        app_id, app, env = _tag_triplet(tags)

        sizes = cw_data.get(bucket, {})
        by_class = sizes.get("bytes", {}) if isinstance(sizes, dict) else {}
        objects = sizes.get("objects") if isinstance(sizes, dict) else None
        est = _storage_monthly_cost(by_class) if by_class else 0.0

        signals = {
            "Region": region,
            "Bucket": bucket,
            "DefaultEncryption": False,
            "Objects": objects if objects is not None else "NULL",
            "SizeGB": round(sum(_gb(v) for v in by_class.values()), 3) if by_class else "NULL",

        }

        config.WRITE_ROW(
            resource_id=bucket,
            resource_type="S3Bucket",
            writer=writer,
            name=bucket,
            region=region,
            owner_id=config.ACCOUNT_ID,
            flags=["S3NoDefaultEncryption"],
            signals=signals,
            app_id=app_id,
            app=app,
            env=env,
            estimated_cost=est,
            potential_saving=0.0,
        )
        log.info(f"[s3] Wrote no-default-encryption: {bucket}")

@retry_with_backoff(exceptions=(ClientError,))
def check_s3_public_access_block_off(  # pylint: disable=unused-argument
    *args,
    logger: Optional[logging.Logger] = None,
    **kwargs,
) -> None:
    """Flag buckets with missing or partially disabled Public Access Block settings."""
    log = _logger(kwargs.get("logger") or logger)
    try:
        writer, s3 = _extract_writer_s3(args, kwargs)
    except TypeError as exc:
        log.warning(f"[check_s3_public_access_block_off] Skipping: {exc}")
        return
    if not (config.ACCOUNT_ID and config.WRITE_ROW):
        log.warning("[check_s3_public_access_block_off] Skipping: checker config not provided.")
        return

    inv = _build_inventory(s3, log)
    needed = {
        "BlockPublicAcls": True,
        "IgnorePublicAcls": True,
        "BlockPublicPolicy": True,
        "RestrictPublicBuckets": True,
    }

    for bucket, info in inv.items():
        cfg = info.get("pab") or {}
        region = str(info.get("region") or "")
        tags = info.get("tags") or {}
        app_id, app, env = _tag_triplet(tags)

        if not cfg:
            signals = {
                "Region": region,
                "Bucket": bucket,
                "PAB": "Missing",
            }

            config.WRITE_ROW(
                resource_id=bucket,
                resource_type="S3Bucket",
                writer=writer,
                name=bucket,
                region=region,
                owner_id=config.ACCOUNT_ID,
                flags=["S3PublicAccessBlockMissing"],
                signals=signals,
                app_id=app_id,
                app=app,
                env=env,
                estimated_cost=0.0,
                potential_saving=0.0,
            )
            log.info(f"[s3] Wrote PAB missing: {bucket}")
            continue

        partial = any(bool(cfg.get(k)) is not v for k, v in needed.items())
        if not partial:
            continue

        signals = {
            "Region": region,
            "Bucket": bucket,
            "PAB": "|".join(f"{k}={bool(cfg.get(k))}" for k in needed.keys()),
        }

        config.WRITE_ROW(
            resource_id=bucket,
            resource_type="S3Bucket",
            writer=writer,
            name=bucket,
            region=region,
            owner_id=config.ACCOUNT_ID,
            flags=["S3PublicAccessBlockPartial"],
            signals=signals,
            app_id=app_id,
            app=app,
            env=env,
            estimated_cost=0.0,
            potential_saving=0.0,
            )
        log.info(f"[s3] Wrote PAB partial: {bucket}")

@retry_with_backoff(exceptions=(ClientError,))
def check_s3_ia_tiering_candidates(  # pylint: disable=unused-argument
    *args,
    logger: Optional[logging.Logger] = None,
    **kwargs,
) -> None:
    """
    Flag buckets with lifecycle rules but NO transitions to IA/Intelligent/Glacier.
    Uses CW (if provided) to estimate cost and a potential saving heuristic.
    """
    log = _logger(kwargs.get("logger") or logger)
    try:
        writer, s3, cloudwatch = _extract_writer_s3_cw(args, kwargs)
    except TypeError as exc:
        log.warning(f"[check_s3_ia_tiering_candidates] Skipping: {exc}")
        return
    if not (config.ACCOUNT_ID and config.WRITE_ROW):
        log.warning("[check_s3_ia_tiering_candidates] Skipping: checker config not provided.")
        return

    inv = _build_inventory(s3, log)
    region_buckets: Dict[str, List[str]] = {}
    for b, info in inv.items():
        lc = info.get("lifecycle") or {}
        if int(lc.get("count") or 0) > 0 and not (lc.get("has_ia_transition") or
                                                  lc.get("has_glacier_transition")):
            region_buckets.setdefault(str(info.get("region") or ""), []).append(b)

    now_utc = datetime.now(timezone.utc)
    cw_data: Dict[str, Dict[str, Any]] = {}
    for region, buckets in region_buckets.items():
        cw_data.update(_cw_sizes_for_region(cloudwatch, region, buckets, now_utc, log))

    pct = _tiering_pct_default()
    for bucket, info in inv.items():
        lc = info.get("lifecycle") or {}
        count = int(lc.get("count") or 0)
        to_ia = bool(lc.get("has_ia_transition"))
        to_gl = bool(lc.get("has_glacier_transition"))
        if count <= 0 or to_ia or to_gl:
            continue

        region = str(info.get("region") or "")
        tags = info.get("tags") or {}
        app_id, app, env = _tag_triplet(tags)

        sizes = cw_data.get(bucket, {})
        by_class = sizes.get("bytes", {}) if isinstance(sizes, dict) else {}
        objects = sizes.get("objects") if isinstance(sizes, dict) else None

        est = _storage_monthly_cost(by_class) if by_class else 0.0
        pot = _potential_tiering_saving(by_class, pct) if by_class else 0.0

        signals = {
            "Region": region,
            "Bucket": bucket,
            "LifecycleRules": count,
            "HasIATransition": False,
            "HasGlacierTransition": False,
            "Objects": objects if objects is not None else "NULL",
            "SizeGB": round(sum(_gb(v) for v in by_class.values()), 3) if by_class else "NULL",
            "TieringPctHeuristic": pct,
        }
        config.WRITE_ROW(
            resource_id=bucket,
            resource_type="S3Bucket",
            writer=writer,
            name=bucket,
            region=region,
            owner_id=config.ACCOUNT_ID,
            flags=["S3NoIATieringTransitions"],
            signals=signals,
            app_id=app_id,
            app=app,
            env=env,
            estimated_cost=est,
            potential_saving=pot,
            )

        log.info(f"[s3] Wrote IA tiering candidate: {bucket}")

# ---------------------- Stale multipart uploads (age) --------------------- #

def _list_stale_multipart_uploads(
    s3,
    bucket: str,
    stale_days: int,
    log: logging.Logger,
) -> Tuple[int, Optional[int]]:
    key_marker: Optional[str] = None
    upload_id_marker: Optional[str] = None
    count = 0
    oldest_days: Optional[int] = None
    now_utc = datetime.now(timezone.utc).replace(microsecond=0)

    try:
        while True:
            params: Dict[str, Any] = {"Bucket": bucket, "MaxUploads": 1000}
            if key_marker:
                params["KeyMarker"] = key_marker
            if upload_id_marker:
                params["UploadIdMarker"] = upload_id_marker

            resp = s3.list_multipart_uploads(**params) or {}
            uploads = resp.get("Uploads", []) or []
            for up in uploads:
                dt = up.get("Initiated")
                if not isinstance(dt, datetime):
                    continue
                dt = dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
                age_days = int((now_utc - dt).total_seconds() // 86400)
                if age_days >= int(stale_days):
                    count += 1
                    oldest_days = age_days if oldest_days is None else max(oldest_days, age_days)

            if not resp.get("IsTruncated"):
                break
            key_marker = resp.get("NextKeyMarker")
            upload_id_marker = resp.get("NextUploadIdMarker")
    except ClientError as exc:
        log.debug(f"[s3] list_multipart_uploads {bucket} failed: {exc}")
        return 0, None

    return count, oldest_days

@retry_with_backoff(exceptions=(ClientError,))
def check_s3_stale_multipart_uploads(  # pylint: disable=unused-argument
    *args,
    logger: Optional[logging.Logger] = None,
    stale_days: int = 7,
    **kwargs,
) -> None:
    """Flag buckets with multipart uploads older than 'stale_days'."""
    log = _logger(kwargs.get("logger") or logger)
    try:
        writer, s3 = _extract_writer_s3(args, kwargs)
    except TypeError as exc:
        log.warning(f"[check_s3_stale_multipart_uploads] Skipping: {exc}")
        return
    if not (config.ACCOUNT_ID and config.WRITE_ROW):
        log.warning("[check_s3_stale_multipart_uploads] Skipping: checker config not provided.")
        return

    inv = _build_inventory(s3, log)
    for bucket, info in inv.items():
        cnt, oldest = _list_stale_multipart_uploads(s3, bucket, int(stale_days), log)
        if cnt <= 0:
            continue

        lc = info.get("lifecycle") or {}
        abort_days = lc.get("abort_incomplete_days")
        has_abort = isinstance(abort_days, int)

        region = str(info.get("region") or "")
        tags = info.get("tags") or {}
        app_id, app, env = _tag_triplet(tags)

        flags = ["S3StaleMultipartUploads"]
        if not has_abort:
            flags.append("S3NoAbortIncompleteMultipartUpload")

        signals = {
            "Region": region,
            "Bucket": bucket,
            "StaleMultipartCount": cnt,
            "OldestAgeDays": oldest if oldest is not None else "NULL",
            "AbortIncompleteDays": abort_days if has_abort else "NULL",
            "LookbackDays": int(stale_days),
        }
        config.WRITE_ROW(
            resource_id=bucket,
            resource_type="S3Bucket",
            writer=writer,
            name=bucket,
            region=region,
            owner_id=config.ACCOUNT_ID,
            flags=flags,
            signals=signals,
            app_id=app_id,
            app=app,
            env=env,
            estimated_cost=0.0,
            potential_saving=0.0,
            )

        log.info(f"[s3] Wrote stale multipart uploads: {bucket} (count={cnt})")

# --------------------------- Empty bucket checker ------------------------- #

def _bucket_is_empty_via_list(
    s3, bucket: str, versioning: bool, log: logging.Logger
) -> bool:
    try:
        r = s3.list_objects_v2(Bucket=bucket, MaxKeys=1) or {}
        if int(r.get("KeyCount") or 0) > 0:
            return False
    except ClientError as exc:
        log.debug(f"[s3] list_objects_v2 {bucket} failed: {exc}")
        return False
    if not versioning:
        return True
    try:
        rv = s3.list_object_versions(Bucket=bucket, MaxKeys=1) or {}
        vers = len(rv.get("Versions", []) or [])
        dels = len(rv.get("DeleteMarkers", []) or [])
        return (vers + dels) == 0
    except ClientError as exc:
        log.debug(f"[s3] list_object_versions {bucket} failed: {exc}")
        return False

@retry_with_backoff(exceptions=(ClientError,))
def check_s3_empty_buckets(  # pylint: disable=unused-argument
    *args,
    logger: Optional[logging.Logger] = None,
    **kwargs,
) -> None:
    """
    Flag buckets with zero objects (and zero versions for versioned buckets).
    If a CloudWatch client is provided (matching bucket region), include size/objects
    and estimated storage cost (usually 0 for empty).
    """
    log = _logger(kwargs.get("logger") or logger)
    try:
        writer, s3, cloudwatch = _extract_writer_s3_cw(args, kwargs)
    except TypeError as exc:
        log.warning(f"[check_s3_empty_buckets] Skipping: {exc}")
        return
    if not (config.ACCOUNT_ID and config.WRITE_ROW):
        log.warning("[check_s3_empty_buckets] Skipping: checker config not provided.")
        return

    inv = _build_inventory(s3, log)
    # Emptiness detection by direct list (fast & definitive), CW only for enrichment
    to_check_by_region: Dict[str, List[str]] = {}
    empty_buckets: List[str] = []
    for bucket, info in inv.items():
        region = str(info.get("region") or "")
        versioning = bool(info.get("versioning"))
        if _bucket_is_empty_via_list(s3, bucket, versioning, log):
            empty_buckets.append(bucket)
            to_check_by_region.setdefault(region, []).append(bucket)

    now_utc = datetime.now(timezone.utc)
    cw_data: Dict[str, Dict[str, Any]] = {}
    for region, buckets in to_check_by_region.items():
        cw_data.update(_cw_sizes_for_region(cloudwatch, region, buckets, now_utc, log))

    for bucket in empty_buckets:
        info = inv.get(bucket) or {}
        region = str(info.get("region") or "")
        tags = info.get("tags") or {}
        app_id, app, env = _tag_triplet(tags)

        sizes = cw_data.get(bucket, {})
        by_class = sizes.get("bytes", {}) if isinstance(sizes, dict) else {}
        objects = sizes.get("objects") if isinstance(sizes, dict) else None
        est = _storage_monthly_cost(by_class) if by_class else 0.0

        signals = {
            "Region": region,
            "Bucket": bucket,
            "Objects": objects if objects is not None else "NULL",
            "SizeGB": round(sum(_gb(v) for v in by_class.values()), 3) if by_class else "NULL",
        }
        config.WRITE_ROW(
            resource_id=bucket,
            resource_type="S3Bucket",
            writer=writer,
            name=bucket,
            region=region,
            owner_id=config.ACCOUNT_ID,
            flags=["S3BucketEmpty"],
            signals=signals,
            app_id=app_id,
            app=app,
            env=env,
            estimated_cost=est,
            potential_saving=0.0,
            )

        log.info(f"[s3] Wrote empty bucket: {bucket}")
