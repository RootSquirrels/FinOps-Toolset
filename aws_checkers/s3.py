"""Checkers: Amazon S3 (cost & compliance, single row per bucket)."""

from __future__ import annotations

import boto3

import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Iterable, List, Optional, Tuple

from botocore.client import BaseClient
from botocore.exceptions import ClientError

from aws_checkers.common import _logger, _signals_str, _to_utc_iso
from aws_checkers import config as chk
from core.cloudwatch import CloudWatchBatcher
from core.retry import retry_with_backoff


# ---------------------------------------------------------------------------
# Constants & pricing helpers
# ---------------------------------------------------------------------------

_SIZE_TYPES: Tuple[str, ...] = (
    "StandardStorage",
    "StandardIAStorage",
    "OneZoneIAStorage",
    "IntelligentTieringAAStorage",
    "IntelligentTieringFAStorage",
    "GlacierStorage",
    "DeepArchiveStorage",
)

_PUBLIC_POLICY_MARKERS: Tuple[str, ...] = (
    "Principal\":\"*\"",
    "Principal\":{\"AWS\":\"*\"",
    "\"AWS\":\"*\"",
)


def _safe_price(service: str, key: str, default: float = 0.0) -> float:
    """Resolve a price via chk.safe_price(service, key, default)."""
    try:
        return float(chk.safe_price(service, key, default))  # type: ignore[arg-type]
    except Exception:  # pylint: disable=broad-except
        return float(default)


# ---------------------------------------------------------------------------
# Pagination helpers
# ---------------------------------------------------------------------------

def _paginate(fn, page_key: str, token_key: str, **kwargs: Any) -> Iterable[Dict[str, Any]]:
    """Generic paginator for list/describe APIs returning a token key."""
    token: Optional[str] = None
    while True:
        params = dict(kwargs)
        if token:
            params[token_key] = token
        page = fn(**params)
        for item in page.get(page_key, []) or []:
            yield item
        token = page.get(token_key)
        if not token:
            break


def _bytes_to_gib(num: float) -> float:
    """Convert bytes to GiB."""
    try:
        return float(num) / (1024.0 ** 3)
    except Exception:  # pylint: disable=broad-except
        return 0.0


def _latest_metric_value(points: List[Tuple[datetime, float]]) -> float:
    """Return the latest available metric value from a CloudWatch series.

    S3 storage metrics can be delayed; relying on the most recent timestamp often yields
    empty/zero values. We therefore take the maximum value in the window (best-effort).
    """
    if not points:
        return 0.0
    vals: List[float] = []
    for _ts, val in points:
        try:
            vals.append(float(val))
        except Exception:  # pylint: disable=broad-except
            continue
    return max(vals) if vals else 0.0


# ---------------------------------------------------------------------------
# S3 inventory helpers
# ---------------------------------------------------------------------------

def _bucket_region(s3: BaseClient, name: str) -> str:
    """Resolve S3 bucket home region."""
    try:
        out = s3.get_bucket_location(Bucket=name)
        loc = out.get("LocationConstraint")
        if not loc:
            return "us-east-1"
        if loc == "EU":
            return "eu-west-1"
        return str(loc)
    except ClientError:
        return "unknown"


def _list_buckets_by_region(s3: BaseClient) -> Dict[str, List[Tuple[str, str]]]:
    """Return {region: [(bucket_name, created_iso), ...]}."""
    out: Dict[str, List[Tuple[str, str]]] = {}
    resp = s3.list_buckets()
    for b in resp.get("Buckets", []) or []:
        name = b.get("Name")
        if not name:
            continue
        region = _bucket_region(s3, name)
        created_iso = _to_utc_iso(b.get("CreationDate"))
        out.setdefault(region, []).append((name, created_iso))
    return out


def _fetch_sizes_and_counts(
    region: str,
    cloudwatch: BaseClient,
    buckets: List[str],
    lookback_days: int,
) -> Tuple[Dict[str, float], Dict[str, int]]:
    """Return ({bucket: size_gb}, {bucket: objects}) via one batched CW round."""
    size_gb: Dict[str, float] = {}
    objects: Dict[str, int] = {}

    if not buckets:
        return size_gb, objects

    end = datetime.now(timezone.utc)
    # S3 storage metrics are daily and can be delayed; query a slightly wider window.
    start = end - timedelta(days=max(3, int(lookback_days) + 2))

    # CloudWatch metrics for S3 storage are regional; ensure the CW client matches
    # the bucket region or datapoints may be missing (reported as 0).
    cw = cloudwatch
    cw_region = getattr(getattr(cw, "meta", None), "region_name", None)
    if cw_region and str(cw_region) != region:
        cw = boto3.client("cloudwatch", region_name=region)

    batch = CloudWatchBatcher(region, client=cw)
    # Sizes (avg last day) per storage type, + objects
    for idx, name in enumerate(buckets):
        for jdx, st in enumerate(_SIZE_TYPES):
            batch.add_q(
                id_hint=f"sz{idx}_{jdx}",
                namespace="AWS/S3",
                metric="BucketSizeBytes",
                dims=[
                    {"Name": "BucketName", "Value": name},
                    {"Name": "StorageType", "Value": st},
                ],
                stat="Average",
                period=86400,
            )
        batch.add_q(
            id_hint=f"obj{idx}",
            namespace="AWS/S3",
            metric="NumberOfObjects",
            dims=[
                {"Name": "BucketName", "Value": name},
                {"Name": "StorageType", "Value": "AllStorageTypes"},
            ],
            stat="Average",
            period=86400,
        )

    series = batch.execute(start, end, scan_by="TimestampDescending")

    for idx, name in enumerate(buckets):
        total_bytes = 0.0
        for jdx, _st in enumerate(_SIZE_TYPES):
            pts = series.get(f"sz{idx}_{jdx}", [])
            total_bytes += _latest_metric_value(pts)
        size_gb[name] = round(_bytes_to_gib(total_bytes), 3) if total_bytes > 0 else 0.0

        pts_obj = series.get(f"obj{idx}", [])
        objects[name] = int(_latest_metric_value(pts_obj))

    return size_gb, objects


def _acl_public_flags(acl: Dict[str, Any]) -> Tuple[bool, bool]:
    """Return (public_all_users, public_auth_users) from ACL grants."""
    all_u = False
    auth_u = False
    for g in (acl.get("Grants") or []):
        gr = g.get("Grantee") or {}
        uri = gr.get("URI", "")
        if "AllUsers" in uri:
            all_u = True
        if "AuthenticatedUsers" in uri:
            auth_u = True
    return all_u, auth_u


def _policy_public(policy_text: str) -> bool:
    """Best-effort check for public bucket policy."""
    if not policy_text:
        return False
    hay = policy_text.replace(" ", "")
    return any(m in hay for m in _PUBLIC_POLICY_MARKERS)


def _collect_bucket_metadata(
    s3: BaseClient,
    name: str,
) -> Tuple[Dict[str, Any], List[str]]:
    """Collect compliance and configuration metadata for a bucket."""
    flags: List[str] = []
    info: Dict[str, Any] = {
        "Versioning": "Unknown",
        "Encryption": "Unknown",
        "PublicACLAllUsers": False,
        "PublicACLAuthUsers": False,
        "PublicPolicy": False,
        "PublicAccessBlock": "Unknown",
        "LifecycleRules": 0,
        "ObjectLock": "Unknown",
        "MFADelete": "Unknown",
        "Logging": "Unknown",
    }

    # Versioning
    try:
        v = s3.get_bucket_versioning(Bucket=name)
        status = v.get("Status") or "Disabled"
        info["Versioning"] = status
        mfa = v.get("MFADelete") or "Disabled"
        info["MFADelete"] = mfa
        if status == "Enabled":
            flags.append("VersioningEnabled")
        if mfa == "Enabled":
            flags.append("MFADeleteEnabled")
    except ClientError:
        pass

    # Encryption
    try:
        enc = s3.get_bucket_encryption(Bucket=name)
        rules = (enc.get("ServerSideEncryptionConfiguration") or {}).get("Rules") or []
        info["Encryption"] = "Enabled" if rules else "Disabled"
        if rules:
            flags.append("EncryptionEnabled")
    except ClientError:
        info["Encryption"] = "Disabled"

    # Public access block
    try:
        pab = s3.get_public_access_block(Bucket=name).get("PublicAccessBlockConfiguration", {})
        info["PublicAccessBlock"] = "Enabled"
        if all(bool(pab.get(k)) for k in ("BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets")):
            flags.append("PABAllEnabled")
    except ClientError:
        info["PublicAccessBlock"] = "Disabled"

    # ACL checks
    try:
        acl = s3.get_bucket_acl(Bucket=name)
        all_u, auth_u = _acl_public_flags(acl)
        info["PublicACLAllUsers"] = all_u
        info["PublicACLAuthUsers"] = auth_u
        if all_u or auth_u:
            flags.append("PublicACL")
    except ClientError:
        pass

    # Policy checks
    try:
        pol = s3.get_bucket_policy(Bucket=name).get("Policy", "")
        is_public = _policy_public(pol)
        info["PublicPolicy"] = is_public
        if is_public:
            flags.append("PublicPolicy")
    except ClientError:
        pass

    # Lifecycle
    try:
        lc = s3.get_bucket_lifecycle_configuration(Bucket=name)
        rules = lc.get("Rules") or []
        info["LifecycleRules"] = len(rules)
        if rules:
            flags.append("LifecycleConfigured")
    except ClientError:
        info["LifecycleRules"] = 0

    # Object lock
    try:
        ol = s3.get_object_lock_configuration(Bucket=name)
        cfg = ol.get("ObjectLockConfiguration") or {}
        info["ObjectLock"] = cfg.get("ObjectLockEnabled", "Disabled")
        if info["ObjectLock"] == "Enabled":
            flags.append("ObjectLock")
    except ClientError:
        info["ObjectLock"] = "Disabled"

    # Logging
    try:
        lg = s3.get_bucket_logging(Bucket=name)
        enabled = bool(lg.get("LoggingEnabled"))
        info["Logging"] = "Enabled" if enabled else "Disabled"
        if enabled:
            flags.append("AccessLogging")
    except ClientError:
        info["Logging"] = "Unknown"

    return info, flags


def _lifecycle_savings_estimate(
    size_gb: float,
    objects: int,
    lifecycle_rules: int,
    versioning: str,
    p_std: float,
    p_ia: float,
    p_glacier: float,
    assumed_cold_fraction: float,
    version_fraction: float,
    min_size_gb_for_lifecycle: float,
    min_objects_for_versions: int,
) -> Tuple[Optional[float], List[str], Dict[str, Any], Optional[str]]:
    """Estimate potential monthly savings for bucket changes (heuristic)."""
    flags: List[str] = []
    signals: Dict[str, Any] = {}
    breakdown: Optional[str] = None

    if size_gb <= 0.0 or p_std <= 0.0:
        return None, flags, signals, breakdown

    base_cost = size_gb * p_std

    # Heuristic: Lifecycle to IA/Glacier (only if no lifecycle already)
    best_saving: float = 0.0
    best_action: Optional[str] = None

    if lifecycle_rules == 0 and size_gb >= float(min_size_gb_for_lifecycle):
        cold_gb = size_gb * float(max(0.0, min(1.0, assumed_cold_fraction)))
        warm_gb = size_gb - cold_gb

        # IA option
        ia_cost = warm_gb * p_std + cold_gb * p_ia
        save_ia = max(0.0, base_cost - ia_cost)

        # Glacier option
        gl_cost = warm_gb * p_std + cold_gb * p_glacier
        save_gl = max(0.0, base_cost - gl_cost)

        if save_ia > best_saving:
            best_saving = save_ia
            best_action = "AddLifecycleToIA"
            breakdown = f"Base={base_cost:.2f}; IA={ia_cost:.2f}; Save={save_ia:.2f}"
        if save_gl > best_saving:
            best_saving = save_gl
            best_action = "AddLifecycleToGlacier"
            breakdown = f"Base={base_cost:.2f}; Glacier={gl_cost:.2f}; Save={save_gl:.2f}"

    # Heuristic: Versioning overhead (if enabled and many objects)
    if str(versioning).lower() == "enabled" and objects >= int(min_objects_for_versions):
        # estimate extra storage from versions
        extra_gb = size_gb * float(max(0.0, min(1.0, version_fraction)))
        extra_cost = extra_gb * p_std
        signals["VersioningExtraGB"] = round(extra_gb, 3)
        signals["VersioningExtraCost"] = round(extra_cost, 2)
        flags.append("ReviewVersioning")
        if extra_cost > best_saving:
            best_saving = extra_cost
            best_action = "ReduceVersions"
            breakdown = f"VersionExtra={extra_cost:.2f}"

    if best_saving > 0.0 and best_action:
        flags.append(best_action)
        signals["BestSavingUSD"] = round(best_saving, 2)
        signals["BestAction"] = best_action
        return round(best_saving, 2), flags, signals, breakdown

    return None, flags, signals, breakdown


# ---------------------------------------------------------------------------
# Main checker
# ---------------------------------------------------------------------------

@retry_with_backoff(exceptions=(ClientError,))
def check_s3_cost_and_compliance(  # noqa: D401
    *args: Any,
    logger: Optional[logging.Logger] = None,
    lookback_days: int = 7,
    assumed_cold_fraction: float = 0.5,
    version_fraction: float = 0.2,
    min_size_gb_for_lifecycle: float = 50.0,
    min_objects_for_versions: int = 1_000_000,
    **kwargs: Any,
) -> List[Dict[str, Any]]:
    """Single-row-per-bucket S3 check: cost baseline + compliance signals.

    Inputs (orchestrator style):
      - writer: positional
      - client: S3 client (global)
      - cloudwatch: CloudWatch client (may be "global"; we re-create regional CW clients as needed)
      - region: optional (ignored for S3 bucket discovery, used for profiling only)

    Outputs:
      - One CSV row per bucket with object_count, storage_gb, estimated_cost, flags, signals.
    """
    log = _logger(kwargs.get("logger") or logger)

    writer = kwargs.get("writer", args[0] if len(args) >= 1 else None)
    s3 = kwargs.get("client", kwargs.get("s3", args[1] if len(args) >= 2 else None))
    cloudwatch = kwargs.get("cloudwatch", kwargs.get("cw", args[2] if len(args) >= 3 else None))

    if writer is None or s3 is None or cloudwatch is None:
        log.warning("[check_s3_cost_and_compliance] Skipping: missing writer/client/cloudwatch")
        return []

    owner = str(kwargs.get("account_id") or chk.ACCOUNT_ID or "")
    if not (owner and chk.WRITE_ROW):
        log.warning("[check_s3_cost_and_compliance] Skipping: missing config.")
        return []

    # Pricing (GB-month)
    p_std = _safe_price("S3", "STANDARD_GB_MONTH", 0.0)
    p_ia = _safe_price("S3", "STANDARD_IA_GB_MONTH", 0.0)
    p_glacier = _safe_price("S3", "GLACIER_GB_MONTH", 0.0)

    buckets_by_region = _list_buckets_by_region(s3)

    for bucket_region, items in buckets_by_region.items():
        names = [n for n, _created in items]
        created_map = {n: c for n, c in items}

        try:
            sizes, counts = _fetch_sizes_and_counts(
                bucket_region,
                cloudwatch,
                names,
                lookback_days=lookback_days,
            )
        except Exception as exc:  # pylint: disable=broad-except
            log.warning("[s3] metrics fetch failed for region %s: %s", bucket_region, exc)
            sizes = {}
            counts = {}

        for name in names:
            created_iso = created_map.get(name, "")
            size_gb = float(sizes.get(name, 0.0))
            objects = int(counts.get(name, 0))

            # Compliance metadata + flags
            meta, flags = _collect_bucket_metadata(s3, name)

            # Savings heuristic (lifecycle, versioning)
            best_saving, add_flags, signals, breakdown = _lifecycle_savings_estimate(
                size_gb=size_gb,
                objects=objects,
                lifecycle_rules=int(meta.get("LifecycleRules", 0) or 0),
                versioning=str(meta.get("Versioning", "Unknown")),
                p_std=p_std,
                p_ia=p_ia,
                p_glacier=p_glacier,
                assumed_cold_fraction=assumed_cold_fraction,
                version_fraction=version_fraction,
                min_size_gb_for_lifecycle=min_size_gb_for_lifecycle,
                min_objects_for_versions=min_objects_for_versions,
            )
            if breakdown:
                signals["SavingsBreakdown"] = breakdown

            # Merge flags (dedup)
            flags = sorted(set(flags) | set(add_flags))

            # Estimated bucket monthly cost (Standard baseline)
            estimated_cost = round(size_gb * p_std, 2) if p_std > 0.0 else 0.0

            try:
                # type: ignore[call-arg]
                chk.WRITE_ROW(
                    writer=writer,
                    resource_id=f"arn:aws:s3:::{name}",
                    name=name,
                    owner_id=owner,  # type: ignore[arg-type]
                    resource_type="S3Bucket",
                    region=bucket_region,
                    state="Active",
                    creation_date=created_iso,
                    storage_gb=size_gb,
                    object_count=objects,
                    estimated_cost=estimated_cost,
                    potential_saving=best_saving,
                    flags=flags,
                    confidence=85 if best_saving else 70,
                    signals=_signals_str(
                        {
                            **meta,
                            **signals,
                            "StorageGB": round(size_gb, 3),
                            "ObjectCount": objects,
                            "StdGBMonthUSD": p_std,
                        }
                    ),
                )
            except Exception as exc:  # pylint: disable=broad-except
                log.warning("[s3] write_row failed for %s: %s", name, exc)
