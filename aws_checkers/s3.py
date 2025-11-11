"""Checkers: Amazon S3 (cost & compliance, single row per bucket)."""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from botocore.client import BaseClient
from botocore.exceptions import ClientError

from aws_checkers.common import _logger, _signals_str, _to_utc_iso
from aws_checkers import config as chk
from core.cloudwatch import CloudWatchBatcher


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


def _price(service: str, key: str, default: float = 0.0) -> float:
    """Resolve a price via chk.safe_price(service, key, default)."""
    try:
        return float(chk.safe_price(service, key, default))  # type: ignore[arg-type]
    except Exception:  # pylint: disable=broad-except
        return float(default)


# ---------------------------------------------------------------------------
# Generic helpers
# ---------------------------------------------------------------------------

def _paginate(
    fn, page_key: str, token_key: str, **kwargs: Any
) -> Iterable[Dict[str, Any]]:
    """Generic paginator for list/describe APIs with NextToken/Marker."""
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


# ---------------------------------------------------------------------------
# S3 inventory helpers
# ---------------------------------------------------------------------------

def _bucket_region(s3: BaseClient, name: str) -> str:
    """Resolve S3 bucket home region."""
    try:
        out = s3.get_bucket_location(Bucket=name)
        loc = out.get("LocationConstraint")
        return loc or "us-east-1"
    except ClientError:
        return "us-east-1"


def _group_buckets_by_region(s3: BaseClient) -> Dict[str, List[Tuple[str, str]]]:
    """Return {region: [(name, created_iso), ...]} using list_buckets()."""
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
    start = end - timedelta(days=max(1, int(lookback_days)))

    batch = CloudWatchBatcher(region, client=cloudwatch)
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
            if pts:
                try:
                    total_bytes += float(pts[0][1])
                except Exception:  # pylint: disable=broad-except
                    pass
        size_gb[name] = round(_bytes_to_gib(total_bytes), 3) if total_bytes > 0 else 0.0

        pts_obj = series.get(f"obj{idx}", [])
        objects[name] = int(pts_obj[0][1]) if pts_obj else 0

    return size_gb, objects


def _acl_public_flags(acl: Dict[str, Any]) -> Tuple[bool, bool]:
    """Return (all_users, authenticated_users) ACL public grants."""
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


def _collect_bucket_metadata(
    s3: BaseClient,
    name: str,
) -> Tuple[Dict[str, Any], List[str]]:
    """Collect compliance metadata and return (signals, flags)."""
    signals: Dict[str, Any] = {}
    flags: List[str] = []

    # Public Access Block
    try:
        pab = s3.get_public_access_block(Bucket=name)
        cfgp = pab.get("PublicAccessBlockConfiguration") or {}
        for k in ("BlockPublicAcls", "IgnorePublicAcls",
                  "BlockPublicPolicy", "RestrictPublicBuckets"):
            signals[k] = int(bool(cfgp.get(k)))
        if not all(bool(cfgp.get(k)) for k in cfgp):
            flags.append("PublicAccessBlockDisabled")
    except ClientError:
        flags.append("GetPublicAccessBlockError")

    # Bucket policy public?
    try:
        st = s3.get_bucket_policy_status(Bucket=name)
        is_pub = bool((st.get("PolicyStatus") or {}).get("IsPublic"))
        signals["PolicyIsPublic"] = int(is_pub)
        if is_pub:
            flags.append("PolicyIsPublic")
    except ClientError:
        # No policy / access denied – ignore
        pass

    # ACL grants
    try:
        acl = s3.get_bucket_acl(Bucket=name)
        pub, auth = _acl_public_flags(acl)
        signals["AclAllUsers"] = int(pub)
        signals["AclAuthUsers"] = int(auth)
        if pub or auth:
            flags.append("AclPublicGrant")
    except ClientError:
        pass

    # Default encryption
    try:
        enc = s3.get_bucket_encryption(Bucket=name)
        rules = (enc.get("ServerSideEncryptionConfiguration") or {}).get("Rules", []) or []
        algo = ""
        if rules:
            apply = rules[0].get("ApplyServerSideEncryptionByDefault") or {}
            algo = str(apply.get("SSEAlgorithm") or "")
        signals["DefaultEncryption"] = algo or "None"
        if not algo:
            flags.append("NoDefaultEncryption")
    except ClientError as err:
        code = (err.response or {}).get("Error", {}).get("Code", "")
        if code == "ServerSideEncryptionConfigurationNotFoundError":
            signals["DefaultEncryption"] = "None"
            flags.append("NoDefaultEncryption")
        else:
            signals["DefaultEncryption"] = "Unknown"

    # Server access logging
    try:
        lg = s3.get_bucket_logging(Bucket=name)
        enabled = bool(lg.get("LoggingEnabled"))
        signals["ServerAccessLogging"] = int(enabled)
        if not enabled:
            flags.append("NoServerAccessLogging")
    except ClientError:
        signals["ServerAccessLogging"] = 0
        flags.append("NoServerAccessLogging")

    # Lifecycle rules
    try:
        lc = s3.get_bucket_lifecycle_configuration(Bucket=name)
        rules = list(lc.get("Rules", []) or [])
        signals["LifecycleRules"] = len(rules)
        # capture if any rule cleans noncurrent versions
        has_nc = False
        for r in rules:
            if str(r.get("Status", "Disabled")).lower() != "enabled":
                continue
            if "NoncurrentVersionExpiration" in r or "NoncurrentVersionTransitions" in r:
                has_nc = True
                break
        signals["HasNoncurrentCleanup"] = int(has_nc)
    except ClientError:
        # absent or denied – treat as zero
        signals["LifecycleRules"] = 0
        signals["HasNoncurrentCleanup"] = 0
        # keep previous code's semantics: emit *query* flags for ops noise only
        # (we avoid adding a noisy error flag here).

    # Versioning
    try:
        ver = s3.get_bucket_versioning(Bucket=name)
        signals["Versioning"] = str(ver.get("Status") or "Disabled")
    except ClientError:
        signals["Versioning"] = "Disabled"

    # Replication (optional; keep compatibility with old "ReplicationQueryError")
    try:
        rep = s3.get_bucket_replication(Bucket=name)
        rules = (rep.get("ReplicationConfiguration") or {}).get("Rules", []) or []
        signals["ReplicationRules"] = len(rules)
    except ClientError:
        signals["ReplicationRules"] = 0
        flags.append("ReplicationQueryError")

    # Object Lock (optional; keep compatibility with old "ObjectLockQueryError")
    try:
        ol = s3.get_object_lock_configuration(Bucket=name)
        mode = (ol.get("ObjectLockConfiguration") or
                 {}).get("Rule", {}).get("DefaultRetention", {}).get("Mode")
        signals["ObjectLockMode"] = str(mode or "")
    except ClientError:
        signals["ObjectLockMode"] = ""
        flags.append("ObjectLockQueryError")

    # Tags (serialize as "k:v, k2:v2")
    try:
        t = s3.get_bucket_tagging(Bucket=name)
        tagset = t.get("TagSet", []) or []
        tags_pairs = [f"{x.get('Key','')}:{x.get('Value','')}" for x in tagset if x.get("Key")]
        signals["Tags"] = ", ".join(sorted(tags_pairs)) if tags_pairs else ""
    except ClientError:
        signals["Tags"] = ""

    return signals, flags


# ---------------------------------------------------------------------------
# MPU sampling (bounded, on the largest buckets)
# ---------------------------------------------------------------------------

def _estimate_stale_mpu_gib(
    s3: BaseClient,
    bucket: str,
    older_than_days: int,
    per_bucket_limit: int,
    per_upload_parts_limit: int,
) -> Tuple[int, float]:
    """Return (stale_uploads_count, reclaim_gib) by sampling MPU parts."""
    cutoff = datetime.now(timezone.utc) - timedelta(days=int(older_than_days))
    try:
        resp = s3.list_multipart_uploads(Bucket=bucket, MaxUploads=per_bucket_limit)
    except ClientError as exc:
        code = (exc.response or {}).get("Error", {}).get("Code", "")
        if code in {"NoSuchUpload", "AccessDenied"}:
            return 0, 0.0
        return 0, 0.0

    uploads = resp.get("Uploads", []) or []
    stale = []
    for u in uploads:
        t = u.get("Initiated")
        if isinstance(t, datetime):
            if t.tzinfo is None:
                t = t.replace(tzinfo=timezone.utc)
            if t < cutoff:
                stale.append(u)

    if not stale:
        return 0, 0.0

    total = 0.0
    sampled = 0
    for up in stale:
        if sampled >= int(per_bucket_limit):
            break
        key = up.get("Key")
        uid = up.get("UploadId")
        if not key or not uid:
            continue
        sampled += 1
        try:
            parts = s3.list_parts(
                Bucket=bucket, Key=key, UploadId=uid, MaxParts=per_upload_parts_limit
            )
            for p in parts.get("Parts", []) or []:
                try:
                    total += float(p.get("Size") or 0.0)
                except Exception:  # pylint: disable=broad-except
                    pass
        except ClientError:
            continue

    return len(stale), round(_bytes_to_gib(total), 3)


# ---------------------------------------------------------------------------
# Single consolidated checker (one CSV row per bucket)
# ---------------------------------------------------------------------------

def _extract_writer_cw_s3(
    args: Tuple[Any, ...], kwargs: Dict[str, Any]
) -> Tuple[Any, BaseClient, BaseClient]:
    """Extract (writer, cloudwatch, s3) from args/kwargs; raise if missing."""
    writer = kwargs.get("writer", args[0] if len(args) >= 1 else None)
    cloudwatch = kwargs.get("cloudwatch", args[1] if len(args) >= 2 else None)
    s3 = kwargs.get("client", args[2] if len(args) >= 3 else None)
    if writer is None or cloudwatch is None or s3 is None:
        raise TypeError("Expected 'writer', 'cloudwatch' and 'client'")
    return writer, cloudwatch, s3


def _savings_candidates(
    size_gb: float,
    std_gb_mo: float,
    cheap_gb_mo: float,
    has_lifecycle: bool,
    versioning: str,
    has_noncurrent_cleanup: bool,
    objects: int,
    mpu_reclaim_gb: float,
    assumed_cold_fraction: float,
    version_fraction: float,
    min_size_gb_for_lifecycle: float,
    min_objects_for_versions: int,
) -> Tuple[Optional[float], Dict[str, Any], List[str], int]:
    """Compute potential savings & emit signals/flags for candidates.

    Returns:
        (best_saving, breakdown, flags_to_add, confidence)
    """
    flags: List[str] = []
    breakdown: Dict[str, Any] = {}
    conf = 60

    # Lifecycle / tiering heuristic
    lifecycle_delta = max(0.0, std_gb_mo - cheap_gb_mo)
    lifecycle_saving = 0.0
    if size_gb >= float(min_size_gb_for_lifecycle) and not has_lifecycle and lifecycle_delta > 0.0:
        lifecycle_saving = size_gb * lifecycle_delta * float(assumed_cold_fraction)
        flags.append("NoLifecycleOnLargeBucket")
        conf = max(conf, 80)
    if lifecycle_saving > 0:
        breakdown["s_no_lifecycle"] = round(lifecycle_saving, 2)

    # Versions heuristic
    versions_saving = 0.0
    if (
        versioning == "Enabled"
        and not has_noncurrent_cleanup
        and objects >= int(min_objects_for_versions)
        and std_gb_mo > 0.0
    ):
        versions_saving = size_gb * std_gb_mo * float(version_fraction)
        flags.append("ExcessVersionsNoCleanup")
        conf = max(conf, 70)
    if versions_saving > 0:
        breakdown["s_versions"] = round(versions_saving, 2)

    # Abandoned MPU heuristic
    mpu_saving = 0.0
    if mpu_reclaim_gb > 0.0 and std_gb_mo > 0.0:
        mpu_saving = mpu_reclaim_gb * std_gb_mo
        flags.append("AbandonedMultipartUploads")
        conf = max(conf, 65)
    if mpu_saving > 0:
        breakdown["s_mpu"] = round(mpu_saving, 2)

    # Choose the best single saving to avoid double-counting
    best = max(lifecycle_saving, versions_saving, mpu_saving, 0.0)
    return (round(best, 2) if best > 0.0 else None), breakdown, flags, conf


def check_s3_cost_and_compliance(  # noqa: D401
    region: str,
    *args: Any,
    logger: Optional[logging.Logger] = None,
    lookback_days: int = 7,
    # Heuristic knobs
    min_size_gb_for_lifecycle: float = 500.0,
    assumed_cold_fraction: float = 0.3,
    min_objects_for_versions: int = 1_000_000,
    version_fraction: float = 0.25,
    mpu_older_than_days: int = 7,
    mpu_check_max_buckets: int = 50,
    mpu_per_bucket_limit: int = 100,
    mpu_per_upload_parts_limit: int = 20,
    **kwargs: Any,
) -> List[Dict[str, Any]]:
    """Single-pass S3 checker that writes exactly one CSV row per bucket.

    It merges compliance (public access, encryption, logging, lifecycle, etc.) with
    savings heuristics (tiering, excess versions, abandoned MPUs).
    """
    log = _logger(kwargs.get("logger") or logger)
    try:
        writer, cloudwatch, s3 = _extract_writer_cw_s3(args, kwargs)
    except TypeError as exc:
        log.warning("[check_s3_cost_and_compliance] Skipping: %s", exc)
        return []

    owner = str(kwargs.get("account_id") or chk.ACCOUNT_ID or "")
    if not (owner and chk.WRITE_ROW):
        log.warning("[check_s3_cost_and_compliance] Skipping: missing config.")
        return []

    # Pricing (rates)
    p_std = _price("S3", "STANDARD_GB_MONTH", 0.0)
    p_ia = _price("S3", "STANDARD_IA_GB_MONTH", 0.0)
    p_it = _price("S3", "INTELLIGENT_TIERING_GB_MONTH", 0.0)
    cheaper = p_ia if (p_ia > 0.0) else (p_it if p_it > 0.0 else 0.0)

    # Partition buckets by region, filter to the target region
    buckets_by_region = _group_buckets_by_region(s3)
    region_buckets = buckets_by_region.get(region, [])
    if not region_buckets:
        return []

    names = [n for (n, _c) in region_buckets]
    size_gb_map, objects_map = _fetch_sizes_and_counts(region, cloudwatch, names, lookback_days)

    # Sort buckets by size desc to bound MPU work to largest ones
    names_sorted = sorted(names, key=lambda n: size_gb_map.get(n, 0.0), reverse=True)
    mpu_sample_set = set(names_sorted[: int(mpu_check_max_buckets)])

    rows: List[Dict[str, Any]] = []

    for name, created_iso in region_buckets:
        size_gb = float(size_gb_map.get(name, 0.0))
        objects = int(objects_map.get(name, 0))

        # Collect compliance metadata
        signals, flags = _collect_bucket_metadata(s3, name)

        # Add universal cost signals
        signals["SizeGB"] = int(size_gb) if size_gb > 0 else 0
        signals["Objects"] = objects

        # Optional MPU sampling for largest buckets
        mpu_count = 0
        mpu_reclaim_gb = 0.0
        if name in mpu_sample_set and mpu_older_than_days > 0:
            mpu_count, mpu_reclaim_gb = _estimate_stale_mpu_gib(
                s3,
                bucket=name,
                older_than_days=int(mpu_older_than_days),
                per_bucket_limit=int(mpu_per_bucket_limit),
                per_upload_parts_limit=int(mpu_per_upload_parts_limit),
            )
            signals["MPUStaleCount"] = mpu_count
            signals["MPUReclaimGB"] = mpu_reclaim_gb

        # Savings candidates (take the best one to avoid double-counting)
        best_saving, breakdown, add_flags, conf = _savings_candidates(
            size_gb=size_gb,
            std_gb_mo=p_std,
            cheap_gb_mo=cheaper,
            has_lifecycle=bool(signals.get("LifecycleRules", 0)),
            versioning=str(signals.get("Versioning", "Disabled")),
            has_noncurrent_cleanup=bool(signals.get("HasNoncurrentCleanup", 0)),
            objects=objects,
            mpu_reclaim_gb=mpu_reclaim_gb,
            assumed_cold_fraction=assumed_cold_fraction,
            version_fraction=version_fraction,
            min_size_gb_for_lifecycle=min_size_gb_for_lifecycle,
            min_objects_for_versions=min_objects_for_versions,
        )
        if breakdown:
            signals["SavingsBreakdown"] = breakdown

        # Merge flags (dedup)
        flags = sorted(set(flags) | set(add_flags))

        # Estimated bucket monthly cost
        estimated_cost = round(size_gb * p_std, 2) if p_std > 0.0 else 0.0

        try:
            # type: ignore[call-arg]
            chk.WRITE_ROW(
                writer=writer,
                resource_id=f"arn:aws:s3:::{name}",
                name=name,
                owner_id=owner,  # type: ignore[arg-type]
                resource_type="S3Bucket",
                region=region,
                state="Active",
                creation_date=created_iso,
                storage_gb=size_gb,
                object_count=objects,
                estimated_cost=estimated_cost,
                potential_saving=best_saving,
                flags=flags,
                confidence=conf,
                signals=_signals_str(signals),
            )
        except Exception as exc:  # pylint: disable=broad-except
            log.warning("[s3] write_row failed for %s: %s", name, exc)

        rows.append(
            {
                "bucket": name,
                "size_gb": size_gb,
                "objects": objects,
                "potential": float(best_saving or 0.0),
            }
        )

    return rows
