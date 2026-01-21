"""Checkers: Amazon S3 (cost & compliance, single row per bucket).

This checker relies primarily on CloudWatch S3 Storage Metrics:
  - AWS/S3 BucketSizeBytes (daily, delayed)
  - AWS/S3 NumberOfObjects (daily, delayed)

Because these metrics can be delayed and because CloudWatch is regional,
this module:
  1) Ensures the CloudWatch client is created in the bucket's region.
  2) Uses the maximum value observed in the lookback window (more robust).
  3) Adds a best-effort fallback to S3 Inventory reports when CW metrics are missing
     (e.g., many buckets show 0 objects and 0 cost).

The output remains one CSV row per bucket and preserves the existing features.
"""

from __future__ import annotations

import csv
import gzip
import io
import json
import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple

import boto3
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

# Inventory guardrails (keep the checker fast/safe)
_INV_MAX_FILES: int = 10
_INV_MAX_TOTAL_BYTES: int = 50 * 1024 * 1024  # 50 MiB compressed/uncompressed best-effort


def _safe_price(service: str, key: str, default: float = 0.0) -> float:
    """Resolve a price via chk.safe_price(service, key, default)."""
    try:
        return float(chk.safe_price(service, key, default))  # type: ignore[arg-type]
    except Exception:  # pylint: disable=broad-except
        return float(default)


# ---------------------------------------------------------------------------
# Pagination helpers
# ---------------------------------------------------------------------------

def _bytes_to_gib(num: float) -> float:
    """Convert bytes to GiB."""
    try:
        return float(num) / (1024.0 ** 3)
    except Exception:  # pylint: disable=broad-except
        return 0.0


def _latest_metric_value(points: List[Tuple[datetime, float]]) -> float:
    """Return a robust metric value from a CloudWatch time series.

    S3 storage metrics can be delayed; relying on the newest timestamp can yield empty.
    We take the maximum in the window as best-effort.
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
# S3 bucket discovery helpers
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


# ---------------------------------------------------------------------------
# CloudWatch metrics (primary source)
# ---------------------------------------------------------------------------

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


# ---------------------------------------------------------------------------
# S3 Inventory fallback (secondary source)
# ---------------------------------------------------------------------------

def _parse_s3_arn_bucket(arn: str) -> Optional[str]:
    """Extract bucket name from arn:aws:s3:::bucket."""
    if not arn:
        return None
    prefix = "arn:aws:s3:::"
    if arn.startswith(prefix):
        return arn[len(prefix):]
    return None


def _list_inventory_configs(s3: BaseClient, bucket: str) -> List[Dict[str, Any]]:
    """List S3 inventory configurations for a bucket."""
    configs: List[Dict[str, Any]] = []
    token: Optional[str] = None
    while True:
        params: Dict[str, Any] = {"Bucket": bucket}
        if token:
            params["ContinuationToken"] = token
        resp = s3.list_bucket_inventory_configurations(**params)
        configs.extend(resp.get("InventoryConfigurationList", []) or [])
        token = resp.get("NextContinuationToken")
        if not token:
            break
    return configs


def _find_latest_manifest_key(
    s3: BaseClient,
    dst_bucket: str,
    prefix: str,
) -> Optional[str]:
    """Return the newest manifest.json key under the given prefix (lexicographic)."""
    latest: Optional[str] = None
    token: Optional[str] = None
    while True:
        params: Dict[str, Any] = {"Bucket": dst_bucket, "Prefix": prefix}
        if token:
            params["ContinuationToken"] = token
        resp = s3.list_objects_v2(**params)
        for obj in resp.get("Contents", []) or []:
            key = obj.get("Key")
            if not key:
                continue
            if not key.endswith("manifest.json"):
                continue
            if latest is None or str(key) > latest:
                latest = str(key)
        token = resp.get("NextContinuationToken")
        if not token:
            break
    return latest


def _read_json_object(s3: BaseClient, bucket: str, key: str) -> Optional[Dict[str, Any]]:
    """Read an S3 object and parse it as JSON."""
    try:
        resp = s3.get_object(Bucket=bucket, Key=key)
        raw = resp["Body"].read()
        return json.loads(raw.decode("utf-8"))
    except Exception:  # pylint: disable=broad-except
        return None


def _open_inventory_stream(body_bytes: bytes, key: str) -> io.TextIOBase:
    """Open inventory file bytes as a text stream (supports .gz)."""
    if key.endswith(".gz"):
        gz = gzip.GzipFile(fileobj=io.BytesIO(body_bytes))
        return io.TextIOWrapper(gz, encoding="utf-8", newline="")
    return io.TextIOWrapper(io.BytesIO(body_bytes), encoding="utf-8", newline="")


def _aggregate_inventory_csv(
    s3: BaseClient,
    dst_bucket: str,
    file_keys: List[str],
    schema: str,
    logger: logging.Logger,
) -> Tuple[int, float, Dict[str, float], bool, str]:
    """Aggregate inventory CSV files.

    Returns:
      (object_count, total_bytes, bytes_by_storage_class, complete, note)
    """
    cols = [c.strip() for c in (schema or "").split(",") if c.strip()]
    idx_size = cols.index("Size") if "Size" in cols else -1
    idx_sc = cols.index("StorageClass") if "StorageClass" in cols else -1

    if idx_size < 0:
        return 0, 0.0, {}, False, "InventorySchemaMissingSize"

    obj_count = 0
    total_bytes = 0.0
    by_sc: Dict[str, float] = {}

    processed_files = 0
    processed_bytes = 0

    for key in file_keys:
        if processed_files >= _INV_MAX_FILES:
            return obj_count, total_bytes, by_sc, False, "InventoryPartialMaxFiles"
        processed_files += 1

        try:
            resp = s3.get_object(Bucket=dst_bucket, Key=key)
            raw = resp["Body"].read()
        except ClientError as exc:
            logger.debug("Inventory get_object failed: %s/%s: %s", dst_bucket, key, exc)
            continue

        processed_bytes += len(raw)
        if processed_bytes > _INV_MAX_TOTAL_BYTES:
            return obj_count, total_bytes, by_sc, False, "InventoryPartialMaxBytes"

        stream = _open_inventory_stream(raw, key)
        reader = csv.reader(stream)
        try:
            for row in reader:
                if not row or len(row) <= idx_size:
                    continue
                try:
                    size = float(row[idx_size] or 0.0)
                except Exception:  # pylint: disable=broad-except
                    size = 0.0

                if size < 0.0:
                    size = 0.0

                obj_count += 1
                total_bytes += size

                if idx_sc >= 0 and len(row) > idx_sc:
                    sc = (row[idx_sc] or "UNKNOWN").strip() or "UNKNOWN"
                    by_sc[sc] = by_sc.get(sc, 0.0) + size
        finally:
            try:
                stream.close()
            except Exception:  # pylint: disable=broad-except
                pass

    return obj_count, total_bytes, by_sc, True, "InventoryComplete"


def _inventory_fallback(
    s3: BaseClient,
    bucket_name: str,
    logger: logging.Logger,
) -> Tuple[Optional[int], Optional[float], Dict[str, float], Dict[str, Any]]:
    """Try to compute bucket object count and size via S3 Inventory.

    Returns:
      object_count (or None), size_gb (or None), storageclass_gb (bytes->GiB map),
      inv_signals (diagnostics)
    """
    inv_signals: Dict[str, Any] = {"InventoryUsed": False}

    try:
        configs = _list_inventory_configs(s3, bucket_name)
    except ClientError as exc:
        inv_signals["InventoryError"] = f"ListConfigsFailed:{exc.response.get('Error', {}).get('Code', 'Unknown')}"
        return None, None, {}, inv_signals

    # Pick the first enabled config (simple + deterministic)
    chosen: Optional[Dict[str, Any]] = None
    for cfg in configs:
        if cfg.get("IsEnabled") is True:
            chosen = cfg
            break

    if not chosen:
        inv_signals["InventoryNote"] = "NoEnabledInventoryConfig"
        return None, None, {}, inv_signals

    inv_id = str(chosen.get("Id") or "inventory")
    dest = (chosen.get("Destination") or {}).get("S3BucketDestination") or {}
    dst_arn = str(dest.get("Bucket") or "")
    dst_bucket = _parse_s3_arn_bucket(dst_arn)
    if not dst_bucket:
        inv_signals["InventoryNote"] = "InventoryDestinationBucketUnknown"
        return None, None, {}, inv_signals

    prefix = str(dest.get("Prefix") or "")
    if prefix and not prefix.endswith("/"):
        prefix = f"{prefix}/"

    # Common inventory layout:
    #   <prefix><source-bucket>/<config-id>/<YYYY-MM-DD>/manifest.json
    base_prefix = f"{prefix}{bucket_name}/{inv_id}/"
    manifest_key = _find_latest_manifest_key(s3, dst_bucket, base_prefix)

    if not manifest_key:
        inv_signals["InventoryNote"] = "NoManifestFound"
        inv_signals["InventoryDestination"] = dst_bucket
        inv_signals["InventoryBasePrefix"] = base_prefix
        return None, None, {}, inv_signals

    manifest = _read_json_object(s3, dst_bucket, manifest_key)
    if not manifest:
        inv_signals["InventoryNote"] = "ManifestUnreadable"
        inv_signals["InventoryManifest"] = manifest_key
        return None, None, {}, inv_signals

    # Identify format and files
    fmt = str((manifest.get("fileFormat") or manifest.get("format") or "")).upper()
    schema = str(manifest.get("fileSchema") or "")
    files = manifest.get("files") or []
    file_keys: List[str] = []
    for f in files:
        k = f.get("key")
        if k:
            file_keys.append(str(k))

    inv_signals["InventoryUsed"] = True
    inv_signals["InventoryId"] = inv_id
    inv_signals["InventoryDestination"] = dst_bucket
    inv_signals["InventoryManifest"] = manifest_key
    inv_signals["InventoryFormat"] = fmt

    if not file_keys:
        inv_signals["InventoryNote"] = "NoInventoryFiles"
        return None, None, {}, inv_signals

    # Only implement CSV/CSV.GZ aggregation (most common). ORC/Parquet skipped (safe).
    if fmt not in {"CSV", "CSV_GZ", "CSV.GZ", ""}:
        inv_signals["InventoryNote"] = "InventoryFormatUnsupported"
        return None, None, {}, inv_signals

    obj_count, total_bytes, by_sc_bytes, complete, note = _aggregate_inventory_csv(
        s3=s3,
        dst_bucket=dst_bucket,
        file_keys=file_keys,
        schema=schema,
        logger=logger,
    )

    inv_signals["InventoryComplete"] = complete
    inv_signals["InventoryNote"] = note
    inv_signals["InventoryFilesSeen"] = min(len(file_keys), _INV_MAX_FILES)

    size_gb = round(_bytes_to_gib(total_bytes), 3) if total_bytes > 0 else 0.0
    by_sc_gb = {k: round(_bytes_to_gib(v), 3) for k, v in by_sc_bytes.items()}

    return obj_count, size_gb, by_sc_gb, inv_signals


# ---------------------------------------------------------------------------
# Compliance helpers
# ---------------------------------------------------------------------------

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

    # Useful: Versioning enabled but no lifecycle (often leads to unbounded noncurrent versions)
    if str(info.get("Versioning", "")).lower() == "enabled" and int(info.get("LifecycleRules") or 0) == 0:
        flags.append("VersioningNoLifecycle")

    return info, flags


# ---------------------------------------------------------------------------
# Savings heuristic (enhanced with optional storage class breakdown)
# ---------------------------------------------------------------------------

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
    std_portion_gb: Optional[float] = None,
) -> Tuple[Optional[float], List[str], Dict[str, Any], Optional[str]]:
    """Estimate potential monthly savings for bucket changes (heuristic)."""
    flags: List[str] = []
    signals: Dict[str, Any] = {}
    breakdown: Optional[str] = None

    if size_gb <= 0.0 or p_std <= 0.0:
        return None, flags, signals, breakdown

    # If we know how much is Standard (from inventory), target lifecycle only on that portion.
    std_target_gb = float(std_portion_gb) if isinstance(std_portion_gb, (int, float)) else float(size_gb)
    std_target_gb = max(0.0, min(float(size_gb), std_target_gb))
    base_cost = std_target_gb * p_std

    best_saving: float = 0.0
    best_action: Optional[str] = None

    # Heuristic: Lifecycle to IA/Glacier (only if no lifecycle already)
    if lifecycle_rules == 0 and std_target_gb >= float(min_size_gb_for_lifecycle):
        cold_gb = std_target_gb * float(max(0.0, min(1.0, assumed_cold_fraction)))
        warm_gb = std_target_gb - cold_gb

        ia_cost = warm_gb * p_std + cold_gb * p_ia
        save_ia = max(0.0, base_cost - ia_cost)

        gl_cost = warm_gb * p_std + cold_gb * p_glacier
        save_gl = max(0.0, base_cost - gl_cost)

        if save_ia > best_saving:
            best_saving = save_ia
            best_action = "AddLifecycleToIA"
            breakdown = f"StdBase={base_cost:.2f}; Std+IA={ia_cost:.2f}; Save={save_ia:.2f}"
        if save_gl > best_saving:
            best_saving = save_gl
            best_action = "AddLifecycleToGlacier"
            breakdown = f"StdBase={base_cost:.2f}; Std+Glacier={gl_cost:.2f}; Save={save_gl:.2f}"

    # Heuristic: Versioning overhead (if enabled and many objects)
    if str(versioning).lower() == "enabled" and objects >= int(min_objects_for_versions):
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
        if std_portion_gb is not None:
            signals["StdPortionGBUsedForSavings"] = round(std_target_gb, 3)
        return round(best_saving, 2), flags, signals, breakdown

    if std_portion_gb is not None:
        signals["StdPortionGBUsedForSavings"] = round(std_target_gb, 3)

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


    # Cache inventory results so we don't read inventory multiple times per bucket
    inv_cache: Dict[str, Tuple[Optional[int], Optional[float], Dict[str, float], Dict[str, Any]]] = {}

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

            cw_size_gb = float(sizes.get(name, 0.0))
            cw_objects = int(counts.get(name, 0))

            size_gb = cw_size_gb
            objects = cw_objects
            data_source = "cloudwatch"
            inv_signals: Dict[str, Any] = {"InventoryUsed": False}

            # Inventory fallback only when CW indicates empty
            if cw_size_gb <= 0.0 and cw_objects <= 0:
                if name not in inv_cache:
                    inv_cache[name] = _inventory_fallback(s3=s3, bucket_name=name, logger=log)
                inv_objects, inv_size_gb, by_sc_gb, inv_signals = inv_cache[name]

                if isinstance(inv_objects, int) and isinstance(inv_size_gb, float):
                    objects = max(0, inv_objects)
                    size_gb = max(0.0, inv_size_gb)
                    data_source = "inventory"
                    inv_signals["InventoryStorageClassGB"] = by_sc_gb

            # Compliance metadata + flags
            meta, flags = _collect_bucket_metadata(s3, name)

            # If inventory provides storage-class distribution, estimate "Standard portion"
            std_portion_gb: Optional[float] = None
            by_sc = inv_signals.get("InventoryStorageClassGB")
            if isinstance(by_sc, dict):
                # Inventory storage class strings are typically like: STANDARD, STANDARD_IA, GLACIER, DEEP_ARCHIVE...
                # We'll treat these as already-cold, so lifecycle savings should target only "STANDARD".
                std_gb = by_sc.get("STANDARD")
                if isinstance(std_gb, (int, float)):
                    std_portion_gb = float(std_gb)

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
                std_portion_gb=std_portion_gb,
            )
            if breakdown:
                signals["SavingsBreakdown"] = breakdown

            # Merge flags (dedup)
            flags = sorted(set(flags) | set(add_flags))

            # Estimated monthly cost (baseline Standard per-GB-month).
            # If we have storage class breakdown via inventory, cost is still baseline but we expose breakdown in signals.
            estimated_cost = round(size_gb * p_std, 2) if p_std > 0.0 else 0.0

            # Signals
            signals_blob: Dict[str, Any] = {
                **meta,
                **signals,
                "StorageGB": round(size_gb, 3),
                "ObjectCount": objects,
                "StdGBMonthUSD": p_std,
                "DataSource": data_source,
                **inv_signals,
            }

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
                    signals=_signals_str(signals_blob),
                )
            except Exception as exc:  # pylint: disable=broad-except
                log.warning("[s3] write_row failed for %s: %s", name, exc)
