"""S3 checker — integrates finops_toolset.aws.cloudwatch.CloudWatchBatcher.

- Keeps all checks (PAB, policy public, ACL, default SSE, versioning/MFA, logging,
  lifecycle, replication, object lock, tags).
- Gets Objects/Size via CloudWatch in batch using your CloudWatchBatcher; falls back
  to a tiny S3 listing peek when metrics are missing.
- Accepts orchestrator clients: run(..., s3_global=..., s3_for_region=..., cw_client=...)
- Pylint: regions_set is always a set; only call proven callables (no E1102).
"""
from __future__ import annotations

import datetime as dt
import os
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Optional, Tuple

import boto3  # type: ignore
from botocore.exceptions import BotoCoreError, ClientError  # type: ignore

from aws_checkers import config as cfg
from core.cloudwatch import CloudWatchBatcher

try:  # pragma: no cover - optional shared SDK config
    from FinOps_Toolset_V2_profiler import SDK_CONFIG as _SDK_CONFIG  # type: ignore
except Exception:  # pylint: disable=broad-exception-caught
    _SDK_CONFIG = None

_S3_ARN = "arn:aws:s3:::{name}"
_ALL_USERS_URI = "http://acs.amazonaws.com/groups/global/AllUsers"
_AUTH_USERS_URI = "http://acs.amazonaws.com/groups/global/AuthenticatedUsers"

# Default storage types for size; set S3_CW_SIZE_TYPES=ALL to include all below.
_DEF_SIZE_TYPES = ["StandardStorage"]
_ALL_SIZE_TYPES = [
    "StandardStorage",
    "StandardIAStorage",
    "OneZoneIAStorage",
    "IntelligentTieringAAStorage",
    "IntelligentTieringFAStorage",
    "GlacierStorage",
    "DeepArchiveStorage",
    "ReducedRedundancyStorage",
]


def _client(service: str, *, region: Optional[str] = None):
    return (
        boto3.client(service, region_name=region, config=_SDK_CONFIG)
        if _SDK_CONFIG is not None
        else boto3.client(service, region_name=region)
    )


def _bucket_home_region(s3_client, name: str) -> str:
    """Resolve bucket region, defaulting to us-east-1 if API returns None/errors."""
    try:
        out = s3_client.get_bucket_location(Bucket=name)
        loc = out.get("LocationConstraint")
        return loc or "us-east-1"
    except (ClientError, BotoCoreError):
        return "us-east-1"


def _acl_public_flags(acl: Dict[str, Any]) -> Tuple[bool, bool]:
    """Return (public_read, public_authusers) from ACL grants."""
    public = False
    auth = False
    for grant in acl.get("Grants", []) or []:
        grantee = grant.get("Grantee", {})
        if grantee.get("Type") != "Group":
            continue
        uri = grantee.get("URI", "")
        if uri == _ALL_USERS_URI:
            public = True
        if uri == _AUTH_USERS_URI:
            auth = True
    return public, auth


def _signals_str(kv: Dict[str, Any]) -> str:
    """Render Signals as stable 'k=v | k2=v2' text."""
    parts = [f"{k}={kv[k]}" for k in sorted(kv)]
    return " | ".join(parts)


def _gb(nbytes: float) -> float:
    return float(nbytes) / (1024.0 ** 3)


# --------------------------- CloudWatch integration ---------------------------

def _cw_size_types_from_env() -> List[str]:
    env = os.getenv("S3_CW_SIZE_TYPES", ",".join(_DEF_SIZE_TYPES))
    if env.strip().upper() == "ALL":
        return list(_ALL_SIZE_TYPES)
    return [t.strip() for t in env.split(",") if t.strip()]


def _build_cw_queries_for_region(
    batcher: CloudWatchBatcher, buckets: List[str], size_types: List[str]
) -> List[Tuple[str, str]]:
    """Add queries to batcher for all buckets in a region. Returns list of (bucket, id_prefix)."""
    ids: List[Tuple[str, str]] = []
    for bname in buckets:
        # Ids can be any string; CloudWatchBatcher will sanitize & map back to this hint.
        obj_id = f"obj::{bname}"
        batcher.add_q(
            id_hint=obj_id,
            namespace="AWS/S3",
            metric="NumberOfObjects",
            dims=[
                {"Name": "BucketName", "Value": bname},
                {"Name": "StorageType", "Value": "AllStorageTypes"},
            ],
            stat="Average",
            period=86400,
        )
        # Add one query per storage class for size
        for idx, stype in enumerate(size_types, start=1):
            sid = f"sz{idx}::{bname}"
            batcher.add_q(
                id_hint=sid,
                namespace="AWS/S3",
                metric="BucketSizeBytes",
                dims=[
                    {"Name": "BucketName", "Value": bname},
                    {"Name": "StorageType", "Value": stype},
                ],
                stat="Average",
                period=86400,
            )
        ids.append((bname, "sz"))  # marker to know how many size series per bucket
    return ids


def _fetch_cw_metrics_grouped(
    cw_client,
    region_buckets: Dict[str, List[str]],
    lookback_days: int,
    size_types: List[str],
) -> Dict[str, Dict[str, Optional[float]]]:
    """Return {bucket: {'Objects': int|None, 'SizeGB': float|None}} via CloudWatchBatcher.

    We create one CloudWatchBatcher per region (metrics are regional). We pass the
    *region-specific* client to the batcher if cw_client.region matches; otherwise
    the batcher will create its own regional client.
    """
    end = dt.datetime.utcnow()
    start = end - dt.timedelta(days=max(1, lookback_days))

    results: Dict[str, Dict[str, Optional[float]]] = {}

    for region, blist in region_buckets.items():
        if not blist:
            continue

        # Prefer using the provided client only if it's already for this region.
        # boto3 clients don't expose region in a stable public way, so let the
        # batcher create a regional client. This keeps code simple and correct.
        batcher = CloudWatchBatcher(region, client=None)

        # Add queries
        _build_cw_queries_for_region(batcher, blist, size_types)

        # Execute; the batcher returns {id_hint: [(ts, val), ...]}
        series = batcher.execute(start, end, scan_by="TimestampDescending")

        # Parse back per-bucket
        for bname in blist:
            obj_vals = series.get(f"obj::{bname}", [])
            obj = int(obj_vals[0][1]) if obj_vals else None

            total_bytes = 0.0
            saw_any = False
            for idx in range(1, len(size_types) + 1):
                sid = f"sz{idx}::{bname}"
                vals = series.get(sid, [])
                if vals:
                    try:
                        total_bytes += float(vals[0][1])
                        saw_any = True
                    except (TypeError, ValueError):
                        pass
            size_gb = round(_gb(total_bytes), 3) if saw_any else None

            results[bname] = {"Objects": obj, "SizeGB": size_gb}

    return results


# -------------------------------- S3 signals ---------------------------------

def _collect_bucket_signals(s3r, bucket: str) -> Tuple[Dict[str, Any], List[str]]:
    """Gather bucket signals and issue flags with minimal, non-redundant calls."""
    signals: Dict[str, Any] = {}
    issues: List[str] = []

    # Public Access Block
    try:
        pab = s3r.get_public_access_block(Bucket=bucket)
        conf = pab.get("PublicAccessBlockConfiguration", {})
        for k in (
            "BlockPublicAcls",
            "IgnorePublicAcls",
            "BlockPublicPolicy",
            "RestrictPublicBuckets",
        ):
            signals[k] = int(bool(conf.get(k)))
        if not all(bool(conf.get(k)) for k in conf):
            issues.append("PublicAccessBlockDisabled")
    except ClientError as err:
        code = (err.response or {}).get("Error", {}).get("Code", "")
        if code not in {"NoSuchPublicAccessBlockConfiguration", "AccessDenied"}:
            issues.append("GetPublicAccessBlockError")

    # Policy public status
    try:
        pol = s3r.get_bucket_policy_status(Bucket=bucket)
        public = bool((pol.get("PolicyStatus") or {}).get("IsPublic"))
        signals["PolicyPublic"] = int(public)
        if public:
            issues.append("PolicyIsPublic")
    except ClientError as err:
        code = (err.response or {}).get("Error", {}).get("Code", "")
        if code != "NoSuchBucketPolicy":
            pass

    # ACL — public grants
    try:
        acl = s3r.get_bucket_acl(Bucket=bucket)
        pub, auth = _acl_public_flags(acl)
        signals["AclAllUsers"] = int(pub)
        signals["AclAuthUsers"] = int(auth)
        if pub or auth:
            issues.append("AclPublicGrant")
    except ClientError:
        pass

    # Default encryption
    try:
        enc = s3r.get_bucket_encryption(Bucket=bucket)
        rules = (enc.get("ServerSideEncryptionConfiguration") or {}).get("Rules", [])
        if rules:
            bydef = rules[0].get("ApplyServerSideEncryptionByDefault") or {}
            algo = bydef.get("SSEAlgorithm")
        else:
            algo = None
        signals["DefaultSSE"] = algo or "None"
        if not algo:
            issues.append("NoDefaultEncryption")
    except ClientError as err:
        code = (err.response or {}).get("Error", {}).get("Code", "")
        if code == "ServerSideEncryptionConfigurationNotFoundError":
            signals["DefaultSSE"] = "None"
            issues.append("NoDefaultEncryption")

    # Versioning & MFA delete
    try:
        ver = s3r.get_bucket_versioning(Bucket=bucket)
        signals["Versioning"] = ver.get("Status", "Disabled")
        signals["MFADelete"] = 1 if ver.get("MFADelete") == "Enabled" else 0
    except ClientError:
        pass

    # Logging
    try:
        log = s3r.get_bucket_logging(Bucket=bucket)
        enabled = 1 if log.get("LoggingEnabled") else 0
        signals["Logging"] = enabled
        if not enabled:
            issues.append("NoServerAccessLogging")
    except ClientError:
        pass

    # Lifecycle
    try:
        lc = s3r.get_bucket_lifecycle_configuration(Bucket=bucket)
        rules = lc.get("Rules", [])
        signals["LifecycleRules"] = len(rules)
    except ClientError as err:
        code = (err.response or {}).get("Error", {}).get("Code", "")
        if code in {"NoSuchLifecycleConfiguration", "AccessDenied"}:
            signals["LifecycleRules"] = 0
        else:
            issues.append("LifecycleQueryError")

    # Replication
    try:
        rp = s3r.get_bucket_replication(Bucket=bucket)
        conf = rp.get("ReplicationConfiguration")
        signals["Replication"] = 1 if conf else 0
    except ClientError as err:
        code = (err.response or {}).get("Error", {}).get("Code", "")
        if code in {"ReplicationConfigurationNotFoundError", "AccessDenied"}:
            signals["Replication"] = 0
        else:
            issues.append("ReplicationQueryError")

    # Object Lock
    try:
        ol = s3r.get_object_lock_configuration(Bucket=bucket)
        signals["ObjectLock"] = 1 if ol.get("ObjectLockConfiguration") else 0
    except ClientError as err:
        code = (err.response or {}).get("Error", {}).get("Code", "")
        if code in {"ObjectLockConfigurationNotFoundError", "AccessDenied"}:
            signals["ObjectLock"] = 0
        else:
            issues.append("ObjectLockQueryError")

    # Tags (flatten)
    try:
        tg = s3r.get_bucket_tagging(Bucket=bucket)
        tags = {t.get("Key"): t.get("Value") for t in tg.get("TagSet") or []}
        if tags:
            signals["Tags"] = ",".join(f"{k}:{v}" for k, v in sorted(tags.items()))
    except ClientError:
        pass

    return signals, issues


# -------------------------------- rows & run ---------------------------------

@dataclass
class BucketRow:
    name: str
    region: str
    owner_id: str
    created: str
    signals: Dict[str, Any]
    issues: List[str]

    def to_row(self) -> Dict[str, Any]:
        return {
            "Resource_ID": _S3_ARN.format(name=self.name),
            "Name": self.name,
            "ResourceType": "S3",
            "Region": self.region,
            "OwnerId": self.owner_id,
            "State": "active",
            "Creation_Date": self.created,
            "Storage_GB": self.signals.get("SizeGB", ""),
            "Object_Count": self.signals.get("Objects", ""),
            "Estimated_Cost_USD": 0.0,
            "Potential_Saving_USD": "",
            "ApplicationID": "",
            "Application": "",
            "Environment": "",
            "ReferencedIn": "",
            "FlaggedForReview": ", ".join(self.issues) if self.issues else "",
            "Confidence": 100,
            "Signals": _signals_str(self.signals),
        }


def _iter_bucket_rows(
    regions: Optional[Iterable[str]] = None,
    *,
    s3_global=None,
    s3_for_region=None,
    cw_client=None,
) -> Iterable[BucketRow]:
    """Yield per-bucket rows; prefer CW metrics; S3 peek fallback."""
    s3g = s3_global or _client("s3")

    try:
        buckets = s3g.list_buckets().get("Buckets", [])
    except (ClientError, BotoCoreError):
        buckets = []

    regions_set: set[str] = {r.lower() for r in regions} if regions else set()

    # Resolve home regions; group by region for CW batch; keep creation dates
    home_map: Dict[str, str] = {}
    created_map: Dict[str, str] = {}
    region_buckets: Dict[str, List[str]] = {}
    for b in buckets:
        name = b.get("Name")
        if not name:
            continue
        home = _bucket_home_region(s3g, name)
        if regions_set and home.lower() not in regions_set:
            continue
        home_map[name] = home
        created_map[name] = str(b["CreationDate"]) if b.get("CreationDate") else ""
        region_buckets.setdefault(home, []).append(name)

    # CloudWatch batch per region using your CloudWatchBatcher
    use_cw = os.getenv("S3_USE_CLOUDWATCH", "1") != "0"
    size_types = _cw_size_types_from_env()
    lookback = int(os.getenv("S3_CW_LOOKBACK_DAYS", "3") or "3")
    cw_data: Dict[str, Dict[str, Optional[float]]] = {}

    if use_cw and region_buckets:
        cw_data = _fetch_cw_metrics_grouped(
            cw_client, region_buckets, lookback_days=lookback, size_types=size_types
        )

    owner_id = str(getattr(cfg, "account_id", getattr(cfg, "ACCOUNT_ID", "")))

    # Regional S3 clients (cached)
    client_cache: Dict[str, Any] = {}
    get_s3 = s3_for_region or (lambda r: _client("s3", region=r))

    # Fallback peek limit when CW is missing/incomplete
    try:
        peek_limit = int(os.getenv("S3_OBJECTS_SCAN_LIMIT", "1") or "1")
    except ValueError:
        peek_limit = 1

    for b in buckets:
        name = b.get("Name")
        if not name or name not in home_map:
            continue
        home = home_map[name]
        created = created_map.get(name, "")

        s3r = client_cache.get(home)
        if s3r is None:
            s3r = get_s3(home)
            client_cache[home] = s3r

        signals, issues = _collect_bucket_signals(s3r, name)

        # Merge CW metrics
        cw_obj = cw_data.get(name, {}).get("Objects") if cw_data else None
        cw_sz = cw_data.get(name, {}).get("SizeGB") if cw_data else None
        obj_val: Optional[int] = cw_obj if isinstance(cw_obj, int) else None
        sz_val: Optional[float] = cw_sz if isinstance(cw_sz, (int, float)) else None

        # Fallback: one fast ListObjectsV2(MaxKeys=1) only if needed
        if (obj_val is None or sz_val is None) and peek_limit > 0:
            try:
                page = s3r.list_objects_v2(Bucket=name, MaxKeys=peek_limit)
                kcount = int(page.get("KeyCount", 0) or 0)
                if obj_val is None:
                    obj_val = kcount
                if sz_val is None:
                    sz_val = 0.0 if kcount == 0 else None
            except (ClientError, BotoCoreError):
                pass

        signals["Objects"] = obj_val if obj_val is not None else "NULL"
        signals["SizeGB"] = sz_val if sz_val is not None else "NULL"

        yield BucketRow(
            name=name,
            region=home,
            owner_id=owner_id,
            created=created,
            signals=signals,
            issues=issues,
        )


def run_s3_checks(
    regions: Optional[Iterable[str]] = None,
    *,
    s3_global=None,
    s3_for_region=None,
    cw_client=None,
) -> None:
    """Emit CSV rows for all buckets using CloudWatchBatcher when available."""
    for br in _iter_bucket_rows(
        regions,
        s3_global=s3_global,
        s3_for_region=s3_for_region,
        cw_client=cw_client,
    ):
        cfg.WRITE_ROW(br.to_row())
