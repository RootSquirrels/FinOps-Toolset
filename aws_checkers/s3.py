"""S3 checker — integrates core.cloudwatch batcher, no redundant calls.

What this does
==============
- Keeps **all existing checks** (PAB, policy public, ACL, default SSE, versioning/MFA,
  logging, lifecycle, replication, object lock, tags) with the same semantics.
- Fixes the bug where Signals["Objects"]/Signals["SizeGB"] showed "NULL" for
  non-empty buckets by using **regional S3 clients** and **CloudWatch metrics**.
- Uses the repository's **core.cloudwatch** batcher if available (no re-implementation).
- Accepts **orchestrator-injected clients** so we don't build duplicates.

Public API
==========
run(
    regions: list[str] | None = None,
    *,
    s3_global=None,
    s3_for_region=None,
    cw_adapter=None,
) -> None

- regions: optional filter; only process buckets whose **home region** matches.
- s3_global: orchestrator-provided S3 client for global endpoint (ListBuckets/GetBucketLocation).
- s3_for_region: callable (region:str) -> S3 client (orchestrator factory); we cache results.
- cw_adapter: core.cloudwatch batcher **or** function we can call to fetch S3 storage
  metrics for multiple buckets at once. If not provided, we try to import and use
  core.cloudwatch automatically. If nothing is available, we fall back to a tiny
  single-page ListObjectsV2 peek to classify empty vs non-empty.

Signals: Objects & SizeGB
=========================
Preferred via core.cloudwatch batcher (fast). Fallback does **one** ListObjectsV2 page
(MaxKeys=S3_OBJECTS_SCAN_LIMIT, default 1):
- empty and accessible -> Objects=0, SizeGB=0.0
- non-empty but no metrics -> Objects>=1, SizeGB="NULL" (unknown quickly)
- permission denied -> both "NULL"

No deletions/changes are performed here; this checker is read-only and emits rows via
aws_checkers.config.WRITE_ROW.
"""
from __future__ import annotations

import os
import re
from typing import Any, Dict, Iterable, List, Optional, Tuple

import boto3  # type: ignore
from botocore.exceptions import BotoCoreError, ClientError  # type: ignore

from aws_checkers import config as cfg
import core.cloudwatch as core_cw

try: 
    from FinOps_Toolset_V2_profiler import SDK_CONFIG as _SDK_CONFIG  # type: ignore
except Exception:  # pylint: disable=broad-exception-caught
    _SDK_CONFIG = None

_S3_ARN = "arn:aws:s3:::{name}"
_ALL_USERS_URI = "http://acs.amazonaws.com/groups/global/AllUsers"
_AUTH_USERS_URI = "http://acs.amazonaws.com/groups/global/AuthenticatedUsers"
_S12 = re.compile(r"^\d{12}$")


def _client(service: str, *, region: Optional[str] = None):
    return (
        boto3.client(service, region_name=region, config=_SDK_CONFIG)
        if _SDK_CONFIG is not None
        else boto3.client(service, region_name=region)
    )


def _bucket_home_region(s3_client, name: str) -> str:
    """Resolve bucket region, defaulting to us-east-1 if API returns None."""
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
        gr = grant.get("Grantee", {})
        if gr.get("Type") != "Group":
            continue
        uri = gr.get("URI", "")
        if uri == _ALL_USERS_URI:
            public = True
        if uri == _AUTH_USERS_URI:
            auth = True
    return public, auth


def _signals_str(kv: Dict[str, Any]) -> str:
    parts: List[str] = []
    for key in sorted(kv):
        parts.append(f"{key}={kv[key]}")
    return " | ".join(parts)


# ---------------- CloudWatch adapter (uses core.cloudwatch) ----------------

_DEF_SIZE_TYPES = ["StandardStorage"]


def _get_cw_s3_metrics_adapter(cw_adapter: Any) -> Optional[Any]:
    """Return a callable buckets->metrics, consulting core.cloudwatch when needed.

    We accept:
    - a callable(adapter)(buckets, size_types, lookback_days)
    - an object with method among: s3_storage_metrics / get_s3_storage_metrics /
      fetch_s3_storage_metrics
    - a module core.cloudwatch exposing any of the above names
    """
    if cw_adapter is not None:
        if callable(cw_adapter):
            return cw_adapter
        for meth in (
            "s3_storage_metrics",
            "get_s3_storage_metrics",
            "fetch_s3_storage_metrics",
        ):
            fn = getattr(cw_adapter, meth, None)
            if callable(fn):
                return fn
        return None

    try:  # autodetect

        for name in (
            "s3_storage_metrics",
            "get_s3_storage_metrics",
            "fetch_s3_storage_metrics",
        ):
            fn = getattr(core_cw, name, None)
            if callable(fn):
                return fn
    except Exception:  # pylint: disable=broad-exception-caught
        return None
    return None


# ---------------------------- S3 signals ----------------------------


def _collect_bucket_signals(s3r, bucket: str) -> Tuple[Dict[str, Any], List[str]]:
    """Gather bucket signals and issue flags with minimal, non-redundant calls."""
    signals: Dict[str, Any] = {}
    issues: List[str] = []

    # Public Access Block
    try:
        pab = s3r.get_public_access_block(Bucket=bucket)
        conf = pab.get("PublicAccessBlockConfiguration", {})
        for k in ("BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets"):
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
        algo = (rules[0].get("ApplyServerSideEncryptionByDefault") or {}).get("SSEAlgorithm") if rules else None
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


# ------------------------------- rows -------------------------------

class BucketRow:
    """Row builder for CSV emission."""

    __slots__ = ("name", "region", "owner_id", "created", "signals", "issues")

    def __init__(
        self,
        name: str,
        region: str,
        owner_id: str,
        created: Optional[str],
        signals: Dict[str, Any],
        issues: List[str],
    ) -> None:
        self.name = name
        self.region = region
        self.owner_id = owner_id
        self.created = created
        self.signals = signals
        self.issues = issues

    def to_row(self) -> Dict[str, Any]:
        return {
            "Resource_ID": _S3_ARN.format(name=self.name),
            "Name": self.name,
            "ResourceType": "S3",
            "Region": self.region,
            "OwnerId": self.owner_id,
            "State": "active",
            "Creation_Date": self.created or "",
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


# ------------------------------ main ------------------------------


def _iter_bucket_rows(
    regions: Optional[Iterable[str]] = None,
    *,
    s3_global=None,
    s3_for_region=None,
    cw_adapter=None,
) -> Iterable[BucketRow]:
    """Yield BucketRow for buckets (filtered by regions if provided).

    Clients can be injected by orchestrator to avoid re-creating them.
    """
    s3g = s3_global or _client("s3")

    try:
        buckets = s3g.list_buckets().get("Buckets", [])
    except (ClientError, BotoCoreError):
        buckets = []

    regions_set = set(r.lower() for r in regions) if regions else None

    # Resolve home region per bucket once; keep only those we need
    home_map: Dict[str, str] = {}
    names: List[str] = []
    for b in buckets:
        name = b.get("Name")
        if not name:
            continue
        home = _bucket_home_region(s3g, name)
        if regions_set and home.lower() not in regions_set:
            continue
        home_map[name] = home
        names.append(name)

    # CloudWatch batch fast-path via core.cloudwatch
    adapter = _get_cw_s3_metrics_adapter(cw_adapter)
    lookback = int(os.getenv("S3_CW_LOOKBACK_DAYS", "3") or "3")
    size_types_env = os.getenv("S3_CW_SIZE_TYPES", ",".join(_DEF_SIZE_TYPES))
    size_types = (
        [
            "StandardStorage",
            "StandardIAStorage",
            "OneZoneIAStorage",
            "IntelligentTieringAAStorage",
            "IntelligentTieringFAStorage",
            "GlacierStorage",
            "DeepArchiveStorage",
            "ReducedRedundancyStorage",
        ]
        if size_types_env.strip().upper() == "ALL"
        else [t.strip() for t in size_types_env.split(",") if t.strip()]
    )

    cw_metrics: Dict[str, Dict[str, Optional[float]]] = {}
    if adapter and names:
        try:
            cw_metrics = adapter(names, size_types, lookback)
        except Exception:  # pylint: disable=broad-exception-caught
            cw_metrics = {}

    owner_id = str(getattr(cfg, "account_id", getattr(cfg, "ACCOUNT_ID", "")))

    # Regional clients on demand
    client_cache: Dict[str, Any] = {}
    get_s3 = s3_for_region or (lambda r: _client("s3", region=r))

    # Fallback object peek limit when no CW metrics
    try:
        peek_limit = int(os.getenv("S3_OBJECTS_SCAN_LIMIT", "1") or "1")
    except ValueError:
        peek_limit = 1

    for b in buckets:
        name = b.get("Name")
        if not name or name not in home_map:
            continue
        home = home_map[name]
        created = None
        if b.get("CreationDate"):
            created = str(b["CreationDate"])  # boto returns datetime; stringify

        s3r = client_cache.get(home)
        if s3r is None:
            s3r = get_s3(home)
            client_cache[home] = s3r

        signals, issues = _collect_bucket_signals(s3r, name)

        # Merge CloudWatch metrics if available
        cw_obj = cw_metrics.get(name, {}).get("Objects") if cw_metrics else None
        cw_sz = cw_metrics.get(name, {}).get("SizeGB") if cw_metrics else None

        obj_val: Optional[int] = cw_obj if isinstance(cw_obj, int) else None
        sz_val: Optional[float] = cw_sz if isinstance(cw_sz, (int, float)) else None

        # Fallback: single fast ListObjectsV2 peek to classify emptiness only
        if (obj_val is None or sz_val is None) and peek_limit > 0:
            try:
                page = s3r.list_objects_v2(Bucket=name, MaxKeys=peek_limit)
                kcount = int(page.get("KeyCount", 0) or 0)
                if obj_val is None:
                    obj_val = kcount
                if sz_val is None:
                    sz_val = 0.0 if kcount == 0 else None
            except (ClientError, BotoCoreError):
                # leave as None (unknown)
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


# ----------------------------- public API -----------------------------


def run_s3_checks(
    regions: Optional[Iterable[str]] = None,
    *,
    s3_global=None,
    s3_for_region=None,
    cw_adapter=None,
) -> None:
    """Emit CSV rows for all buckets using core.cloudwatch batcher when available.

    Orchestrator can inject clients and the CW adapter to ensure zero duplication.
    """
    for br in _iter_bucket_rows(
        regions,
        s3_global=s3_global,
        s3_for_region=s3_for_region,
        cw_adapter=cw_adapter,
    ):
        cfg.WRITE_ROW(br.to_row())
