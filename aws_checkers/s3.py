"""S3 checker — CW-batched metrics, tag→columns, costs, and pylint clean."""

from __future__ import annotations

import datetime as dt
import os
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Optional, Tuple

import boto3  # type: ignore
from botocore.exceptions import BotoCoreError, ClientError  # type: ignore

from aws_checkers import config as cfg
from core.cloudwatch import CloudWatchBatcher

try:  # pragma: no cover
    from FinOps_Toolset_V2_profiler import SDK_CONFIG as _SDK_CONFIG  # type: ignore
except Exception:  # pylint: disable=broad-exception-caught
    _SDK_CONFIG = None

_S3_ARN = "arn:aws:s3:::{name}"
_ALL_USERS_URI = "http://acs.amazonaws.com/groups/global/AllUsers"
_AUTH_USERS_URI = "http://acs.amazonaws.com/groups/global/AuthenticatedUsers"

# ---------- pricing knobs (simple, overridable) ----------
# default: S3 Standard first tier
_S3_PRICE_PER_GB_USD = float(os.getenv("S3_PRICE_PER_GB_USD", "0.023"))
# treat tiny/empty buckets as removable savings
_EMPTY_SIZE_GB_THRESHOLD = float(os.getenv("S3_EMPTY_SIZE_GB_THRESHOLD", "0.01"))
_EMPTY_OBJECTS_THRESHOLD = int(os.getenv("S3_EMPTY_OBJECTS_THRESHOLD", "1"))

# ---------- helpers ----------

def _client(service: str, *, region: Optional[str] = None):
    return (
        boto3.client(service, region_name=region, config=_SDK_CONFIG)
        if _SDK_CONFIG is not None
        else boto3.client(service, region_name=region)
    )


def _bucket_home_region(s3_client, name: str) -> str:
    try:
        out = s3_client.get_bucket_location(Bucket=name)
        loc = out.get("LocationConstraint")
        return loc or "us-east-1"
    except (ClientError, BotoCoreError):
        return "us-east-1"


def _acl_public_flags(acl: Dict[str, Any]) -> Tuple[bool, bool]:
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
    parts = [f"{k}={kv[k]}" for k in sorted(kv)]
    return " | ".join(parts)


def _gb(nbytes: float) -> float:
    return float(nbytes) / (1024.0 ** 3)


def _normalize_regions(regions: object) -> set[str]:
    if regions is None:
        return set()
    if isinstance(regions, str):
        return {regions.lower()}
    try:
        return {str(r).lower() for r in regions}  # type: ignore[arg-type]
    except TypeError:  # writer accidentally passed positionally, etc.
        return set()


# ---------- CloudWatch integration (via your batcher) ----------

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


def _cw_size_types_from_env() -> List[str]:
    env = os.getenv("S3_CW_SIZE_TYPES", "StandardStorage").strip()
    if env.upper() == "ALL":
        return list(_ALL_SIZE_TYPES)
    return [t.strip() for t in env.split(",") if t.strip()]


def _fetch_cw_metrics_per_region(
    region_buckets: Dict[str, List[str]],
    lookback_days: int,
    size_types: List[str],
) -> Dict[str, Dict[str, Optional[float]]]:
    """Return {bucket: {'Objects': int|None, 'SizeGB': float|None}}."""
    end = dt.datetime.utcnow()
    start = end - dt.timedelta(days=max(1, lookback_days))
    out: Dict[str, Dict[str, Optional[float]]] = {}

    for region, blist in region_buckets.items():
        if not blist:
            continue
        batcher = CloudWatchBatcher(region, client=None)
        for bname in blist:
            batcher.add_q(
                id_hint=f"obj::{bname}",
                namespace="AWS/S3",
                metric="NumberOfObjects",
                dims=[
                    {"Name": "BucketName", "Value": bname},
                    {"Name": "StorageType", "Value": "AllStorageTypes"},
                ],
                stat="Average",
                period=86400,
            )
            for idx, stype in enumerate(size_types, start=1):
                batcher.add_q(
                    id_hint=f"sz{idx}::{bname}",
                    namespace="AWS/S3",
                    metric="BucketSizeBytes",
                    dims=[
                        {"Name": "BucketName", "Value": bname},
                        {"Name": "StorageType", "Value": stype},
                    ],
                    stat="Average",
                    period=86400,
                )

        series = batcher.execute(start, end, scan_by="TimestampDescending")
        for bname in blist:
            obj_vals = series.get(f"obj::{bname}", [])
            obj = int(obj_vals[0][1]) if obj_vals else None

            total_bytes = 0.0
            saw_any = False
            for idx in range(1, len(size_types) + 1):
                vals = series.get(f"sz{idx}::{bname}", [])
                if vals:
                    saw_any = True
                    try:
                        total_bytes += float(vals[0][1])
                    except (TypeError, ValueError):
                        pass
            size_gb = round(_gb(total_bytes), 3) if saw_any else None
            out[bname] = {"Objects": obj, "SizeGB": size_gb}

    return out


# ---------- S3 signals ----------

def _collect_bucket_signals(s3r, bucket: str) -> Tuple[Dict[str, Any], List[str]]:
    """Return (signals, flags) with minimal calls; resilient to AccessDenied."""
    signals: Dict[str, Any] = {}
    flags: List[str] = []

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
            flags.append("PublicAccessBlockDisabled")
    except ClientError as err:
        code = (err.response or {}).get("Error", {}).get("Code", "")
        if code not in {"NoSuchPublicAccessBlockConfiguration", "AccessDenied"}:
            flags.append("GetPublicAccessBlockError")

    # Policy public status
    try:
        pol = s3r.get_bucket_policy_status(Bucket=bucket)
        public = bool((pol.get("PolicyStatus") or {}).get("IsPublic"))
        signals["PolicyPublic"] = int(public)
        if public:
            flags.append("PolicyIsPublic")
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
            flags.append("AclPublicGrant")
    except ClientError:
        pass

    # Default encryption
    try:
        enc = s3r.get_bucket_encryption(Bucket=bucket)
        rules = (enc.get("ServerSideEncryptionConfiguration") or {}).get("Rules", [])
        algo = None
        if rules:
            ade = rules[0].get("ApplyServerSideEncryptionByDefault") or {}
            algo = ade.get("SSEAlgorithm")
        signals["DefaultSSE"] = algo or "None"
        if not algo:
            flags.append("NoDefaultEncryption")
    except ClientError as err:
        code = (err.response or {}).get("Error", {}).get("Code", "")
        if code == "ServerSideEncryptionConfigurationNotFoundError":
            signals["DefaultSSE"] = "None"
            flags.append("NoDefaultEncryption")

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
            flags.append("NoServerAccessLogging")
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
            flags.append("LifecycleQueryError")

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
            flags.append("ReplicationQueryError")

    # Object Lock
    try:
        ol = s3r.get_object_lock_configuration(Bucket=bucket)
        signals["ObjectLock"] = 1 if ol.get("ObjectLockConfiguration") else 0
    except ClientError as err:
        code = (err.response or {}).get("Error", {}).get("Code", "")
        if code in {"ObjectLockConfigurationNotFoundError", "AccessDenied"}:
            signals["ObjectLock"] = 0
        else:
            flags.append("ObjectLockQueryError")

    # Tags: keep them in Signals only; CSV columns will be populated later
    try:
        tg = s3r.get_bucket_tagging(Bucket=bucket)
        tags = {t.get("Key"): t.get("Value") for t in tg.get("TagSet") or []}
        if tags:
            signals["Tags"] = ",".join(f"{k}:{v}" for k, v in sorted(tags.items()))
    except ClientError:
        pass

    return signals, flags


# ---------- rows ----------

@dataclass
class BucketRow:
    name: str
    region: str
    owner_id: str
    created: Optional[str]
    signals: Dict[str, Any]
    flags: List[str]

    def _parse_tags(self) -> Dict[str, str]:
        raw = self.signals.get("Tags")
        if not raw:
            return {}
        out: Dict[str, str] = {}
        for pair in str(raw).split(","):
            if ":" in pair:
                k, v = pair.split(":", 1)
                out[k.strip()] = v.strip()
        return out

    def _estimated_cost(self) -> float:
        size_gb = self.signals.get("SizeGB")
        if isinstance(size_gb, (int, float)):
            return round(float(size_gb) * _S3_PRICE_PER_GB_USD, 2)
        return 0.0

    def _potential_saving(self, est_cost: float) -> str:
        """Simple heuristic: if bucket effectively empty, saving ≈ current monthly cost."""
        objs = self.signals.get("Objects")
        size_gb = self.signals.get("SizeGB")
        if isinstance(objs, int) and isinstance(size_gb, (int, float)):
            if objs <= _EMPTY_OBJECTS_THRESHOLD and size_gb <= _EMPTY_SIZE_GB_THRESHOLD:
                return f"{est_cost:.2f}"
        return ""

    def to_row(self) -> Dict[str, Any]:
        tags = self._parse_tags()
        est_cost = self._estimated_cost()
        return {
            "resource_id": _S3_ARN.format(name=self.name),
            "name": self.name,
            "resource_type": "S3",
            "region": self.region,
            "owner_id": self.owner_id,
            "state": "active",
            "creation_date": self.created or "",
            "storage_gb": self.signals.get("SizeGB", ""),
            "object_count": self.signals.get("Objects", ""),
            "estimated_cost": est_cost,
            "potential_saving": self._potential_saving(est_cost),
            "app_id": tags.get("ApplicationID", ""),
            "app": tags.get("Application", ""),
            "env": tags.get("Environment", ""),
            "referenced_in": "N/A",
            "flags": ", ".join(self.flags) if self.flags else "",
            "confidence": 100,
            "signals": _signals_str(self.signals),
        }

# ---------- iterator & public API ----------

def _iter_bucket_rows(
    regions: Optional[Iterable[str]] = None,
    *,
    s3_global=None,
    s3_for_region=None,
) -> Iterable[BucketRow]:
    """Yield BucketRow, optionally filtering by home region (case-insensitive)."""
    s3g = s3_global or _client("s3")
    try:
        buckets = s3g.list_buckets().get("Buckets", [])
    except (ClientError, BotoCoreError):
        buckets = []

    regions_set = _normalize_regions(regions)

    # map bucket -> region and group per-region for CW batching
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

    # CloudWatch batch per region (via your batcher)
    use_cw = os.getenv("S3_USE_CLOUDWATCH", "1") != "0"
    cw_lookback = int(os.getenv("S3_CW_LOOKBACK_DAYS", "3") or "3")
    size_types = _cw_size_types_from_env()
    cw_data: Dict[str, Dict[str, Optional[float]]] = {}
    if use_cw and region_buckets:
        cw_data = _fetch_cw_metrics_per_region(
            region_buckets, lookback_days=cw_lookback, size_types=size_types
        )

    owner_id = str(getattr(cfg, "account_id", getattr(cfg, "ACCOUNT_ID", "")))

    client_cache: Dict[str, Any] = {}
    get_s3 = s3_for_region or (lambda r: _client("s3", region=r))

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

        signals, flags = _collect_bucket_signals(s3r, name)

        # Merge CW metrics or fall back to minimal peek
        cw_obj = cw_data.get(name, {}).get("Objects") if cw_data else None
        cw_sz = cw_data.get(name, {}).get("SizeGB") if cw_data else None
        obj_val: Optional[int] = cw_obj if isinstance(cw_obj, int) else None
        sz_val: Optional[float] = cw_sz if isinstance(cw_sz, (int, float)) else None

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
            flags=flags,
        )


def run(
    regions: Optional[Iterable[str]] = None,
    *,
    s3_global=None,
    s3_for_region=None,
) -> None:
    """Emit CSV rows for all buckets (DI-friendly for orchestrator)."""
    for br in _iter_bucket_rows(
        regions, s3_global=s3_global, s3_for_region=s3_for_region
    ):
        cfg.WRITE_ROW(br.to_row())
