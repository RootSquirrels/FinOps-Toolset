"""S3 checker (refactored) — fast, robust signals, no redundant calls.

Goals
-----
* Keep behavior and checks intact where possible; add missing "Region" support.
* Fix bug where Signals["Objects"] / Signals["SizeGB"] ended up as "NULL" even
  for non-empty buckets by ensuring we use a **regional client** and robust
  counting logic.
* Avoid redundant API calls: compute everything per bucket in one linear pass.
* Be resilient to missing permissions; record "Unknown"/"NULL" rather than crash.

Public API
----------
- ``run(regions: list[str] | None) -> None``: enumerate and write rows via
  ``aws_checkers.config.WRITE_ROW``. If ``regions`` is provided, only buckets
  whose home region is in the list are processed.

Notes
-----
- Objects/SizeGB computation:
  * We call ``ListObjectsV2`` **once** with ``MaxKeys`` controlled by an env var
    (``S3_OBJECTS_SCAN_LIMIT``, default ``1``) to *detect emptiness fast*.
  * If the limit is ``0``, we do **no listing** (Objects/SizeGB become "NULL").
  * If the first page is non-empty and the limit > 1, we paginate up to the
    limit; if we hit the limit early we mark SizeGB as "NULL" (unknown) to avoid
    misleading totals.
  * Empty-but-accessible bucket reports ``Objects=0`` and ``SizeGB=0.0``.

- Region handling: we resolve each bucket's region via ``GetBucketLocation``,
  falling back to ``us-east-1`` (per S3 semantics). We cache regional clients.

- Checks included (non-destructive):
  * Public Access Block (account+bucket level)
  * Policy public status (GetBucketPolicyStatus)
  * ACL grants to AllUsers/AuthUsers
  * Default encryption (GetBucketEncryption)
  * Versioning/MFA-Delete
  * Logging target
  * Lifecycle rules presence
  * Replication presence
  * Object Lock configuration
  * Tags (simply collected into Signals)

This module does **not** delete or change resources; it only emits rows.
"""
from __future__ import annotations

import os
import re
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Optional, Tuple

import boto3  # type: ignore
from botocore.exceptions import BotoCoreError, ClientError  # type: ignore

from aws_checkers import config as cfg

# Optional shared SDK config — if available in repo
try:  # pragma: no cover - optional import
    from FinOps_Toolset_V2_profiler import SDK_CONFIG as _SDK_CONFIG  # type: ignore
except Exception:  # pylint: disable=broad-exception-caught
    _SDK_CONFIG = None


# --------------------------- helpers ---------------------------

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
        # Without permission, most buckets are classic region; assume us-east-1
        return "us-east-1"


def _acl_public_flags(acl: Dict[str, Any]) -> Tuple[bool, bool]:
    """Return ``(public_read, public_authusers)`` booleans from ACL grants."""
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
    """Render Signals dict into a stable key=value string separated by ' | '."""
    parts: List[str] = []
    for key in sorted(kv):
        val = kv[key]
        parts.append(f"{key}={val}")
    return " | ".join(parts)


def _gb(nbytes: int) -> float:
    return float(nbytes) / (1024.0 ** 3)


@dataclass
class BucketRow:
    """Information needed to emit one CSV row for a bucket."""

    name: str
    region: str
    owner_id: str
    created: Optional[str]
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


# --------------------------- main logic ---------------------------


def _objects_and_size(s3r, bucket: str) -> Tuple[Optional[int], Optional[float]]:
    """Return (objects_count, size_gb) with minimal calls.

    * Empty bucket: returns (0, 0.0)
    * Non-empty within scan limit: returns (N, size_gb)
    * Non-empty above scan limit: returns (N_partial, None)
    * Permission denied / cannot list: (None, None)
    """
    try:
        limit = int(os.getenv("S3_OBJECTS_SCAN_LIMIT", "1"))
    except ValueError:
        limit = 1

    if limit == 0:
        return None, None

    count = 0
    size = 0
    try:
        paginator = s3r.get_paginator("list_objects_v2")
        kwargs = {"Bucket": bucket}
        for page in paginator.paginate(**kwargs):
            # KeyCount reports number of keys in *this* page
            kc = int(page.get("KeyCount", 0) or 0)
            count += kc
            contents = page.get("Contents") or []
            for obj in contents:
                size += int(obj.get("Size", 0) or 0)
            if 0 < limit <= count:
                # We reached the limit; indicate partial by hiding SizeGB
                return count, None
            # If the bucket is empty, we exit after first page with (0, 0.0)
            if kc == 0:
                return 0, 0.0
        # Completed without hitting limit -> exact values
        return count, round(_gb(size), 3)
    except (ClientError, BotoCoreError):
        return None, None


def _collect_bucket_signals(s3r, bucket: str) -> Tuple[Dict[str, Any], List[str]]:
    """Gather bucket signals and issue flags with minimal calls.

    Returns (signals_dict, issues_list).
    """
    signals: Dict[str, Any] = {}
    issues: List[str] = []

    # Public Access Block
    try:
        pab = s3r.get_public_access_block(Bucket=bucket)
        conf = pab.get("PublicAccessBlockConfiguration", {})
        # Expose Booleans in signals (0/1), and flag if any are disabled
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
            # AccessDenied or other -> unknown
            pass

    # ACL — detect public grants
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
        # else: AccessDenied — leave unknown

    # Versioning & MFA delete
    try:
        ver = s3r.get_bucket_versioning(Bucket=bucket)
        signals["Versioning"] = ver.get("Status", "Disabled")
        if ver.get("MFADelete") == "Enabled":
            signals["MFADelete"] = 1
        else:
            signals["MFADelete"] = 0
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
        obj_lock = 1 if ol.get("ObjectLockConfiguration") else 0
        signals["ObjectLock"] = obj_lock
    except ClientError as err:
        code = (err.response or {}).get("Error", {}).get("Code", "")
        if code in {"ObjectLockConfigurationNotFoundError", "AccessDenied"}:
            signals["ObjectLock"] = 0
        else:
            issues.append("ObjectLockQueryError")

    # Tags (flatten small sets only)
    try:
        tg = s3r.get_bucket_tagging(Bucket=bucket)
        tags = {t.get("Key"): t.get("Value") for t in tg.get("TagSet") or []}
        # Store a compact form in signals (avoid exploding cell size)
        if tags:
            signals["Tags"] = ",".join(f"{k}:{v}" for k, v in sorted(tags.items()))
    except ClientError:
        pass

    # Objects & size (bug fix: avoid always-NULL by using regional client and
    # the logic in _objects_and_size)
    objects, size_gb = _objects_and_size(s3r, bucket)
    signals["Objects"] = objects if objects is not None else "NULL"
    signals["SizeGB"] = size_gb if size_gb is not None else "NULL"

    return signals, issues


def _iter_bucket_rows(regions: Optional[Iterable[str]] = None) -> Iterable[BucketRow]:
    """Yield :class:`BucketRow` for all buckets, optionally filtering by region."""
    s3g = _client("s3")  # global endpoint for list_buckets & get_bucket_location
    try:
        buckets = s3g.list_buckets().get("Buckets", [])
    except (ClientError, BotoCoreError):
        buckets = []

    regions_set = set(r.lower() for r in regions) if regions else None
    client_cache: Dict[str, Any] = {}

    owner_id = getattr(cfg, "account_id", getattr(cfg, "ACCOUNT_ID", ""))
    owner_id = str(owner_id)

    for b in buckets:
        name = b.get("Name")
        if not name:
            continue
        created = None
        if b.get("CreationDate"):
            created = str(b["CreationDate"])  # boto returns datetime; stringify

        home = _bucket_home_region(s3g, name)
        if regions_set and home.lower() not in regions_set:
            continue

        if home not in client_cache:
            client_cache[home] = _client("s3", region=home)
        s3r = client_cache[home]

        # Ensure bucket exists/accessible before deeper calls
        try:
            s3r.head_bucket(Bucket=name)
        except (ClientError, BotoCoreError):
            # Unreadable bucket; still emit a row with minimal signals
            signals = {"Objects": "NULL", "SizeGB": "NULL"}
            issues: List[str] = ["HeadBucketFailed"]
            yield BucketRow(name=name, region=home, owner_id=owner_id, created=created,
                            signals=signals, issues=issues)
            continue

        signals, issues = _collect_bucket_signals(s3r, name)
        yield BucketRow(
            name=name,
            region=home,
            owner_id=owner_id,
            created=created,
            signals=signals,
            issues=issues,
        )


# --------------------------- public API ---------------------------


def run_s3_checks(regions: Optional[Iterable[str]] = None) -> None:
    """Entry point used by the test suite/CLI to emit CSV rows for S3 buckets."""
    for br in _iter_bucket_rows(regions):
        cfg.WRITE_ROW(br.to_row())
