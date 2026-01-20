"""
AMI checker.

This checker runs multiple tests against AMIs and writes at most one CSV row per AMI.
If an AMI matches multiple tests (e.g., unused and old), its flags are merged into a
single row and potential savings are not duplicated.

Tests:
  - Public or shared AMI
  - Unused AMI (not referenced by instances / launch templates / launch configs)
  - Old AMI (age threshold)
  - AMI backed by unencrypted EBS snapshots
  - Snapshot monthly cost estimation (used for estimated_cost/potential_saving where relevant)
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set, Tuple

from botocore.exceptions import ClientError

from aws_checkers import config
from aws_checkers.common import _logger, _signals_str, _to_utc_iso
from core.retry import retry_with_backoff


@dataclass
class AmiFinding:
    """Aggregated finding for one AMI across multiple tests."""
    ami_id: str
    name: str
    created_at: Optional[datetime]
    region: str
    flags: Set[str] = field(default_factory=set)
    signals: Dict[str, Any] = field(default_factory=dict)
    estimated_cost: float = 0.0
    potential_saving: float = 0.0
    confidence: int = 100

    def add_flag(self, flag: str) -> None:
        """Add one flag."""
        if flag:
            self.flags.add(flag)

    def add_signals(self, more: Dict[str, Any]) -> None:
        """Merge signals, preferring existing keys if duplicates occur."""
        for key, val in more.items():
            if key not in self.signals:
                self.signals[key] = val

    def set_costs_once(self, monthly_snapshot_cost: float) -> None:
        """
        Set costs based on monthly snapshot storage.

        Multiple tests can rely on the same cost basis (e.g., unused and old). We keep:
          - estimated_cost = max(existing, cost)
          - potential_saving = max(existing, cost)
        """
        cost = float(monthly_snapshot_cost or 0.0)
        if cost > self.estimated_cost:
            self.estimated_cost = cost
        if cost > self.potential_saving:
            self.potential_saving = cost


def _extract_writer_ec2(
    args: Tuple[Any, ...],
    kwargs: Dict[str, Any],
) -> Tuple[Any, Any]:
    """Support positional or keyword injection of writer/ec2."""
    writer = kwargs.get("writer", args[0] if len(args) >= 1 else None)
    ec2 = kwargs.get("ec2", args[1] if len(args) >= 2 else None)
    if writer is None or ec2 is None:
        raise TypeError("Expected writer and ec2 to be provided.")
    return writer, ec2


def _chunk(items: Sequence[str], chunk_size: int) -> Iterable[List[str]]:
    """Yield list chunks of given size."""
    for idx in range(0, len(items), chunk_size):
        yield list(items[idx: idx + chunk_size])


def _parse_creation_date(ami: Dict[str, Any]) -> Optional[datetime]:
    """Parse AWS AMI CreationDate into an aware datetime in UTC."""
    value = (ami.get("CreationDate") or "").strip()
    if not value:
        return None
    try:
        created = datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%fZ")
        return created.replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def _ami_snapshot_ids(ami: Dict[str, Any]) -> List[str]:
    """Extract backing EBS snapshot IDs from AMI block device mappings."""
    snapshot_ids: List[str] = []
    for bdm in ami.get("BlockDeviceMappings", []) or []:
        ebs = bdm.get("Ebs") or {}
        snap_id = ebs.get("SnapshotId")
        if snap_id:
            snapshot_ids.append(str(snap_id))
    return snapshot_ids


def _describe_snapshots_map(
    ec2: Any,
    snapshot_ids: List[str],
    log: logging.Logger,
) -> Dict[str, Dict[str, Any]]:
    """Describe snapshots in batches and return a map snapshot_id -> snapshot dict."""
    result: Dict[str, Dict[str, Any]] = {}
    if not snapshot_ids:
        return result

    uniq = list(set(snapshot_ids))
    for batch_ids in _chunk(uniq, 200):
        try:
            resp = ec2.describe_snapshots(SnapshotIds=batch_ids)
        except ClientError as exc:
            log.debug("[ami] describe_snapshots failed: %s", exc)
            continue

        for snap in resp.get("Snapshots", []) or []:
            sid = snap.get("SnapshotId")
            if sid:
                result[str(sid)] = snap
    return result


def _snapshot_monthly_cost(snapshot: Dict[str, Any]) -> float:
    """
    Estimate monthly cost for a snapshot based on VolumeSize and StorageTier.

    Uses project price keys:
      EBS / SNAPSHOT_STANDARD_GB_MONTH
      EBS / SNAPSHOT_ARCHIVE_GB_MONTH
    """
    size_gb = float(snapshot.get("VolumeSize") or 0.0)
    tier = (snapshot.get("StorageTier") or "standard").lower()

    price_standard = config.safe_price("EBS", "SNAPSHOT_STANDARD_GB_MONTH", 0.0)
    price_archive = config.safe_price("EBS", "SNAPSHOT_ARCHIVE_GB_MONTH", 0.0)

    unit = price_archive if tier == "archive" else price_standard
    return size_gb * float(unit or 0.0)


def _estimate_ami_snapshot_cost(
    ami: Dict[str, Any],
    snap_map: Dict[str, Dict[str, Any]],
) -> float:
    """Sum monthly snapshot storage cost across all backing snapshots of an AMI."""
    total = 0.0
    for sid in _ami_snapshot_ids(ami):
        total += _snapshot_monthly_cost(snap_map.get(sid, {}))
    return total


def _gather_used_image_ids(
    ec2: Any,
    log: logging.Logger,
    autoscaling: Optional[Any] = None,
) -> Tuple[Set[str], int, int]:
    """
    Gather AMI IDs referenced by:
      - EC2 instances
      - Launch templates (latest + default)
      - AutoScaling launch configurations (if autoscaling client provided)

    Returns: (used_image_ids, instances_scanned, templates_scanned)
    """
    used_ids: Set[str] = set()
    instances_scanned = 0
    templates_scanned = 0

    # Instances
    try:
        paginator = ec2.get_paginator("describe_instances")
        for page in paginator.paginate():
            for res in page.get("Reservations", []) or []:
                for inst in res.get("Instances", []) or []:
                    img = inst.get("ImageId")
                    if img:
                        used_ids.add(str(img))
                    instances_scanned += 1
    except ClientError as exc:
        log.debug("[ami] describe_instances failed: %s", exc)

    # Launch templates
    try:
        lt_paginator = ec2.get_paginator("describe_launch_templates")
        for page in lt_paginator.paginate():
            for lt in page.get("LaunchTemplates", []) or []:
                lt_id = lt.get("LaunchTemplateId")
                if not lt_id:
                    continue
                try:
                    versions = ec2.describe_launch_template_versions(
                        LaunchTemplateId=lt_id,
                        Versions=["$Latest", "$Default"],
                    )
                except ClientError as exc:
                    log.debug("[ami] describe_launch_template_versions failed: %s", exc)
                    continue

                for ver in versions.get("LaunchTemplateVersions", []) or []:
                    data = ver.get("LaunchTemplateData", {}) or {}
                    img = data.get("ImageId")
                    if img:
                        used_ids.add(str(img))
                    templates_scanned += 1
    except ClientError as exc:
        log.debug("[ami] describe_launch_templates failed: %s", exc)

    # Launch configurations (Auto Scaling) - optional
    if autoscaling is not None:
        try:
            lc_paginator = autoscaling.get_paginator("describe_launch_configurations")
            for page in lc_paginator.paginate():
                for lc in page.get("LaunchConfigurations", []) or []:
                    img = lc.get("ImageId")
                    if img:
                        used_ids.add(str(img))
                    templates_scanned += 1
        except ClientError as exc:
            log.debug("[ami] describe_launch_configurations failed: %s", exc)

    return used_ids, instances_scanned, templates_scanned


def _compute_public_shared_flags(
    ec2: Any,
    ami_id: str,
    ami: Dict[str, Any],
    account_id: str,
    log: logging.Logger,
) -> Tuple[Set[str], Dict[str, Any]]:
    """Determine AMIPublic / AMISharedOutsideAccount and return flags + signals."""
    flags: Set[str] = set()
    signals: Dict[str, Any] = {}

    is_public = bool(ami.get("Public"))
    shared_outside = False
    shared_ids: List[str] = []

    try:
        attr = ec2.describe_image_attribute(ImageId=ami_id, Attribute="launchPermission")
        perms = attr.get("LaunchPermissions", []) or []
        for perm in perms:
            if perm.get("Group") == "all":
                is_public = True
            uid = perm.get("UserId")
            if uid and str(uid) != str(account_id):
                shared_outside = True
                shared_ids.append(str(uid))
    except ClientError as exc:
        log.debug("[ami] describe_image_attribute failed (%s): %s", ami_id, exc)

    if is_public:
        flags.add("AMIPublic")
    if shared_outside:
        flags.add("AMISharedOutsideAccount")
        signals["SharedWith"] = ",".join(shared_ids)

    return flags, signals


def _compute_unencrypted_snapshot_flag(
    ami: Dict[str, Any],
    snap_map: Dict[str, Dict[str, Any]],
) -> Tuple[bool, List[str]]:
    """Return (has_unencrypted, unencrypted_snapshot_ids)."""
    unencrypted: List[str] = []
    for sid in _ami_snapshot_ids(ami):
        snap = snap_map.get(sid, {})
        encrypted = bool(snap.get("Encrypted"))
        if not encrypted:
            unencrypted.append(sid)
    return bool(unencrypted), unencrypted


@retry_with_backoff(exceptions=(ClientError,))
def run_check(  # pylint: disable=unused-argument
    *args: Any,
    logger: Optional[logging.Logger] = None,
    min_unused_age_days: int = 14,
    old_age_days: int = 180,
    **kwargs: Any,
) -> None:
    """
    Run AMI checks and write one row per AMI with merged flags.

    The checker writes a row only if at least one test matches.
    """
    log = _logger(kwargs.get("logger") or logger)

    try:
        writer, ec2 = _extract_writer_ec2(args, kwargs)
    except TypeError as exc:
        log.warning("[ami] Skipping: %s", exc)
        return

    autoscaling = kwargs.get("autoscaling")

    if not (config.ACCOUNT_ID and config.WRITE_ROW and config.GET_PRICE):
        log.warning("[ami] Skipping: checker config not provided.")
        return

    region = getattr(getattr(ec2, "meta", None), "region_name", "") or ""
    now = datetime.now(timezone.utc).replace(microsecond=0)

    # Load AMIs
    try:
        images = ec2.describe_images(Owners=["self"]).get("Images", []) or []
    except ClientError as exc:
        log.error("[ami] describe_images failed: %s", exc)
        return

    # Used AMI ids (for unused check)
    used_ids, instances_scanned, templates_scanned = _gather_used_image_ids(
        ec2,
        log,
        autoscaling=autoscaling,
    )

    # Snapshot map for cost + encryption checks
    all_snapshot_ids: List[str] = []
    for ami in images:
        all_snapshot_ids.extend(_ami_snapshot_ids(ami))
    snap_map = _describe_snapshots_map(ec2, all_snapshot_ids, log)

    # Aggregate findings per AMI
    findings: Dict[str, AmiFinding] = {}

    min_created_cutoff = now - timedelta(days=int(min_unused_age_days))
    old_cutoff = now - timedelta(days=int(old_age_days))

    for ami in images:
        ami_id = str(ami.get("ImageId") or "")
        if not ami_id:
            continue

        name = str(ami.get("Name") or ami_id)
        created_at = _parse_creation_date(ami)

        if ami_id not in findings:
            findings[ami_id] = AmiFinding(
                ami_id=ami_id,
                name=name,
                created_at=created_at,
                region=region,
            )

        finding = findings[ami_id]
        finding.add_signals(
            {
                "Region": region,
                "ImageId": ami_id,
                "Name": name,
                "CreatedAt": _to_utc_iso(created_at),
            }
        )

        # Common cost basis (computed once per AMI)
        snapshot_count = len(_ami_snapshot_ids(ami))
        monthly_snapshot_cost = _estimate_ami_snapshot_cost(ami, snap_map)
        finding.add_signals(
            {
                "SnapshotCount": snapshot_count,
                "EstSnapshotMonthly": round(monthly_snapshot_cost, 2),
            }
        )

        # Test 1: public/shared
        pub_flags, pub_signals = _compute_public_shared_flags(
            ec2=ec2,
            ami_id=ami_id,
            ami=ami,
            account_id=str(config.ACCOUNT_ID),
            log=log,
        )
        for flag in pub_flags:
            finding.add_flag(flag)
        finding.add_signals(pub_signals)

        # Test 2: unused (and mature enough)
        # "unused" means not referenced by instances/LT/LC.
        if ami_id not in used_ids:
            too_new = created_at is not None and created_at > min_created_cutoff
            if not too_new:
                finding.add_flag("AMIUnused")
                finding.add_signals(
                    {
                        "MinUnusedAgeDays": int(min_unused_age_days),
                        "InstancesScanned": instances_scanned,
                        "TemplatesScanned": templates_scanned,
                    }
                )
                # Savings basis: snapshot storage (count once even if other tests match)
                finding.set_costs_once(monthly_snapshot_cost)

        # Test 3: old
        if created_at is not None and created_at < old_cutoff:
            finding.add_flag("AMIOld")
            finding.add_signals({"OldAgeDays": int(old_age_days)})
            # Same savings basis as unused: snapshot storage (do not double count)
            finding.set_costs_once(monthly_snapshot_cost)

        # Test 4: unencrypted snapshots
        has_unenc, unenc_ids = _compute_unencrypted_snapshot_flag(ami, snap_map)
        if has_unenc:
            finding.add_flag("AMIBackedByUnencryptedSnapshots")
            finding.add_signals({"UnencryptedSnapshots": ",".join(unenc_ids)})

    # Write rows: only AMIs with at least one flag
    wrote = 0
    for finding in findings.values():
        if not finding.flags:
            continue

        signals = _signals_str(finding.signals)
        flags_sorted = sorted(finding.flags)

        try:
            # config.WRITE_ROW is the standard writer wrapper used across checkers.
            config.WRITE_ROW(  # type: ignore[call-arg]
                writer=writer,
                resource_id=finding.ami_id,
                name=finding.name,
                owner_id=config.ACCOUNT_ID,  # type: ignore[arg-type]
                resource_type="AMI",
                estimated_cost=float(finding.estimated_cost),
                potential_saving=float(finding.potential_saving),
                flags=flags_sorted,
                confidence=int(finding.confidence),
                signals=signals,
            )
        except Exception as exc:  # pylint: disable=broad-except
            log.warning("[ami] write_row failed for %s: %s", finding.ami_id, exc)
            continue

        wrote += 1

    log.info("[ami] Completed. AMIs scanned=%d, rows written=%d", len(images), wrote)
