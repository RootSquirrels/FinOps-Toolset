"""Checkers: Amazon Machine Images (AMIs).

Checks included:

  - check_ami_public_or_shared
      Flags public AMIs or AMIs shared outside the account (hygiene/security).

  - check_ami_unused_and_snapshot_cost
      AMIs not referenced by any instance or launch template/config.
      Estimates monthly snapshot storage cost tied to the AMI.

  - check_ami_old_images
      Very old AMIs (age threshold). Uses snapshot cost as potential saving.

  - check_ami_unencrypted_snapshots
      AMIs whose backing EBS snapshots are unencrypted (hygiene).

Design:
  - Dependencies injected via finops_toolset.checkers.config.setup(...).
  - Tolerant signatures for run_check; no return values; graceful skips.
  - Uses EBS snapshot pricing keys from your pricebook:
        "EBS" -> "SNAPSHOT_STANDARD_GB_MONTH", "SNAPSHOT_ARCHIVE_GB_MONTH"
  - Timezone-aware datetimes (datetime.now(timezone.utc)).
  - Pylint-friendly, lines <= 100 chars.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from botocore.exceptions import ClientError

from aws_checkers import config
from core.retry import retry_with_backoff


# ------------------------------- helpers -------------------------------- #

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


def _extract_writer_ec2(
    args: Tuple[Any, ...],
    kwargs: Dict[str, Any],
) -> Tuple[Any, Any]:
    """Accept writer/ec2 passed positionally or by keyword; prefer keywords."""
    writer = kwargs.get("writer", args[0] if len(args) >= 1 else None)
    ec2 = kwargs.get("ec2", args[1] if len(args) >= 2 else None)
    if writer is None or ec2 is None:
        raise TypeError(
            "Expected 'writer' and 'ec2' "
            f"(got writer={writer!r}, ec2={ec2!r})"
        )
    return writer, ec2


def _chunk(seq: Sequence[str], n: int) -> Iterable[List[str]]:
    for i in range(0, len(seq), n):
        yield list(seq[i:i + n])


def _creation_dt(ami: Dict[str, Any]) -> Optional[datetime]:
    cstr = (ami.get("CreationDate") or "").strip()
    if not cstr:
        return None
    # e.g. "2023-05-10T12:34:56.000Z"
    try:
        return datetime.strptime(cstr, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=timezone.utc)
    except Exception:  # pylint: disable=broad-except
        return None


def _gather_used_image_ids(
    ec2,
    log: logging.Logger,
    autoscaling=None,  # optional
) -> Tuple[set, int, int]:
    """Return (image_ids_in_use, instance_count, lt_count)."""
    used: set = set()
    inst_count = 0
    lt_count = 0

    # Instances
    try:
        paginator = ec2.get_paginator("describe_instances")
        for page in paginator.paginate():
            for r in page.get("Reservations", []) or []:
                for inst in r.get("Instances", []) or []:
                    img = inst.get("ImageId")
                    if img:
                        used.add(img)
                        inst_count += 1
    except ClientError as exc:
        log.debug("[ami] describe_instances failed: %s", exc)

    # Launch templates (default + latest)
    try:
        lt_p = ec2.get_paginator("describe_launch_templates")
        for page in lt_p.paginate():
            for lt in page.get("LaunchTemplates", []) or []:
                lt_id = lt.get("LaunchTemplateId")
                if not lt_id:
                    continue
                try:
                    vers = ec2.describe_launch_template_versions(
                        LaunchTemplateId=lt_id,
                        Versions=["$Latest", "$Default"],
                    )
                    for v in vers.get("LaunchTemplateVersions", []) or []:
                        data = v.get("LaunchTemplateData", {}) or {}
                        img = data.get("ImageId")
                        if img:
                            used.add(img)
                            lt_count += 1
                except ClientError as exc:
                    log.debug("[ami] describe_launch_template_versions %s: %s", lt_id, exc)
    except ClientError as exc:
        log.debug("[ami] describe_launch_templates failed: %s", exc)

    # Launch configurations (Auto Scaling) – optional
    if autoscaling is not None:
        try:
            lc_p = autoscaling.get_paginator("describe_launch_configurations")
            for page in lc_p.paginate():
                for lc in page.get("LaunchConfigurations", []) or []:
                    img = lc.get("ImageId")
                    if img:
                        used.add(img)
                        lt_count += 1
        except ClientError as exc:
            log.debug("[ami] describe_launch_configurations failed: %s", exc)

    return used, inst_count, lt_count


def _describe_snapshots_map(
    ec2,
    snapshot_ids: List[str],
    log: logging.Logger,
) -> Dict[str, Dict[str, Any]]:
    """Batch describe snapshots, return {snapshotId: snapshot_dict}."""
    info: Dict[str, Dict[str, Any]] = {}
    if not snapshot_ids:
        return info

    for chunk_ids in _chunk(snapshot_ids, 200):
        try:
            resp = ec2.describe_snapshots(SnapshotIds=chunk_ids)
            for s in resp.get("Snapshots", []) or []:
                sid = s.get("SnapshotId")
                if sid:
                    info[sid] = s
        except ClientError as exc:
            log.debug("[ami] describe_snapshots for chunk failed: %s", exc)
    return info


def _ami_snapshot_ids(ami: Dict[str, Any]) -> List[str]:
    snap_ids: List[str] = []
    for bdm in ami.get("BlockDeviceMappings", []) or []:
        ebs = bdm.get("Ebs") or {}
        sid = ebs.get("SnapshotId")
        if sid:
            snap_ids.append(sid)
    return snap_ids


def _snapshot_monthly_cost(snap: Dict[str, Any]) -> float:
    size_gb = float(snap.get("VolumeSize") or 0.0)
    tier = (snap.get("StorageTier") or "standard").lower()
    p_std = config.safe_price("EBS", "SNAPSHOT_STANDARD_GB_MONTH", 0.0)
    p_arc = config.safe_price("EBS", "SNAPSHOT_ARCHIVE_GB_MONTH", 0.0)
    price = p_arc if tier == "archive" else p_std
    return size_gb * price


def _estimate_ami_snapshot_cost(
    ami: Dict[str, Any],
    snap_map: Dict[str, Dict[str, Any]],
) -> float:
    tot = 0.0
    for sid in _ami_snapshot_ids(ami):
        tot += _snapshot_monthly_cost(snap_map.get(sid, {}))
    return tot


# -------------------- 1) Public / shared AMIs (hygiene) ------------------ #

@retry_with_backoff(exceptions=(ClientError,))
def check_ami_public_or_shared(  # pylint: disable=unused-argument
    *args,
    logger: Optional[logging.Logger] = None,
    **kwargs,
) -> None:
    """Flag AMIs that are public or shared with other AWS accounts."""
    log = _logger(kwargs.get("logger") or logger)

    try:
        writer, ec2 = _extract_writer_ec2(args, kwargs)
    except TypeError as exc:
        log.warning("[check_ami_public_or_shared] Skipping: %s", exc)
        return
    if not (config.ACCOUNT_ID and config.WRITE_ROW):
        log.warning("[check_ami_public_or_shared] Skipping: checker config not provided.")
        return

    region = getattr(getattr(ec2, "meta", None), "region_name", "") or ""

    try:
        imgs = ec2.describe_images(Owners=["self"]).get("Images", []) or []
    except ClientError as exc:
        log.error("[check_ami_public_or_shared] describe_images failed: %s", exc)
        return

    for ami in imgs:
        ami_id = ami.get("ImageId") or ""
        name = ami.get("Name") or ami_id
        is_public = bool(ami.get("Public"))
        shared_outside = False
        shared_ids: List[str] = []

        # Image attribute sharing
        try:
            attr = ec2.describe_image_attribute(
                ImageId=ami_id,
                Attribute="launchPermission",
            )
            perms = attr.get("LaunchPermissions", []) or []
            for p in perms:
                if p.get("Group") == "all":
                    is_public = True
                uid = p.get("UserId")
                if uid and str(uid) != str(config.ACCOUNT_ID or ""):
                    shared_outside = True
                    shared_ids.append(str(uid))
        except ClientError as exc:
            log.debug("[ami] describe_image_attribute %s: %s", ami_id, exc)

        flags: List[str] = []
        if is_public:
            flags.append("AMIPublic")
        if shared_outside:
            flags.append("AMISharedOutsideAccount")
        if not flags:
            continue

        created = _creation_dt(ami)
        signals = _signals_str(
            {
                "Region": region,
                "ImageId": ami_id,
                "Name": name,
                "CreatedAt": _to_utc_iso(created),
                "SharedWith": ",".join(shared_ids) if shared_ids else "",
            }
        )

        try:
            # type: ignore[call-arg]
            config.WRITE_ROW(
                writer=writer,
                resource_id=ami_id,
                name=name,
                owner_id=config.ACCOUNT_ID,  # type: ignore[arg-type]
                resource_type="AMI",
                estimated_cost=0.0,
                potential_saving=0.0,
                flags=flags,
                confidence=100,
                signals=signals,
            )
        except Exception as exc:  # pylint: disable=broad-except
            log.warning("[check_ami_public_or_shared] write_row failed for %s: %s", ami_id, exc)

        log.info("[check_ami_public_or_shared] Wrote: %s (flags=%s)", ami_id, flags)


# -------- 2) Unused AMIs + estimated snapshot storage (potential save) --- #

@retry_with_backoff(exceptions=(ClientError,))
def check_ami_unused_and_snapshot_cost(  # pylint: disable=unused-argument
    *args,
    logger: Optional[logging.Logger] = None,
    min_age_days: int = 14,
    **kwargs,
) -> None:
    """
    Flag AMIs not referenced by any instance / LT / LC.
    Potential saving = sum of monthly snapshot storage tied to the AMI.
    """
    log = _logger(kwargs.get("logger") or logger)

    autoscaling = kwargs.get("autoscaling")  # optional
    try:
        writer, ec2 = _extract_writer_ec2(args, kwargs)
    except TypeError as exc:
        log.warning("[check_ami_unused_and_snapshot_cost] Skipping: %s", exc)
        return
    if not (config.ACCOUNT_ID and config.WRITE_ROW and config.GET_PRICE):
        log.warning("[check_ami_unused_and_snapshot_cost] Skipping: checker config not provided.")
        return

    region = getattr(getattr(ec2, "meta", None), "region_name", "") or ""
    now_utc = datetime.now(timezone.utc).replace(microsecond=0)
    min_created = now_utc - timedelta(days=int(min_age_days))

    # All owned images
    try:
        imgs = ec2.describe_images(Owners=["self"]).get("Images", []) or []
    except ClientError as exc:
        log.error("[check_ami_unused_and_snapshot_cost] describe_images failed: %s", exc)
        return

    # Build set of used AMI ids
    used_ids, inst_cnt, lt_cnt = _gather_used_image_ids(ec2, log, autoscaling=autoscaling)

    # Collect all backing snapshot ids for cost calc
    all_snap_ids: List[str] = []
    for ami in imgs:
        all_snap_ids.extend(_ami_snapshot_ids(ami))
    snap_map = _describe_snapshots_map(ec2, list(set(all_snap_ids)), log)

    for ami in imgs:
        ami_id = ami.get("ImageId") or ""
        name = ami.get("Name") or ami_id
        created = _creation_dt(ami)
        if created and created > now_utc:
            created = now_utc  # guard
        if created and created > min_created:
            continue  # too new, skip to avoid false positives

        if ami_id in used_ids:
            continue  # in use somewhere

        est = _estimate_ami_snapshot_cost(ami, snap_map)
        flags = ["AMIUnused"]

        signals = _signals_str(
            {
                "Region": region,
                "ImageId": ami_id,
                "Name": name,
                "CreatedAt": _to_utc_iso(created),
                "InstancesScanned": inst_cnt,
                "TemplatesScanned": lt_cnt,
                "SnapshotCount": len(_ami_snapshot_ids(ami)),
                "EstSnapshotMonthly": round(est, 2),
                "MinAgeDays": min_age_days,
            }
        )

        try:
            # type: ignore[call-arg]
            config.WRITE_ROW(
                writer=writer,
                resource_id=ami_id,
                name=name,
                owner_id=config.ACCOUNT_ID,  # type: ignore[arg-type]
                resource_type="AMI",
                estimated_cost=est,
                potential_saving=est,
                flags=flags,
                confidence=100,
                signals=signals,
            )
        except Exception as exc:  # pylint: disable=broad-except
            log.warning("[check_ami_unused_and_snapshot_cost] write_row %s: %s", ami_id, exc)

        log.info("[check_ami_unused_and_snapshot_cost] Wrote: %s (est=%.2f)", ami_id, est)


# ------------------------ 3) Old AMIs (age based) ------------------------ #

@retry_with_backoff(exceptions=(ClientError,))
def check_ami_old_images(  # pylint: disable=unused-argument
    *args,
    logger: Optional[logging.Logger] = None,
    age_days: int = 180,
    **kwargs,
) -> None:
    """
    Flag very old AMIs (CreationDate older than 'age_days').
    Potential saving = monthly snapshot storage estimate for the AMI.
    """
    log = _logger(kwargs.get("logger") or logger)

    try:
        writer, ec2 = _extract_writer_ec2(args, kwargs)
    except TypeError as exc:
        log.warning("[check_ami_old_images] Skipping: %s", exc)
        return
    if not (config.ACCOUNT_ID and config.WRITE_ROW and config.GET_PRICE):
        log.warning("[check_ami_old_images] Skipping: checker config not provided.")
        return

    region = getattr(getattr(ec2, "meta", None), "region_name", "") or ""
    cutoff = (datetime.now(timezone.utc) - timedelta(days=int(age_days))).replace(microsecond=0)

    try:
        imgs = ec2.describe_images(Owners=["self"]).get("Images", []) or []
    except ClientError as exc:
        log.error("[check_ami_old_images] describe_images failed: %s", exc)
        return

    # Preload snapshot info map for all AMIs
    all_snap_ids: List[str] = []
    for ami in imgs:
        all_snap_ids.extend(_ami_snapshot_ids(ami))
    snap_map = _describe_snapshots_map(ec2, list(set(all_snap_ids)), log)

    for ami in imgs:
        ami_id = ami.get("ImageId") or ""
        name = ami.get("Name") or ami_id
        created = _creation_dt(ami)
        if not created or created >= cutoff:
            continue

        est = _estimate_ami_snapshot_cost(ami, snap_map)

        signals = _signals_str(
            {
                "Region": region,
                "ImageId": ami_id,
                "Name": name,
                "CreatedAt": _to_utc_iso(created),
                "AgeDays": age_days,
                "SnapshotCount": len(_ami_snapshot_ids(ami)),
                "EstSnapshotMonthly": round(est, 2),
            }
        )

        try:
            # type: ignore[call-arg]
            config.WRITE_ROW(
                writer=writer,
                resource_id=ami_id,
                name=name,
                owner_id=config.ACCOUNT_ID,  # type: ignore[arg-type]
                resource_type="AMI",
                estimated_cost=est,
                potential_saving=est,
                flags=["AMIOld"],
                confidence=100,
                signals=signals,
            )
        except Exception as exc:  # pylint: disable=broad-except
            log.warning("[check_ami_old_images] write_row failed for %s: %s", ami_id, exc)

        log.info("[check_ami_old_images] Wrote: %s (age>%dd est=%.2f)", ami_id, age_days, est)


# ------------- 4) AMIs backed by unencrypted EBS snapshots -------------- #

@retry_with_backoff(exceptions=(ClientError,))
def check_ami_unencrypted_snapshots(  # pylint: disable=unused-argument
    *args,
    logger: Optional[logging.Logger] = None,
    **kwargs,
) -> None:
    """Flag AMIs whose EBS block device snapshots are unencrypted."""
    log = _logger(kwargs.get("logger") or logger)

    try:
        writer, ec2 = _extract_writer_ec2(args, kwargs)
    except TypeError as exc:
        log.warning("[check_ami_unencrypted_snapshots] Skipping: %s", exc)
        return
    if not (config.ACCOUNT_ID and config.WRITE_ROW):
        log.warning("[check_ami_unencrypted_snapshots] Skipping: checker config not provided.")
        return

    region = getattr(getattr(ec2, "meta", None), "region_name", "") or ""

    try:
        imgs = ec2.describe_images(Owners=["self"]).get("Images", []) or []
    except ClientError as exc:
        log.error("[check_ami_unencrypted_snapshots] describe_images failed: %s", exc)
        return

    # Preload snapshot encryption map
    all_snap_ids: List[str] = []
    for ami in imgs:
        all_snap_ids.extend(_ami_snapshot_ids(ami))
    snap_map = _describe_snapshots_map(ec2, list(set(all_snap_ids)), log)

    for ami in imgs:
        ami_id = ami.get("ImageId") or ""
        name = ami.get("Name") or ami_id
        created = _creation_dt(ami)

        unenc: List[str] = []
        for sid in _ami_snapshot_ids(ami):
            enc = bool(snap_map.get(sid, {}).get("Encrypted"))
            if not enc:
                unenc.append(sid)

        if not unenc:
            continue

        signals = _signals_str(
            {
                "Region": region,
                "ImageId": ami_id,
                "Name": name,
                "CreatedAt": _to_utc_iso(created),
                "UnencryptedSnapshots": ",".join(unenc),
            }
        )

        try:
            # type: ignore[call-arg]
            config.WRITE_ROW(
                writer=writer,
                resource_id=ami_id,
                name=name,
                owner_id=config.ACCOUNT_ID,  # type: ignore[arg-type]
                resource_type="AMI",
                estimated_cost=0.0,
                potential_saving=0.0,
                flags=["AMIBackedByUnencryptedSnapshots"],
                confidence=100,
                signals=signals,
            )
        except Exception as exc:  # pylint: disable=broad-except
            log.warning("[check_ami_unencrypted_snapshots] write_row %s: %s", ami_id, exc)

        log.info("[check_ami_unencrypted_snapshots] Wrote: %s (unencrypted snaps=%d)",
                 ami_id, len(unenc))
