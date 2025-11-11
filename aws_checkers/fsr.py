"""Checkers: Amazon EBS Fast Snapshot Restore (FSR).

Checks included:

  - check_ebs_fsr_enabled_snapshots
      Finds snapshots with FSR enabled (per AZ). Estimates monthly DSU-hour cost:
      price("EBS_FSR", "DSU_HR") * 730 * enabled_AZ_count. Also flags snapshots
      with no fast-restored volumes in the lookback window.

Design:
  - Dependencies via finops_toolset.checkers.config.setup(...).
  - Tolerant signatures; graceful skips; no return values.
  - UTC datetimes; pylint-friendly; lines ≤ 100 chars.

Notes:
  - Cost model matches AWS docs: billed per minute (1h min) while FSR is enabled
    for a snapshot in a given AZ; default $0.75/DSU-hr per AZ (region-specific).
  - We aggregate by snapshot (sum of enabled AZs) to avoid noisy per-AZ rows.

Pricebook keys used (safe defaults if absent):
  "EBS_FSR": { "DSU_HR": 0.75 }
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple

from botocore.exceptions import ClientError
from finops_toolset import config as const

from aws_checkers import config
from aws_checkers.common import (
    _logger,
    _signals_str,
    _to_utc_iso,
)
from core.retry import retry_with_backoff


# -------------------------------- helpers -------------------------------- #

def _extract_writer_ec2(
    args: Tuple[Any, ...],
    kwargs: Dict[str, Any],
) -> Tuple[Any, Any]:
    """Accept writer/ec2 (positional or keyword)."""
    writer = kwargs.get("writer", args[0] if len(args) >= 1 else None)
    ec2 = kwargs.get("ec2", args[1] if len(args) >= 2 else None)
    if writer is None or ec2 is None:
        raise TypeError(
            "Expected 'writer' and 'ec2' (got writer=%r, ec2=%r)" % (writer, ec2)
        )
    return writer, ec2


def _price_dsu_hr() -> float:
    return float(config.safe_price("EBS_FSR", "DSU_HR", 0.75))


def _chunk(lst: List[str], n: int) -> List[List[str]]:
    return [lst[i:i + n] for i in range(0, len(lst), n)]


# ------------------------ 1) FSR-enabled snapshots ----------------------- #

@retry_with_backoff(exceptions=(ClientError,))
def check_ebs_fsr_enabled_snapshots(  # pylint: disable=unused-argument
    *args,
    logger: Optional[logging.Logger] = None,
    lookback_days: int = 30,
    **kwargs,
) -> None:
    """
    Flag snapshots with FSR enabled and estimate monthly DSU-hour cost.

    Also reports whether any volumes were created via FSR in the lookback window
    (fast-restored volumes), to spot unused/forgotten FSR enablement.
    """
    log = _logger(kwargs.get("logger") or logger)

    try:
        writer, ec2 = _extract_writer_ec2(args, kwargs)
    except TypeError as exc:
        log.warning("[check_ebs_fsr_enabled_snapshots] Skipping: %s", exc)
        return
    if not (config.ACCOUNT_ID and config.WRITE_ROW and config.GET_PRICE):
        log.warning("[check_ebs_fsr_enabled_snapshots] Skipping: checker config not provided.")
        return

    region = getattr(getattr(ec2, "meta", None), "region_name", "") or ""
    now_utc = datetime.now(timezone.utc).replace(microsecond=0)
    start = now_utc - timedelta(days=int(lookback_days))
    dsu_hr = _price_dsu_hr()

    # 1) Gather FSR state per snapshot+AZ, then aggregate by snapshot.
    fsr_items: List[Dict[str, Any]] = []
    try:
        p = ec2.get_paginator("describe_fast_snapshot_restores")
        for page in p.paginate():
            fsr_items.extend(page.get("FastSnapshotRestores", []) or
                             page.get("fastSnapshotRestoreSet", []) or [])
    except ClientError as exc:
        log.error("[fsr] describe_fast_snapshot_restores failed: %s", exc)
        return

    if not fsr_items:
        return

    per_snap: Dict[str, Dict[str, Any]] = {}
    for it in fsr_items:
        sid = it.get("SnapshotId") or it.get("SnapshotID") or ""
        az = it.get("AvailabilityZone") or ""
        state = (it.get("State") or "").lower()
        owner = it.get("OwnerId") or it.get("OwnerID")
        if not sid or not az:
            continue
        info = per_snap.setdefault(
            sid, {"owner": owner, "states": {}, "azs": set(), "enabled_azs": set()}
        )
        info["azs"].add(az)
        info["states"][state] = int(info["states"].get(state, 0)) + 1
        if state == "enabled":
            info["enabled_azs"].add(az)

    # 2) Describe snapshots (age / name) — best-effort.
    snaps_detail: Dict[str, Dict[str, Any]] = {}
    try:
        ids = list(per_snap.keys())
        for chunk_ids in _chunk(ids, 200):
            try:
                resp = ec2.describe_snapshots(SnapshotIds=chunk_ids)
                for s in resp.get("Snapshots", []) or []:
                    snaps_detail[s.get("SnapshotId")] = s
            except ClientError as exc:
                log.debug("[fsr] describe_snapshots chunk failed: %s", exc)
    except Exception as exc:  # pylint: disable=broad-except
        log.debug("[fsr] describe_snapshots summary failed: %s", exc)

    # 3) Collect fast-restored volume usage once, group by snapshot.
    fr_vols_by_snap: Dict[str, int] = {}
    try:
        p = ec2.get_paginator("describe_volumes")
        for page in p.paginate(
            Filters=[
                {"Name": "fast-restored", "Values": ["true"]},
            ]
        ):
            for v in page.get("Volumes", []) or []:
                ctime = v.get("CreateTime")
                if not isinstance(ctime, datetime):
                    continue
                ctime = ctime if ctime.tzinfo else ctime.replace(tzinfo=timezone.utc)
                if ctime < start:
                    continue
                sid = v.get("SnapshotId")
                if sid:
                    fr_vols_by_snap[sid] = int(fr_vols_by_snap.get(sid, 0)) + 1
    except ClientError as exc:
        # Not fatal; proceed without usage info.
        log.debug("[fsr] describe_volumes fast-restored failed: %s", exc)

    # 4) Emit rows per snapshot with enabled AZs.
    for sid, info in per_snap.items():
        az_count = len(info["enabled_azs"])
        if az_count <= 0:
            continue  # only cost when state is 'enabled'

        det = snaps_detail.get(sid, {})
        name = next(
            (t.get("Value") for t in det.get("Tags", []) or [] if t.get("Key") == "Name"),
            sid,
        )
        start_time = det.get("StartTime")
        age_days = None
        if isinstance(start_time, datetime):
            st = start_time if start_time.tzinfo else start_time.replace(tzinfo=timezone.utc)
            age_days = max(0, int((now_utc - st).total_seconds() // 86400))

        used_count = int(fr_vols_by_snap.get(sid, 0))
        flags: List[str] = ["EBSFSREnabled"]
        if used_count == 0:
            flags.append("EBSFSRNoRecentUse")

        est = const.HOURS_PER_MONTH * dsu_hr * az_count
        potential = est

        signals = _signals_str(
            {
                "Region": region,
                "SnapshotId": sid,
                "OwnerId": info.get("owner"),
                "EnabledAZs": az_count,
                "States": ",".join(f"{k}:{v}" for k, v in info.get("states", {}).items()),
                "SnapshotStart": _to_utc_iso(start_time) if isinstance(start_time, datetime) else "",
                "SnapshotAgeDays": age_days if age_days is not None else "",
                "FastRestoredVolsInWindow": used_count,
                "LookbackDays": lookback_days,
                "DSU_HR": dsu_hr,
            }
        )

        try:
            # type: ignore[call-arg]
            config.WRITE_ROW(
                writer=writer,
                resource_id=sid,
                name=str(name),
                owner_id=config.ACCOUNT_ID,  # type: ignore[arg-type]
                resource_type="EBSFastSnapshotRestore",
                estimated_cost=est,
                potential_saving=potential,
                flags=flags,
                confidence=100,
                signals=signals,
            )
        except Exception as exc:  # pylint: disable=broad-except
            log.warning("[fsr] write_row snapshot %s: %s", sid, exc)

        log.info("[fsr] Wrote FSR snapshot: %s (AZs=%s, used=%s)", sid, az_count, used_count)
