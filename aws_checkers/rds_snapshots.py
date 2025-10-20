"""Checkers: Amazon RDS – Snapshots (DB & Cluster/Aurora).

Checks included:

  - check_rds_manual_snapshots_old
      Manual snapshots older than N days. Estimates monthly snapshot storage cost.

  - check_rds_snapshots_public_or_shared
      Manual snapshots that are public or shared outside the account.

  - check_rds_snapshots_unencrypted
      Snapshots without encryption (hygiene).

  - check_rds_snapshots_orphaned
      Snapshots whose source instance/cluster no longer exists.

Design:
  - Dependencies via finops_toolset.checkers.config.setup(...).
  - Tolerant signatures (accept positional/keyword) and graceful skips.
  - UTC datetimes; pylint-friendly; lines ≤ 100 chars.
  - Pricing key used: config.safe_price("RDS", "SNAPSHOT_GB_MONTH", default=0.095).
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple

from botocore.exceptions import ClientError

from aws_checkers import config
from aws_checkers.common import (
    _logger,
    _signals_str,
    _to_utc_iso,
)
from core.retry import retry_with_backoff


# --------------------------------- helpers -------------------------------- #

def _extract_writer_rds(
    args: Tuple[Any, ...],
    kwargs: Dict[str, Any],
) -> Tuple[Any, Any]:
    """Accept writer/rds (positional or keyword)."""
    writer = kwargs.get("writer", args[0] if len(args) >= 1 else None)
    rds = kwargs.get("rds", args[1] if len(args) >= 2 else None)
    if writer is None or rds is None:
        raise TypeError(
            "Expected 'writer' and 'rds' "
            f"(got writer={writer!r}, rds={rds!r})"
        )
    return writer, rds


def _list_db_snapshots(rds, log: logging.Logger) -> List[Dict[str, Any]]:
    """Return all DB snapshots owned by the account (manual + automated)."""
    out: List[Dict[str, Any]] = []
    try:
        paginator = rds.get_paginator("describe_db_snapshots")
        for page in paginator.paginate(IncludePublic=False, IncludeShared=False):
            out.extend(page.get("DBSnapshots", []) or [])
    except ClientError as exc:
        log.error("[rds] describe_db_snapshots failed: %s", exc)
    return out


def _list_db_cluster_snapshots(rds, log: logging.Logger) -> List[Dict[str, Any]]:
    """Return all DB cluster snapshots owned by the account (manual + automated)."""
    out: List[Dict[str, Any]] = []
    try:
        paginator = rds.get_paginator("describe_db_cluster_snapshots")
        for page in paginator.paginate(IncludePublic=False, IncludeShared=False):
            out.extend(page.get("DBClusterSnapshots", []) or [])
    except ClientError as exc:
        log.error("[rds] describe_db_cluster_snapshots failed: %s", exc)
    return out


def _db_snapshot_size_gb(s: Dict[str, Any]) -> float:
    """DB snapshot size (GiB) if available."""
    # For instance snapshots, AllocatedStorage is present (GB).
    try:
        return float(s.get("AllocatedStorage") or 0.0)
    except Exception:  # pylint: disable=broad-except
        return 0.0


def _cluster_snapshot_size_gb(s: Dict[str, Any]) -> float:
    """DB cluster snapshot size estimate (Aurora often lacks explicit size)."""
    # Aurora doesn't expose an explicit size in the snapshot object;
    # return 0.0 (best-effort) — signals will indicate 'SizeGiB_Est=0'.
    try:
        return float(s.get("AllocatedStorage") or 0.0)
    except Exception:  # pylint: disable=broad-except
        return 0.0


def _snapshot_monthly_price_per_gb() -> float:
    return float(config.safe_price("RDS", "SNAPSHOT_GB_MONTH", 0.095))


def _owner_id_str() -> str:
    return str(config.ACCOUNT_ID) if config.ACCOUNT_ID is not None else ""


# ----------------------- 1) Old manual snapshots ------------------------- #

@retry_with_backoff(exceptions=(ClientError,))
def check_rds_manual_snapshots_old(  # pylint: disable=unused-argument
    *args,
    logger: Optional[logging.Logger] = None,
    stale_days: int = 30,
    **kwargs,
) -> None:
    """Flag manual DB and cluster snapshots older than 'stale_days'."""
    log = _logger(kwargs.get("logger") or logger)

    try:
        writer, rds = _extract_writer_rds(args, kwargs)
    except TypeError as exc:
        log.warning("[check_rds_manual_snapshots_old] Skipping: %s", exc)
        return
    if not (config.ACCOUNT_ID and config.WRITE_ROW and config.GET_PRICE):
        log.warning("[check_rds_manual_snapshots_old] Skipping: checker config not provided.")
        return

    region = getattr(getattr(rds, "meta", None), "region_name", "") or ""
    cutoff = (datetime.now(timezone.utc) - timedelta(days=int(stale_days))).replace(
        microsecond=0
    )
    price_gb = _snapshot_monthly_price_per_gb()

    # DB snapshots (instances)
    for s in _list_db_snapshots(rds, log):
        if (s.get("SnapshotType") or "").lower() != "manual":
            continue
        sid = s.get("DBSnapshotIdentifier") or ""
        created = s.get("SnapshotCreateTime")
        if not isinstance(created, datetime):
            continue
        c_utc = created if created.tzinfo else created.replace(tzinfo=timezone.utc)
        if c_utc >= cutoff:
            continue

        size_gb = _db_snapshot_size_gb(s)
        est = size_gb * price_gb
        potential = est

        enc = bool(s.get("Encrypted"))
        src = s.get("DBInstanceIdentifier") or ""
        eng = s.get("Engine") or ""

        try:
            # type: ignore[call-arg]
            config.WRITE_ROW(
                writer=writer,
                resource_id=sid,
                name=sid,
                owner_id=config.ACCOUNT_ID,  # type: ignore[arg-type]
                resource_type="RDSSnapshot",
                estimated_cost=est,
                potential_saving=potential,
                flags=["RDSSnapshotOld"],
                confidence=100,
                signals=_signals_str(
                    {
                        "Region": region,
                        "SnapshotId": sid,
                        "Engine": eng,
                        "Encrypted": enc,
                        "SourceInstance": src,
                        "SizeGiB": int(size_gb),
                        "CreatedAt": _to_utc_iso(c_utc),
                        "StaleDays": stale_days,
                    }
                ),
            )
        except Exception as exc:  # pylint: disable=broad-except
            log.warning("[check_rds_manual_snapshots_old] write_row %s: %s", sid, exc)

        log.info("[rds] Wrote old manual DB snapshot: %s", sid)

    # DB cluster snapshots (Aurora)
    for s in _list_db_cluster_snapshots(rds, log):
        if (s.get("SnapshotType") or "").lower() != "manual":
            continue
        sid = s.get("DBClusterSnapshotIdentifier") or ""
        created = s.get("SnapshotCreateTime")
        if not isinstance(created, datetime):
            continue
        c_utc = created if created.tzinfo else created.replace(tzinfo=timezone.utc)
        if c_utc >= cutoff:
            continue

        size_gb = _cluster_snapshot_size_gb(s)  # often 0 for Aurora (unknown)
        est = size_gb * price_gb
        potential = est

        enc = bool(s.get("StorageEncrypted"))
        src = s.get("DBClusterIdentifier") or ""
        eng = s.get("Engine") or ""

        try:
            # type: ignore[call-arg]
            config.WRITE_ROW(
                writer=writer,
                resource_id=sid,
                name=sid,
                owner_id=config.ACCOUNT_ID,  # type: ignore[arg-type]
                resource_type="RDSClusterSnapshot",
                estimated_cost=est,
                potential_saving=potential,
                flags=["RDSClusterSnapshotOld"],
                confidence=100,
                signals=_signals_str(
                    {
                        "Region": region,
                        "SnapshotId": sid,
                        "Engine": eng,
                        "Encrypted": enc,
                        "SourceCluster": src,
                        "SizeGiB_Est": int(size_gb),
                        "CreatedAt": _to_utc_iso(c_utc),
                        "StaleDays": stale_days,
                    }
                ),
            )
        except Exception as exc:  # pylint: disable=broad-except
            log.warning("[check_rds_manual_snapshots_old] write_row cluster %s: %s", sid, exc)

        log.info("[rds] Wrote old manual DB cluster snapshot: %s", sid)


# --------------- 2) Public or shared outside the account ----------------- #

@retry_with_backoff(exceptions=(ClientError,))
def check_rds_snapshots_public_or_shared(  # pylint: disable=unused-argument
    *args,
    logger: Optional[logging.Logger] = None,
    **kwargs,
) -> None:
    """Flag manual snapshots that are public or shared outside the account."""
    log = _logger(kwargs.get("logger") or logger)

    try:
        writer, rds = _extract_writer_rds(args, kwargs)
    except TypeError as exc:
        log.warning("[check_rds_snapshots_public_or_shared] Skipping: %s", exc)
        return
    if not (config.ACCOUNT_ID and config.WRITE_ROW):
        log.warning("[check_rds_snapshots_public_or_shared] Skipping: checker config not provided.")
        return

    region = getattr(getattr(rds, "meta", None), "region_name", "") or ""
    acct = _owner_id_str()

    # DB snapshots
    for s in _list_db_snapshots(rds, log):
        if (s.get("SnapshotType") or "").lower() != "manual":
            continue
        sid = s.get("DBSnapshotIdentifier") or ""
        if not sid:
            continue

        try:
            attrs = rds.describe_db_snapshot_attributes(
                DBSnapshotIdentifier=sid
            ).get("DBSnapshotAttributesResult", {})
            shared_accts: List[str] = []
            is_public = False
            for a in attrs.get("DBSnapshotAttributes", []) or []:
                if a.get("AttributeName") != "restore":
                    continue
                vals = [str(v) for v in (a.get("AttributeValues") or [])]
                is_public = "all" in {v.lower() for v in vals}
                shared_accts = [v for v in vals if v != acct and v.lower() != "all"]
            flags: List[str] = []
            if is_public:
                flags.append("RDSSnapshotPublic")
            if shared_accts:
                flags.append("RDSSnapshotSharedOutsideAccount")
            if not flags:
                continue

            enc = bool(s.get("Encrypted"))
            src = s.get("DBInstanceIdentifier") or ""
            eng = s.get("Engine") or ""

            try:
                # type: ignore[call-arg]
                config.WRITE_ROW(
                    writer=writer,
                    resource_id=sid,
                    name=sid,
                    owner_id=config.ACCOUNT_ID,  # type: ignore[arg-type]
                    resource_type="RDSSnapshot",
                    estimated_cost=0.0,
                    potential_saving=0.0,
                    flags=flags,
                    confidence=100,
                    signals=_signals_str(
                        {
                            "Region": region,
                            "SnapshotId": sid,
                            "Engine": eng,
                            "Encrypted": enc,
                            "SourceInstance": src,
                            "SharedWith": ",".join(shared_accts),
                        }
                    ),
                )
            except Exception as exc:  # pylint: disable=broad-except
                log.warning("[rds] write_row snapshot %s: %s", sid, exc)

            log.info("[rds] Wrote snapshot sharing issue: %s (%s)", sid, ",".join(flags))
        except ClientError as exc:
            log.debug("[rds] describe_db_snapshot_attributes %s failed: %s", sid, exc)

    # DB cluster snapshots
    for s in _list_db_cluster_snapshots(rds, log):
        if (s.get("SnapshotType") or "").lower() != "manual":
            continue
        sid = s.get("DBClusterSnapshotIdentifier") or ""
        if not sid:
            continue

        try:
            attrs = rds.describe_db_cluster_snapshot_attributes(
                DBClusterSnapshotIdentifier=sid
            ).get("DBClusterSnapshotAttributesResult", {})
            shared_accts: List[str] = []
            is_public = False
            for a in attrs.get("DBClusterSnapshotAttributes", []) or []:
                if a.get("AttributeName") != "restore":
                    continue
                vals = [str(v) for v in (a.get("AttributeValues") or [])]
                is_public = "all" in {v.lower() for v in vals}
                shared_accts = [v for v in vals if v != acct and v.lower() != "all"]
            flags: List[str] = []
            if is_public:
                flags.append("RDSClusterSnapshotPublic")
            if shared_accts:
                flags.append("RDSClusterSnapshotSharedOutsideAccount")
            if not flags:
                continue

            enc = bool(s.get("StorageEncrypted"))
            src = s.get("DBClusterIdentifier") or ""
            eng = s.get("Engine") or ""

            try:
                # type: ignore[call-arg]
                config.WRITE_ROW(
                    writer=writer,
                    resource_id=sid,
                    name=sid,
                    owner_id=config.ACCOUNT_ID,  # type: ignore[arg-type]
                    resource_type="RDSClusterSnapshot",
                    estimated_cost=0.0,
                    potential_saving=0.0,
                    flags=flags,
                    confidence=100,
                    signals=_signals_str(
                        {
                            "Region": region,
                            "SnapshotId": sid,
                            "Engine": eng,
                            "Encrypted": enc,
                            "SourceCluster": src,
                            "SharedWith": ",".join(shared_accts),
                        }
                    ),
                )
            except Exception as exc:  # pylint: disable=broad-except
                log.warning("[rds] write_row cluster snapshot %s: %s", sid, exc)

            log.info("[rds] Wrote cluster snapshot sharing issue: %s (%s)", sid, ",".join(flags))
        except ClientError as exc:
            log.debug("[rds] describe_db_cluster_snapshot_attributes %s failed: %s", sid, exc)


# --------------------------- 3) Unencrypted ------------------------------ #

@retry_with_backoff(exceptions=(ClientError,))
def check_rds_snapshots_unencrypted(  # pylint: disable=unused-argument
    *args,
    logger: Optional[logging.Logger] = None,
    **kwargs,
) -> None:
    """Flag DB & cluster snapshots that are not encrypted."""
    log = _logger(kwargs.get("logger") or logger)

    try:
        writer, rds = _extract_writer_rds(args, kwargs)
    except TypeError as exc:
        log.warning("[check_rds_snapshots_unencrypted] Skipping: %s", exc)
        return
    if not (config.ACCOUNT_ID and config.WRITE_ROW):
        log.warning("[check_rds_snapshots_unencrypted] Skipping: checker config not provided.")
        return

    region = getattr(getattr(rds, "meta", None), "region_name", "") or ""

    for s in _list_db_snapshots(rds, log):
        sid = s.get("DBSnapshotIdentifier") or ""
        if not sid:
            continue
        if bool(s.get("Encrypted")):
            continue

        src = s.get("DBInstanceIdentifier") or ""
        eng = s.get("Engine") or ""

        try:
            # type: ignore[call-arg]
            config.WRITE_ROW(
                writer=writer,
                resource_id=sid,
                name=sid,
                owner_id=config.ACCOUNT_ID,  # type: ignore[arg-type]
                resource_type="RDSSnapshot",
                estimated_cost=0.0,
                potential_saving=0.0,
                flags=["RDSSnapshotUnencrypted"],
                confidence=100,
                signals=_signals_str(
                    {"Region": region, "SnapshotId": sid, "Engine": eng, "SourceInstance": src}
                ),
            )
        except Exception as exc:  # pylint: disable=broad-except
            log.warning("[rds] write_row snapshot %s: %s", sid, exc)

        log.info("[rds] Wrote unencrypted snapshot: %s", sid)

    for s in _list_db_cluster_snapshots(rds, log):
        sid = s.get("DBClusterSnapshotIdentifier") or ""
        if not sid:
            continue
        if bool(s.get("StorageEncrypted")):
            continue

        src = s.get("DBClusterIdentifier") or ""
        eng = s.get("Engine") or ""

        try:
            # type: ignore[call-arg]
            config.WRITE_ROW(
                writer=writer,
                resource_id=sid,
                name=sid,
                owner_id=config.ACCOUNT_ID,  # type: ignore[arg-type]
                resource_type="RDSClusterSnapshot",
                estimated_cost=0.0,
                potential_saving=0.0,
                flags=["RDSClusterSnapshotUnencrypted"],
                confidence=100,
                signals=_signals_str(
                    {"Region": region, "SnapshotId": sid, "Engine": eng, "SourceCluster": src}
                ),
            )
        except Exception as exc:  # pylint: disable=broad-except
            log.warning("[rds] write_row cluster snapshot %s: %s", sid, exc)

        log.info("[rds] Wrote unencrypted cluster snapshot: %s", sid)


# ----------------------------- 4) Orphaned ------------------------------- #

@retry_with_backoff(exceptions=(ClientError,))
def check_rds_snapshots_orphaned(  # pylint: disable=unused-argument
    *args,
    logger: Optional[logging.Logger] = None,
    **kwargs,
) -> None:
    """
    Flag snapshots whose source instance/cluster no longer exists.

    Note: This does not imply the snapshot is invalid; it highlights cleanup candidates.
    """
    log = _logger(kwargs.get("logger") or logger)

    try:
        writer, rds = _extract_writer_rds(args, kwargs)
    except TypeError as exc:
        log.warning("[check_rds_snapshots_orphaned] Skipping: %s", exc)
        return
    if not (config.ACCOUNT_ID and config.WRITE_ROW):
        log.warning("[check_rds_snapshots_orphaned] Skipping: checker config not provided.")
        return

    region = getattr(getattr(rds, "meta", None), "region_name", "") or ""

    # Build sets of existing sources
    instances: set = set()
    clusters: set = set()
    try:
        p = rds.get_paginator("describe_db_instances")
        for page in p.paginate():
            for i in page.get("DBInstances", []) or []:
                iid = i.get("DBInstanceIdentifier")
                if iid:
                    instances.add(iid)
    except ClientError as exc:
        log.debug("[rds] describe_db_instances failed: %s", exc)

    try:
        p = rds.get_paginator("describe_db_clusters")
        for page in p.paginate():
            for c in page.get("DBClusters", []) or []:
                cid = c.get("DBClusterIdentifier")
                if cid:
                    clusters.add(cid)
    except ClientError as exc:
        log.debug("[rds] describe_db_clusters failed: %s", exc)

    # DB snapshots
    for s in _list_db_snapshots(rds, log):
        sid = s.get("DBSnapshotIdentifier") or ""
        if not sid:
            continue
        src = s.get("DBInstanceIdentifier") or ""
        if not src or src in instances:
            continue

        eng = s.get("Engine") or ""
        enc = bool(s.get("Encrypted"))

        try:
            # type: ignore[call-arg]
            config.WRITE_ROW(
                writer=writer,
                resource_id=sid,
                name=sid,
                owner_id=config.ACCOUNT_ID,  # type: ignore[arg-type]
                resource_type="RDSSnapshot",
                estimated_cost=0.0,
                potential_saving=0.0,
                flags=["RDSSnapshotOrphaned"],
                confidence=100,
                signals=_signals_str(
                    {
                        "Region": region,
                        "SnapshotId": sid,
                        "Engine": eng,
                        "Encrypted": enc,
                        "SourceInstance": src,
                    }
                ),
            )
        except Exception as exc:  # pylint: disable=broad-except
            log.warning("[rds] write_row orphaned snapshot %s: %s", sid, exc)

        log.info("[rds] Wrote orphaned snapshot: %s", sid)

    # DB cluster snapshots
    for s in _list_db_cluster_snapshots(rds, log):
        sid = s.get("DBClusterSnapshotIdentifier") or ""
        if not sid:
            continue
        src = s.get("DBClusterIdentifier") or ""
        if not src or src in clusters:
            continue

        eng = s.get("Engine") or ""
        enc = bool(s.get("StorageEncrypted"))

        try:
            # type: ignore[call-arg]
            config.WRITE_ROW(
                writer=writer,
                resource_id=sid,
                name=sid,
                owner_id=config.ACCOUNT_ID,  # type: ignore[arg-type]
                resource_type="RDSClusterSnapshot",
                estimated_cost=0.0,
                potential_saving=0.0,
                flags=["RDSClusterSnapshotOrphaned"],
                confidence=100,
                signals=_signals_str(
                    {
                        "Region": region,
                        "SnapshotId": sid,
                        "Engine": eng,
                        "Encrypted": enc,
                        "SourceCluster": src,
                    }
                ),
            )
        except Exception as exc:  # pylint: disable=broad-except
            log.warning("[rds] write_row orphaned cluster snapshot %s: %s", sid, exc)

        log.info("[rds] Wrote orphaned cluster snapshot: %s", sid)
