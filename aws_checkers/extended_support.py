"""Checkers: Extended Support (RDS engines & EKS clusters).

Scope:
  - RDS / Aurora engines on versions commonly covered by Extended Support:
      * MySQL 5.7 (RDS)            -> label "MySQL57"
      * PostgreSQL 11 (RDS)        -> label "PostgreSQL11"
      * Aurora MySQL 5.7 compat    -> label "AuroraMySQL57" (aurora-mysql 2.x / 5.7.*)
      * Aurora PostgreSQL 11       -> label "AuroraPostgreSQL11"
    Costs are modeled via pricebook keys under "RDS_EXT", per *instance hour*.
    For Aurora clusters we multiply by member count.

  - EKS clusters on Kubernetes versions you treat as in Extended Support.
    Versions are matched on "<major.minor>" strings. Default set is {"1.23","1.24"}.
    Costs are modeled via pricebook key "EKS_EXT" → "CLUSTER_HR".

Design:
  - Dependencies via finops_toolset.checkers.config.setup(...).
  - Tolerant signatures; graceful skips; no return values.
  - UTC datetimes; pylint-friendly; lines ≤ 100 chars.
  - No external calls or embedded pricing — everything is driven by config.safe_price.

Pricebook keys used (safe defaults if absent):
  "RDS_EXT": {
      "MySQL57_INSTANCE_HR": 0.0,
      "PostgreSQL11_INSTANCE_HR": 0.0,
      "AuroraMySQL57_INSTANCE_HR": 0.0,
      "AuroraPostgreSQL11_INSTANCE_HR": 0.0
  },
  "EKS_EXT": {
      "CLUSTER_HR": 0.0
  }
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from botocore.exceptions import ClientError

from aws_checkers import config
from core.retry import retry_with_backoff


# -------------------------------- helpers -------------------------------- #

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


def _extract_writer_rds(
    args: Tuple[Any, ...],
    kwargs: Dict[str, Any],
) -> Tuple[Any, Any]:
    """Accept writer/rds (positional or keyword)."""
    writer = kwargs.get("writer", args[0] if len(args) >= 1 else None)
    rds = kwargs.get("rds", args[1] if len(args) >= 2 else None)
    if writer is None or rds is None:
        raise TypeError(
            "Expected 'writer' and 'rds' (got writer=%r, rds=%r)" % (writer, rds)
        )
    return writer, rds


def _extract_writer_eks(
    args: Tuple[Any, ...],
    kwargs: Dict[str, Any],
) -> Tuple[Any, Any]:
    """Accept writer/eks (positional or keyword)."""
    writer = kwargs.get("writer", args[0] if len(args) >= 1 else None)
    eks = kwargs.get("eks", args[1] if len(args) >= 2 else None)
    if writer is None or eks is None:
        raise TypeError(
            "Expected 'writer' and 'eks' (got writer=%r, eks=%r)" % (writer, eks)
        )
    return writer, eks


def _price_rds_ext(label: str) -> float:
    key = f"{label}_INSTANCE_HR"
    return float(config.safe_price("RDS_EXT", key, 0.0))


def _price_eks_ext_cluster_hr() -> float:
    return float(config.safe_price("EKS_EXT", "CLUSTER_HR", 0.0))


def _version_major_minor(version: Optional[str]) -> Optional[str]:
    v = (version or "").strip()
    if not v:
        return None
    parts = v.split(".")
    if len(parts) >= 2 and parts[0].isdigit() and parts[1].isdigit():
        return f"{int(parts[0])}.{int(parts[1])}"
    # Aurora versions can be like "5.7.mysql_aurora.2.12.3" → detect "5.7"
    if v.startswith("5.7"):
        return "5.7"
    if v.startswith("11."):
        return "11.0"
    return None


def _rds_ext_label(engine: str, version: str) -> Optional[str]:
    """Return Extended Support label if engine/version match, else None."""
    e = (engine or "").lower()
    mm = _version_major_minor(version or "")
    if not mm:
        return None

    if e.startswith("mysql") and mm == "5.7":
        return "MySQL57"
    if e.startswith("postgres") and mm.startswith("11"):
        return "PostgreSQL11"

    if e.startswith("aurora-mysql"):
        # Aurora MySQL 2.x is MySQL 5.7 compatible; version often contains "5.7"
        if "5.7" in (version or "") or ".aurora.2" in (version or ""):
            return "AuroraMySQL57"
    if e.startswith("aurora-postgresql") and mm.startswith("11"):
        return "AuroraPostgreSQL11"

    return None


def _owner_id_str() -> str:
    return str(config.ACCOUNT_ID) if config.ACCOUNT_ID is not None else ""


# ---------------------- RDS: Extended Support candidates ----------------- #

@retry_with_backoff(exceptions=(ClientError,))
def check_rds_extended_support_candidates(  # pylint: disable=unused-argument
    *args,
    logger: Optional[logging.Logger] = None,
    **kwargs,
) -> None:
    """
    Flag RDS instances and Aurora clusters on versions commonly in Extended Support.

    Cost model:
      - Per-instance hour price from pricebook:
            price("RDS_EXT", "<Label>_INSTANCE_HR")
      - Aurora clusters: multiply by member count (instances in the cluster).
    """
    log = _logger(kwargs.get("logger") or logger)

    try:
        writer, rds = _extract_writer_rds(args, kwargs)
    except TypeError as exc:
        log.warning("[check_rds_extended_support_candidates] Skipping: %s", exc)
        return
    if not (config.ACCOUNT_ID and config.WRITE_ROW):
        log.warning(
            "[check_rds_extended_support_candidates] Skipping: checker config not provided."
        )
        return

    region = getattr(getattr(rds, "meta", None), "region_name", "") or ""

    # Instances (non-Aurora)
    try:
        p = rds.get_paginator("describe_db_instances")
        for page in p.paginate():
            for inst in page.get("DBInstances", []) or []:
                iid = inst.get("DBInstanceIdentifier") or ""
                eng = inst.get("Engine") or ""
                ver = str(inst.get("EngineVersion") or "")
                cls = inst.get("DBInstanceClass") or ""
                label = _rds_ext_label(eng, ver)
                if not iid or not label:
                    continue

                hr = _price_rds_ext(label)
                est = 730.0 * hr
                potential = est

                name = next(
                    (t.get("Value") for t in inst.get("TagList", []) or []
                     if t.get("Key") == "Name"),
                    iid,
                )

                try:
                    # type: ignore[call-arg]
                    config.WRITE_ROW(
                        writer=writer,
                        resource_id=iid,
                        name=name,
                        owner_id=config.ACCOUNT_ID,  # type: ignore[arg-type]
                        resource_type="RDSInstance",
                        estimated_cost=est,
                        potential_saving=potential,
                        flags=["RDSExtendedSupport"],
                        confidence=100,
                        signals=_signals_str(
                            {
                                "Region": region,
                                "InstanceId": iid,
                                "Class": cls,
                                "Engine": eng,
                                "Version": ver,
                                "Label": label,
                                "HrPrice_Ext": hr,
                            }
                        ),
                    )
                except Exception as exc:  # pylint: disable=broad-except
                    log.warning("[rds] write_row ext support %s: %s", iid, exc)

                log.info("[rds] Extended Support candidate: %s (%s %s)", iid, eng, ver)
    except ClientError as exc:
        log.error("[rds] describe_db_instances failed: %s", exc)

    # Aurora clusters
    try:
        p = rds.get_paginator("describe_db_clusters")
        for page in p.paginate():
            for cl in page.get("DBClusters", []) or []:
                cid = cl.get("DBClusterIdentifier") or ""
                eng = cl.get("Engine") or ""
                ver = str(cl.get("EngineVersion") or "")
                label = _rds_ext_label(eng, ver)
                if not cid or not label:
                    continue

                members = len(cl.get("DBClusterMembers", []) or [])
                hr = _price_rds_ext(label)
                est = 730.0 * hr * max(1, members)
                potential = est

                name = next(
                    (t.get("Value") for t in cl.get("TagList", []) or []
                     if t.get("Key") == "Name"),
                    cid,
                )

                try:
                    # type: ignore[call-arg]
                    config.WRITE_ROW(
                        writer=writer,
                        resource_id=cid,
                        name=name,
                        owner_id=config.ACCOUNT_ID,  # type: ignore[arg-type]
                        resource_type="RDSCluster",
                        estimated_cost=est,
                        potential_saving=potential,
                        flags=["RDSAuroraExtendedSupport"],
                        confidence=100,
                        signals=_signals_str(
                            {
                                "Region": region,
                                "ClusterId": cid,
                                "Members": members,
                                "Engine": eng,
                                "Version": ver,
                                "Label": label,
                                "HrPrice_Ext": hr,
                            }
                        ),
                    )
                except Exception as exc:  # pylint: disable=broad-except
                    log.warning("[rds] write_row aurora ext support %s: %s", cid, exc)

                log.info("[rds] Aurora Extended Support candidate: %s (%s %s)", cid, eng, ver)
    except ClientError as exc:
        log.error("[rds] describe_db_clusters failed: %s", exc)


# ------------------------- EKS: Extended Support ------------------------- #

@retry_with_backoff(exceptions=(ClientError,))
def check_eks_extended_support_clusters(  # pylint: disable=unused-argument
    *args,
    logger: Optional[logging.Logger] = None,
    ext_versions: Optional[List[str]] = None,
    **kwargs,
) -> None:
    """
    Flag EKS clusters whose Kubernetes version is in your Extended Support set.

    Args:
      ext_versions: list like ["1.23","1.24"]. If None, defaults to {"1.23","1.24"}.

    Cost model:
      - Per-cluster hour price from pricebook: price("EKS_EXT", "CLUSTER_HR").
    """
    log = _logger(kwargs.get("logger") or logger)

    try:
        writer, eks = _extract_writer_eks(args, kwargs)
    except TypeError as exc:
        log.warning("[check_eks_extended_support_clusters] Skipping: %s", exc)
        return
    if not (config.ACCOUNT_ID and config.WRITE_ROW):
        log.warning(
            "[check_eks_extended_support_clusters] Skipping: checker config not provided."
        )
        return

    region = getattr(getattr(eks, "meta", None), "region_name", "") or ""
    ext_set = set(ext_versions or ["1.23", "1.24"])

    try:
        names: List[str] = []
        p = eks.get_paginator("list_clusters")
        for page in p.paginate():
            names.extend(page.get("clusters", []) or [])
    except ClientError as exc:
        log.error("[eks] list_clusters failed: %s", exc)
        return
    if not names:
        return

    hr = _price_eks_ext_cluster_hr()
    monthly = 730.0 * hr

    for name in names:
        try:
            desc = eks.describe_cluster(name=name).get("cluster", {}) or {}
        except ClientError as exc:
            log.debug("[eks] describe_cluster %s failed: %s", name, exc)
            continue

        ver = str(desc.get("version") or "")
        m = _version_major_minor(ver)
        if not m or m not in ext_set:
            continue

        arn = desc.get("arn") or name
        status = desc.get("status")
        plat = desc.get("platformVersion")

        try:
            # type: ignore[call-arg]
            config.WRITE_ROW(
                writer=writer,
                resource_id=arn,
                name=name,
                owner_id=config.ACCOUNT_ID,  # type: ignore[arg-type]
                resource_type="EKSCluster",
                estimated_cost=monthly,
                potential_saving=monthly,
                flags=["EKSExtendedSupport"],
                confidence=100,
                signals=_signals_str(
                    {
                        "Region": region,
                        "Cluster": name,
                        "Version": ver,
                        "VersionMM": m,
                        "Status": status,
                        "PlatformVersion": plat,
                        "HrPrice_Ext": hr,
                    }
                ),
            )
        except Exception as exc:  # pylint: disable=broad-except
            log.warning("[eks] write_row ext support %s: %s", name, exc)

        log.info("[eks] Extended Support cluster: %s (v%s)", name, ver)
