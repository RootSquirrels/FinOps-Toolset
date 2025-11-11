"""Checkers: Amazon EKS.

Checks included:

  - check_eks_empty_clusters
      Clusters with zero managed nodegroups and zero Fargate profiles.
      Estimates monthly cluster fee as potential saving.

  - check_eks_logging_incomplete
      Control plane logging not fully enabled (api/audit/authenticator).

  - check_eks_public_endpoint_open
      Public endpoint allowed from 0.0.0.0/0 (or no CIDR restrictions).

  - check_eks_nodegroups_scaled_to_zero
      Managed nodegroups (ACTIVE) scaled to desired=0 & min=0 for >= stale_days.

  - check_eks_addons_degraded
      Add-ons with Health.Status in {DEGRADED, UNHEALTHY} or with issues.

  - check_eks_old_versions
      Clusters on versions lower than min_version_mm (e.g. "1.27").

Design:
  - Dependencies via finops_toolset.checkers.config.setup(...).
  - Tolerant signatures; graceful skips; no return values.
  - UTC datetimes; pylint-friendly; lines ≤ 100 chars.

Pricing keys (safe defaults if absent):
  "EKS": { "CLUSTER_HR": 0.10 }
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


# ------------------------------- helpers --------------------------------- #

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


def _price_cluster_hr() -> float:
    return float(config.safe_price("EKS", "CLUSTER_HR", 0.10))


def _version_mm(version: Optional[str]) -> Optional[str]:
    v = (version or "").strip()
    if not v:
        return None
    parts = v.split(".")
    if len(parts) >= 2 and parts[0].isdigit() and parts[1].isdigit():
        return f"{int(parts[0])}.{int(parts[1])}"
    return None


def _cmp_mm(a: str, b: str) -> int:
    """Compare '1.27' style strings. Returns -1, 0, 1."""
    try:
        am, an = (int(x) for x in a.split(".", 1))
        bm, bn = (int(x) for x in b.split(".", 1))
    except Exception:  # pylint: disable=broad-except
        return 0
    if am != bm:
        return -1 if am < bm else 1
    if an != bn:
        return -1 if an < bn else 1
    return 0


def _list_clusters(eks, log: logging.Logger) -> List[str]:
    names: List[str] = []
    try:
        p = eks.get_paginator("list_clusters")
        for page in p.paginate():
            names.extend(page.get("clusters", []) or [])
    except ClientError as exc:
        log.error("[eks] list_clusters failed: %s", exc)
    return names


def _list_nodegroups(eks, cluster: str, log: logging.Logger) -> List[str]:
    ngs: List[str] = []
    try:
        p = eks.get_paginator("list_nodegroups")
        for page in p.paginate(clusterName=cluster):
            ngs.extend(page.get("nodegroups", []) or [])
    except ClientError as exc:
        log.debug("[eks] list_nodegroups(%s) failed: %s", cluster, exc)
    return ngs


def _list_fargate_profiles(eks, cluster: str, log: logging.Logger) -> List[str]:
    fps: List[str] = []
    try:
        p = eks.get_paginator("list_fargate_profiles")
        for page in p.paginate(clusterName=cluster):
            fps.extend(page.get("fargateProfileNames", []) or [])
    except ClientError as exc:
        log.debug("[eks] list_fargate_profiles(%s) failed: %s", cluster, exc)
    return fps


# -------------------------- 1) Empty clusters ---------------------------- #

@retry_with_backoff(exceptions=(ClientError,))
def check_eks_empty_clusters(  # pylint: disable=unused-argument
    *args,
    logger: Optional[logging.Logger] = None,
    **kwargs,
) -> None:
    """Flag EKS clusters with no nodegroups and no Fargate profiles."""
    log = _logger(kwargs.get("logger") or logger)

    try:
        writer, eks = _extract_writer_eks(args, kwargs)
    except TypeError as exc:
        log.warning("[check_eks_empty_clusters] Skipping: %s", exc)
        return
    if not (config.ACCOUNT_ID and config.WRITE_ROW and config.GET_PRICE):
        log.warning("[check_eks_empty_clusters] Skipping: checker config not provided.")
        return

    region = getattr(getattr(eks, "meta", None), "region_name", "") or ""
    names = _list_clusters(eks, log)
    if not names:
        return

    hr = _price_cluster_hr()
    monthly = const.HOURS_PER_MONTH * hr

    for name in names:
        try:
            desc = eks.describe_cluster(name=name).get("cluster", {}) or {}
        except ClientError as exc:
            log.debug("[eks] describe_cluster %s failed: %s", name, exc)
            continue

        ngs = _list_nodegroups(eks, name, log)
        fps = _list_fargate_profiles(eks, name, log)
        if ngs or fps:
            continue

        arn = desc.get("arn") or name
        status = desc.get("status")
        created = desc.get("createdAt")

        signals = _signals_str(
            {
                "Region": region,
                "Cluster": name,
                "Status": status,
                "NodeGroups": 0,
                "FargateProfiles": 0,
                "CreatedAt": _to_utc_iso(created) if isinstance(created, datetime) else None,
                "HrPrice": hr,
            }
        )

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
                flags=["EKSClusterEmpty"],
                confidence=100,
                signals=signals,
            )
        except Exception as exc:  # pylint: disable=broad-except
            log.warning("[eks] write_row empty cluster %s: %s", name, exc)

        log.info("[eks] Wrote empty cluster: %s", name)


# --------------------- 2) Logging incomplete (hygiene) ------------------- #

@retry_with_backoff(exceptions=(ClientError,))
def check_eks_logging_incomplete(  # pylint: disable=unused-argument
    *args,
    logger: Optional[logging.Logger] = None,
    required: Optional[List[str]] = None,
    **kwargs,
) -> None:
    """
    Flag clusters where control plane logging isn't fully enabled.

    Required types (default): ["api", "audit", "authenticator"].
    """
    log = _logger(kwargs.get("logger") or logger)

    try:
        writer, eks = _extract_writer_eks(args, kwargs)
    except TypeError as exc:
        log.warning("[check_eks_logging_incomplete] Skipping: %s", exc)
        return
    if not (config.ACCOUNT_ID and config.WRITE_ROW):
        log.warning("[check_eks_logging_incomplete] Skipping: checker config not provided.")
        return

    region = getattr(getattr(eks, "meta", None), "region_name", "") or ""
    required = required or ["api", "audit", "authenticator"]

    for name in _list_clusters(eks, log):
        try:
            desc = eks.describe_cluster(name=name).get("cluster", {}) or {}
        except ClientError as exc:
            log.debug("[eks] describe_cluster %s failed: %s", name, exc)
            continue

        arn = desc.get("arn") or name
        clog = (desc.get("logging") or {}).get("clusterLogging") or []
        enabled: set = set()
        for item in clog:
            if item.get("enabled"):
                for t in item.get("types", []) or []:
                    enabled.add(str(t).lower())

        missing = [t for t in required if t.lower() not in enabled]
        if not missing:
            continue

        try:
            # type: ignore[call-arg]
            config.WRITE_ROW(
                writer=writer,
                resource_id=arn,
                name=name,
                owner_id=config.ACCOUNT_ID,  # type: ignore[arg-type]
                resource_type="EKSCluster",
                estimated_cost=0.0,
                potential_saving=0.0,
                flags=["EKSClusterLoggingIncomplete"],
                confidence=100,
                signals=_signals_str(
                    {
                        "Region": region,
                        "Cluster": name,
                        "Enabled": ",".join(sorted(enabled)),
                        "Missing": ",".join(missing),
                    }
                ),
            )
        except Exception as exc:  # pylint: disable=broad-except
            log.warning("[eks] write_row logging incomplete %s: %s", name, exc)

        log.info("[eks] Wrote logging incomplete: %s (missing=%s)", name, ",".join(missing))


# ------------------- 3) Public endpoint wide-open (hygiene) -------------- #

@retry_with_backoff(exceptions=(ClientError,))
def check_eks_public_endpoint_open(  # pylint: disable=unused-argument
    *args,
    logger: Optional[logging.Logger] = None,
    **kwargs,
) -> None:
    """Flag clusters with public endpoint open to 0.0.0.0/0 (or no CIDR limit)."""
    log = _logger(kwargs.get("logger") or logger)

    try:
        writer, eks = _extract_writer_eks(args, kwargs)
    except TypeError as exc:
        log.warning("[check_eks_public_endpoint_open] Skipping: %s", exc)
        return
    if not (config.ACCOUNT_ID and config.WRITE_ROW):
        log.warning("[check_eks_public_endpoint_open] Skipping: checker config not provided.")
        return

    region = getattr(getattr(eks, "meta", None), "region_name", "") or ""
    for name in _list_clusters(eks, log):
        try:
            desc = eks.describe_cluster(name=name).get("cluster", {}) or {}
        except ClientError as exc:
            log.debug("[eks] describe_cluster %s failed: %s", name, exc)
            continue

        arn = desc.get("arn") or name
        vcfg = desc.get("resourcesVpcConfig") or {}
        public = bool(vcfg.get("endpointPublicAccess"))
        cidrs = [str(c) for c in (vcfg.get("publicAccessCidrs") or [])]

        open_all = not cidrs or "0.0.0.0/0" in {c.strip() for c in cidrs}
        if not (public and open_all):
            continue

        try:
            # type: ignore[call-arg]
            config.WRITE_ROW(
                writer=writer,
                resource_id=arn,
                name=name,
                owner_id=config.ACCOUNT_ID,  # type: ignore[arg-type]
                resource_type="EKSCluster",
                estimated_cost=0.0,
                potential_saving=0.0,
                flags=["EKSClusterPublicEndpointOpen"],
                confidence=100,
                signals=_signals_str(
                    {"Region": region, "Cluster": name, "PublicAccessCidrs": ",".join(cidrs)}
                ),
            )
        except Exception as exc:  # pylint: disable=broad-except
            log.warning("[eks] write_row public endpoint %s: %s", name, exc)

        log.info("[eks] Wrote public endpoint open: %s", name)


# ---------------- 4) Nodegroups scaled to zero (cleanup) ----------------- #

@retry_with_backoff(exceptions=(ClientError,))
def check_eks_nodegroups_scaled_to_zero(  # pylint: disable=unused-argument
    *args,
    logger: Optional[logging.Logger] = None,
    stale_days: int = 14,
    **kwargs,
) -> None:
    """Flag ACTIVE nodegroups at desired=0 & min=0 for >= stale_days."""
    log = _logger(kwargs.get("logger") or logger)

    try:
        writer, eks = _extract_writer_eks(args, kwargs)
    except TypeError as exc:
        log.warning("[check_eks_nodegroups_scaled_to_zero] Skipping: %s", exc)
        return
    if not (config.ACCOUNT_ID and config.WRITE_ROW):
        log.warning("[check_eks_nodegroups_scaled_to_zero] Skipping: checker config not provided.")
        return

    region = getattr(getattr(eks, "meta", None), "region_name", "") or ""
    cutoff = (datetime.now(timezone.utc) - timedelta(days=int(stale_days))).replace(
        microsecond=0
    )

    for name in _list_clusters(eks, log):
        ngs = _list_nodegroups(eks, name, log)
        for ng in ngs:
            try:
                d = eks.describe_nodegroup(clusterName=name, nodegroupName=ng).get(
                    "nodegroup", {}
                ) or {}
            except ClientError as exc:
                log.debug("[eks] describe_nodegroup %s/%s failed: %s", name, ng, exc)
                continue

            status = d.get("status")
            sc = d.get("scalingConfig") or {}
            des, mn = sc.get("desiredSize"), sc.get("minSize")
            created = d.get("createdAt")

            if status != "ACTIVE" or des != 0 or mn != 0:
                continue
            too_old = isinstance(created, datetime) and (
                (created if created.tzinfo else created.replace(tzinfo=timezone.utc)) < cutoff
            )
            if not too_old:
                continue

            arn = d.get("nodegroupArn") or ng
            inst_type = ",".join(d.get("instanceTypes", []) or [])

            try:
                # type: ignore[call-arg]
                config.WRITE_ROW(
                    writer=writer,
                    resource_id=arn,
                    name=f"{name}/{ng}",
                    owner_id=config.ACCOUNT_ID,  # type: ignore[arg-type]
                    resource_type="EKSNodegroup",
                    estimated_cost=0.0,
                    potential_saving=0.0,
                    flags=["EKSNodegroupScaledToZero"],
                    confidence=100,
                    signals=_signals_str(
                        {
                            "Region": region,
                            "Cluster": name,
                            "Nodegroup": ng,
                            "Status": status,
                            "Desired": des,
                            "Min": mn,
                            "InstanceTypes": inst_type,
                            "CreatedAt": _to_utc_iso(created)
                            if isinstance(created, datetime)
                            else None,
                            "StaleDays": stale_days,
                        }
                    ),
                )
            except Exception as exc:  # pylint: disable=broad-except
                log.warning("[eks] write_row ng scaled-to-zero %s/%s: %s", name, ng, exc)

            log.info("[eks] Wrote nodegroup scaled to zero: %s/%s", name, ng)


# --------------------- 5) Add-ons degraded (hygiene) --------------------- #

@retry_with_backoff(exceptions=(ClientError,))
def check_eks_addons_degraded(  # pylint: disable=unused-argument
    *args,
    logger: Optional[logging.Logger] = None,
    **kwargs,
) -> None:
    """Flag add-ons with Health.Status bad or with issues."""
    log = _logger(kwargs.get("logger") or logger)

    try:
        writer, eks = _extract_writer_eks(args, kwargs)
    except TypeError as exc:
        log.warning("[check_eks_addons_degraded] Skipping: %s", exc)
        return
    if not (config.ACCOUNT_ID and config.WRITE_ROW):
        log.warning("[check_eks_addons_degraded] Skipping: checker config not provided.")
        return

    region = getattr(getattr(eks, "meta", None), "region_name", "") or ""

    bad_states = {"DEGRADED", "UNHEALTHY"}

    for name in _list_clusters(eks, log):
        addons = []
        try:
            p = eks.get_paginator("list_addons")
            for page in p.paginate(clusterName=name):
                addons.extend(page.get("addons", []) or [])
        except ClientError as exc:
            log.debug("[eks] list_addons %s failed: %s", name, exc)
            continue

        for ad in addons:
            try:
                info = eks.describe_addon(clusterName=name, addonName=ad).get("addon", {}) or {}
            except ClientError as exc:
                log.debug("[eks] describe_addon %s/%s failed: %s", name, ad, exc)
                continue

            health = (info.get("health") or {}).get("status", "")
            issues = (info.get("health") or {}).get("issues") or []

            if str(health).upper() not in bad_states and not issues:
                continue

            arn = info.get("addonArn") or f"{name}:{ad}"
            ver = info.get("addonVersion")

            try:
                # type: ignore[call-arg]
                config.WRITE_ROW(
                    writer=writer,
                    resource_id=arn,
                    name=f"{name}/{ad}",
                    owner_id=config.ACCOUNT_ID,  # type: ignore[arg-type]
                    resource_type="EKSAddon",
                    estimated_cost=0.0,
                    potential_saving=0.0,
                    flags=["EKSAddonDegraded"],
                    confidence=100,
                    signals=_signals_str(
                        {
                            "Region": region,
                            "Cluster": name,
                            "Addon": ad,
                            "Version": ver,
                            "Health": health,
                            "IssueCount": len(issues),
                        }
                    ),
                )
            except Exception as exc:  # pylint: disable=broad-except
                log.warning("[eks] write_row addon degraded %s/%s: %s", name, ad, exc)

            log.info("[eks] Wrote degraded addon: %s/%s", name, ad)


# ----------------------- 6) Old cluster versions ------------------------- #

@retry_with_backoff(exceptions=(ClientError,))
def check_eks_old_versions(  # pylint: disable=unused-argument
    *args,
    logger: Optional[logging.Logger] = None,
    min_version_mm: str = "1.27",
    **kwargs,
) -> None:
    """Flag clusters on version lower than min_version_mm (e.g. '1.27')."""
    log = _logger(kwargs.get("logger") or logger)

    try:
        writer, eks = _extract_writer_eks(args, kwargs)
    except TypeError as exc:
        log.warning("[check_eks_old_versions] Skipping: %s", exc)
        return
    if not (config.ACCOUNT_ID and config.WRITE_ROW):
        log.warning("[check_eks_old_versions] Skipping: checker config not provided.")
        return

    region = getattr(getattr(eks, "meta", None), "region_name", "") or ""

    for name in _list_clusters(eks, log):
        try:
            desc = eks.describe_cluster(name=name).get("cluster", {}) or {}
        except ClientError as exc:
            log.debug("[eks] describe_cluster %s failed: %s", name, exc)
            continue

        arn = desc.get("arn") or name
        ver = str(desc.get("version") or "")
        mm = _version_mm(ver)
        if not mm or _cmp_mm(mm, min_version_mm) >= 0:
            continue

        try:
            # type: ignore[call-arg]
            config.WRITE_ROW(
                writer=writer,
                resource_id=arn,
                name=name,
                owner_id=config.ACCOUNT_ID,  # type: ignore[arg-type]
                resource_type="EKSCluster",
                estimated_cost=0.0,
                potential_saving=0.0,
                flags=["EKSClusterOldVersion"],
                confidence=100,
                signals=_signals_str(
                    {"Region": region, "Cluster": name, "Version": ver, "VersionMM": mm,
                     "MinRequired": min_version_mm}
                ),
            )
        except Exception as exc:  # pylint: disable=broad-except
            log.warning("[eks] write_row old version %s: %s", name, exc)

        log.info("[eks] Wrote old-version cluster: %s (v%s)", name, ver)
