"""Checkers: Amazon ECS (idle services, zero-task zombies, old task defs)."""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from botocore.client import BaseClient
from botocore.exceptions import ClientError

from aws_checkers.common import _logger, _signals_str, _to_utc_iso
from aws_checkers import config as chk
from finops_toolset import config as const
from core.retry import retry_with_backoff
from core.cloudwatch import CloudWatchBatcher


# ---------------------------------------------------------------------------
# Extractors
# ---------------------------------------------------------------------------

def _extract_writer_client(
    args: Tuple[Any, ...], kwargs: Dict[str, Any]
) -> Tuple[Any, BaseClient]:
    """Extract (writer, ecs client) from args/kwargs; raise if missing."""
    writer = kwargs.get("writer", args[0] if len(args) >= 1 else None)
    ecs = kwargs.get("client", args[1] if len(args) >= 2 else None)
    if writer is None or ecs is None:
        raise TypeError("Expected 'writer' and 'client'")
    return writer, ecs


def _extract_writer_cw_client(
    args: Tuple[Any, ...], kwargs: Dict[str, Any]
) -> Tuple[Any, BaseClient, BaseClient]:
    """Extract (writer, cloudwatch, ecs) from args/kwargs; raise if missing."""
    writer = kwargs.get("writer", args[0] if len(args) >= 1 else None)
    cloudwatch = kwargs.get("cloudwatch", args[1] if len(args) >= 2 else None)
    ecs = kwargs.get("client", args[2] if len(args) >= 3 else None)
    if writer is None or cloudwatch is None or ecs is None:
        raise TypeError("Expected 'writer', 'cloudwatch' and 'client'")
    return writer, cloudwatch, ecs


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _paginate(
    fn, page_key: str, token_key: str, **kwargs: Any
) -> Iterable[Dict[str, Any]]:
    """Generic paginator for list/describe APIs that return a next token."""
    token: Optional[str] = None
    while True:
        params = dict(kwargs)
        if token:
            params[token_key] = token
        page = fn(**params)
        for item in page.get(page_key, []) or []:
            yield item
        token = page.get(token_key)
        if not token:
            break


def _sum_series(points: Sequence[Tuple[datetime, float]]) -> float:
    """Sum values in a (timestamp, value) series."""
    return float(sum(float(v) for _, v in (points or [])))


def _avg_series(points: Sequence[Tuple[datetime, float]]) -> float:
    """Average values in a (timestamp, value) series."""
    vals = [float(v) for _, v in (points or [])]
    return float(sum(vals) / len(vals)) if vals else 0.0


def _cluster_name_from_arn(arn: str) -> str:
    """Extract the ECS cluster name from ARN suffix 'cluster/NAME'."""
    if not arn:
        return ""
    parts = arn.split("/", 1)
    return parts[1] if len(parts) > 1 else arn


def _is_fargate_service(svc: Dict[str, Any]) -> bool:
    """Return True if the service appears to run on Fargate (incl. Spot)."""
    lt = str(svc.get("launchType") or "").upper()
    if lt in {"FARGATE"}:
        return True
    cps = svc.get("capacityProviderStrategy") or []
    names = {str(x.get("capacityProvider") or "").upper() for x in cps}
    return bool({"FARGATE", "FARGATE_SPOT"} & names)


def _taskdef_cpu_memory(ecs: BaseClient, taskdef_arn: str) -> Tuple[float, float]:
    """Return (vCPU, GiB) defined at the task level, best-effort for Fargate."""
    try:
        td = ecs.describe_task_definition(taskDefinition=taskdef_arn).get("taskDefinition", {})  # type: ignore[call-arg]
    except ClientError:
        return 0.0, 0.0

    cpu_s = str(td.get("cpu") or "0")
    mem_s = str(td.get("memory") or "0")
    try:
        cpu_units = int(cpu_s)
    except Exception:  # pylint: disable=broad-except
        cpu_units = 0
    try:
        mem_mib = int(mem_s)
    except Exception:  # pylint: disable=broad-except
        mem_mib = 0

    vcpu = float(cpu_units) / 1024.0 if cpu_units > 0 else 0.0
    mem_gib = float(mem_mib) / 1024.0 if mem_mib > 0 else 0.0
    return vcpu, mem_gib


def _fargate_hourly(vcpu: float, mem_gib: float) -> float:
    """Return the hourly Fargate cost for given vCPU and GiB."""
    try:
        p_vcpu = float(chk.safe_price("FARGATE", "VCPU_HOUR", 0.0))  # type: ignore[arg-type]
        p_gb = float(chk.safe_price("FARGATE", "GB_HOUR", 0.0))      # type: ignore[arg-type]
    except Exception:  # pylint: disable=broad-except
        p_vcpu, p_gb = 0.0, 0.0
    return vcpu * p_vcpu + mem_gib * p_gb


def _bytes_to_mb(num: float) -> float:
    """Convert bytes to MiB."""
    try:
        return float(num) / (1024.0 * 1024.0)
    except Exception:  # pylint: disable=broad-except
        return 0.0


# ---------------------------------------------------------------------------
# Check 1: Idle ECS services (Fargate) — low CPU & network for N days
# ---------------------------------------------------------------------------

@retry_with_backoff(exceptions=(ClientError,))
def check_ecs_idle_services(  # noqa: D401
    region: str,
    *args: Any,
    logger: Optional[logging.Logger] = None,
    lookback_days: int = 14,
    cpu_threshold_pct: float = 1.0,
    net_total_mb_threshold: float = 5.0,
    **kwargs: Any,
) -> List[Dict[str, Any]]:
    """Flag Fargate services with desired>0 but ~zero CPU & network for N days.

    Potential saving: desired_tasks × (vCPU*VCPU_HOUR + GiB*GB_HOUR) × HOURS_PER_MONTH.
    """
    log = _logger(kwargs.get("logger") or logger)

    try:
        writer, cloudwatch, ecs = _extract_writer_cw_client(args, kwargs)
    except TypeError as exc:
        log.warning("[check_ecs_idle_services] Skipping: %s", exc)
        return []

    owner = str(kwargs.get("account_id") or chk.ACCOUNT_ID or "")
    if not (owner and chk.WRITE_ROW):
        log.warning("[check_ecs_idle_services] Skipping: missing config.")
        return []

    # Enumerate clusters
    clusters_arns = [c for c in _paginate(ecs.list_clusters, page_key="clusterArns", token_key="nextToken")]  # type: ignore[arg-type]
    if not clusters_arns:
        return []

    # Enumerate services by cluster
    services: List[Dict[str, Any]] = []
    for cluster_arn in clusters_arns:
        svc_arns: List[str] = []
        for page in _paginate(
            ecs.list_services, page_key="serviceArns", token_key="nextToken", cluster=cluster_arn
        ):
            svc_arns.extend(page if isinstance(page, list) else [page])
        if not svc_arns:
            continue
        # Describe in chunks
        for i in range(0, len(svc_arns), 10):
            chunk = svc_arns[i : i + 10]
            try:
                resp = ecs.describe_services(cluster=cluster_arn, services=chunk)  # type: ignore[call-arg]
            except ClientError:
                continue
            services.extend(resp.get("services", []) or [])

    if not services:
        return []

    # CW batch
    start = datetime.now(timezone.utc) - timedelta(days=lookback_days)
    end = datetime.now(timezone.utc)
    batch = CloudWatchBatcher(region, client=cloudwatch)

    idx_map: List[Tuple[str, str, str]] = []  # (svc_arn, svc_name, cluster_name)
    for idx, svc in enumerate(services):
        if not _is_fargate_service(svc):
            continue
        desired = int(svc.get("desiredCount") or 0)
        running = int(svc.get("runningCount") or 0)
        if desired <= 0 and running <= 0:
            continue  # zero tasks handled by another checker

        svc_name = str(svc.get("serviceName") or "")
        cluster_arn = str(svc.get("clusterArn") or "")
        cluster_name = _cluster_name_from_arn(cluster_arn)

        dims = [
            {"Name": "ClusterName", "Value": cluster_name},
            {"Name": "ServiceName", "Value": svc_name},
        ]
        batch.add_q(
            id_hint=f"cpu_{idx}",
            namespace="AWS/ECS",
            metric="CPUUtilization",
            dims=dims,
            stat="Average",
            period=3600,
        )
        # Network metrics may not exist everywhere; we attempt both
        batch.add_q(
            id_hint=f"netin_{idx}",
            namespace="AWS/ECS",
            metric="NetworkBytesIn",
            dims=dims,
            stat="Sum",
            period=3600,
        )
        batch.add_q(
            id_hint=f"netout_{idx}",
            namespace="AWS/ECS",
            metric="NetworkBytesOut",
            dims=dims,
            stat="Sum",
            period=3600,
        )
        idx_map.append((str(svc.get("serviceArn") or ""), svc_name, cluster_name))

    if not idx_map:
        return []

    series = batch.execute(start, end)

    hours = float(getattr(const, "HOURS_PER_MONTH", 730))
    rows: List[Dict[str, Any]] = []

    for idx, (svc_arn, svc_name, cluster_name) in enumerate(idx_map):
        # Find service object again (for counts and taskdef)
        svc = next((s for s in services if s.get("serviceArn") == svc_arn), None)
        if not svc:
            continue

        desired = int(svc.get("desiredCount") or 0)
        if desired <= 0:
            continue

        cpu_avg = _avg_series(series.get(f"cpu_{idx}", []))
        net_mb = _bytes_to_mb(
            _sum_series(series.get(f"netin_{idx}", [])) + _sum_series(series.get(f"netout_{idx}", []))
        )

        # Idle heuristic
        if cpu_avg > float(cpu_threshold_pct):
            continue
        if net_mb > float(net_total_mb_threshold):
            continue

        # Compute per-task hourly for Fargate
        taskdef_arn = str(svc.get("taskDefinition") or "")
        vcpu, mem_gib = _taskdef_cpu_memory(ecs, taskdef_arn)
        hourly_per_task = _fargate_hourly(vcpu, mem_gib)
        monthly = hourly_per_task * float(desired) * hours if hourly_per_task > 0.0 else 0.0
        potential = monthly if monthly > 0.0 else None

        created_iso = _to_utc_iso(svc.get("createdAt"))
        flags = ["IdleFargateService"]
        signals = _signals_str(
            {
                "cluster": cluster_name,
                "desired": desired,
                "cpu_avg_pct": round(cpu_avg, 2),
                "net_total_mb": round(net_mb, 2),
                "vcpu": round(vcpu, 2),
                "mem_gib": round(mem_gib, 2),
                "fg_hourly_task": round(hourly_per_task, 4),
            }
        )

        try:
            # type: ignore[call-arg]
            chk.WRITE_ROW(
                writer=writer,
                resource_id=svc_arn,
                name=svc_name,
                owner_id=str(chk.ACCOUNT_ID or ""),  # type: ignore[arg-type]
                resource_type="ECSService",
                region=region,
                state=str(svc.get("status") or "UNKNOWN"),
                creation_date=created_iso,
                estimated_cost=round(monthly, 2) if monthly else 0.0,
                potential_saving=round(potential, 2) if potential else None,
                flags=flags,
                confidence=80,
                signals=signals,
            )
        except Exception as exc:  # pylint: disable=broad-except
            log.warning("[ecs] write_row(idle) failed: %s", exc)

        rows.append({"service": svc_name, "potential": potential or 0.0})

    return rows


# ---------------------------------------------------------------------------
# Check 2: Services with zero tasks (zombies) but still bound to LBs/registries
# ---------------------------------------------------------------------------

@retry_with_backoff(exceptions=(ClientError,))
def check_ecs_services_zero_tasks(  # noqa: D401
    region: str,
    *args: Any,
    logger: Optional[logging.Logger] = None,
    **kwargs: Any,
) -> List[Dict[str, Any]]:
    """Flag services where desired==0 and running==0 but still configured.

    We surface attached load balancers or service registries as signals.
    """
    log = _logger(kwargs.get("logger") or logger)

    try:
        writer, ecs = _extract_writer_client(args, kwargs)
    except TypeError as exc:
        log.warning("[check_ecs_services_zero_tasks] Skipping: %s", exc)
        return []

    owner = str(kwargs.get("account_id") or chk.ACCOUNT_ID or "")
    if not (owner and chk.WRITE_ROW):
        log.warning("[check_ecs_services_zero_tasks] Skipping: missing config.")
        return []

    clusters_arns = [c for c in _paginate(ecs.list_clusters, page_key="clusterArns", token_key="nextToken")]  # type: ignore[arg-type]
    if not clusters_arns:
        return []

    rows: List[Dict[str, Any]] = []

    for cluster_arn in clusters_arns:
        svc_arns: List[str] = []
        for page in _paginate(
            ecs.list_services, page_key="serviceArns", token_key="nextToken", cluster=cluster_arn
        ):
            svc_arns.extend(page if isinstance(page, list) else [page])
        if not svc_arns:
            continue

        for i in range(0, len(svc_arns), 10):
            chunk = svc_arns[i : i + 10]
            try:
                resp = ecs.describe_services(cluster=cluster_arn, services=chunk)  # type: ignore[call-arg]
            except ClientError:
                continue
            for svc in resp.get("services", []) or []:
                desired = int(svc.get("desiredCount") or 0)
                running = int(svc.get("runningCount") or 0)
                if desired != 0 or running != 0:
                    continue

                svc_arn = str(svc.get("serviceArn") or "")
                svc_name = str(svc.get("serviceName") or "")
                cluster_name = _cluster_name_from_arn(str(svc.get("clusterArn") or ""))

                lbs = svc.get("loadBalancers") or []
                regs = svc.get("serviceRegistries") or []
                lb_targets = [lb.get("targetGroupArn") for lb in lbs if lb.get("targetGroupArn")]
                ns_arns = [r.get("registryArn") for r in regs if r.get("registryArn")]

                flags = ["ZombieService"]
                signals = _signals_str(
                    {
                        "cluster": cluster_name,
                        "lbs": ";".join(lb_targets) if lb_targets else "",
                        "registries": ";".join(ns_arns) if ns_arns else "",
                    }
                )
                created_iso = _to_utc_iso(svc.get("createdAt"))

                try:
                    # type: ignore[call-arg]
                    chk.WRITE_ROW(
                        writer=writer,
                        resource_id=svc_arn,
                        name=svc_name,
                        owner_id=owner,  # type: ignore[arg-type]
                        resource_type="ECSService",
                        region=region,
                        state=str(svc.get("status") or "UNKNOWN"),
                        creation_date=created_iso,
                        estimated_cost="",
                        potential_saving=None,
                        flags=flags,
                        confidence=70,
                        signals=signals,
                    )
                except Exception as exc:  # pylint: disable=broad-except
                    log.warning("[ecs] write_row(zombie) failed: %s", exc)

                rows.append({"service": svc_name, "potential": 0.0})

    return rows


# ---------------------------------------------------------------------------
# Check 3: Old task definitions (hygiene)
# ---------------------------------------------------------------------------

@retry_with_backoff(exceptions=(ClientError,))
def check_ecs_old_task_definitions(  # noqa: D401
    region: str,
    *args: Any,
    logger: Optional[logging.Logger] = None,
    older_than_days: int = 90,
    max_task_defs: int = 200,
    **kwargs: Any,
) -> List[Dict[str, Any]]:
    """Flag task definitions registered more than N days ago and not in use.

    This is hygiene (not direct cost), but reduces drift and accidental launches.
    """
    log = _logger(kwargs.get("logger") or logger)

    try:
        writer, ecs = _extract_writer_client(args, kwargs)
    except TypeError as exc:
        log.warning("[check_ecs_old_task_definitions] Skipping: %s", exc)
        return []

    owner = str(kwargs.get("account_id") or chk.ACCOUNT_ID or "")
    if not (owner and chk.WRITE_ROW):
        log.warning("[check_ecs_old_task_definitions] Skipping: missing config.")
        return []

    # Gather services' task definitions (in-use set)
    in_use: set[str] = set()
    clusters_arns = [c for c in _paginate(ecs.list_clusters, page_key="clusterArns", token_key="nextToken")]  # type: ignore[arg-type]
    for cluster_arn in clusters_arns:
        svc_arns: List[str] = []
        for page in _paginate(
            ecs.list_services, page_key="serviceArns", token_key="nextToken", cluster=cluster_arn
        ):
            svc_arns.extend(page if isinstance(page, list) else [page])
        for i in range(0, len(svc_arns), 10):
            chunk = svc_arns[i : i + 10]
            try:
                resp = ecs.describe_services(cluster=cluster_arn, services=chunk)  # type: ignore[call-arg]
            except ClientError:
                continue
            for svc in resp.get("services", []) or []:
                td = svc.get("taskDefinition")
                if isinstance(td, str):
                    in_use.add(td)

    # List task def ARNs (DESC) and limit
    arns: List[str] = []
    for page in _paginate(
        ecs.list_task_definitions, page_key="taskDefinitionArns", token_key="nextToken", sort="DESC"
    ):
        arns.extend(page if isinstance(page, list) else [page])
        if len(arns) >= int(max_task_defs):
            break
    arns = arns[: int(max_task_defs)]

    rows: List[Dict[str, Any]] = []
    cutoff = datetime.now(timezone.utc) - timedelta(days=int(older_than_days))

    for arn in arns:
        try:
            td = ecs.describe_task_definition(taskDefinition=arn).get("taskDefinition", {})  # type: ignore[call-arg]
        except ClientError:
            continue
        reg_at = td.get("registeredAt")
        if not isinstance(reg_at, datetime):
            continue
        if reg_at.tzinfo is None:
            reg_at = reg_at.replace(tzinfo=timezone.utc)
        if reg_at > cutoff:
            continue
        if arn in in_use:
            continue

        name = str(td.get("family") or arn)
        created_iso = _to_utc_iso(reg_at)
        flags = ["OldTaskDefinition"]
        signals = _signals_str({"status": str(td.get("status") or "ACTIVE")})

        try:
            # type: ignore[call-arg]
            chk.WRITE_ROW(
                writer=writer,
                resource_id=arn,
                name=name,
                owner_id=owner,  # type: ignore[arg-type]
                resource_type="ECSTaskDefinition",
                region=region,
                state=str(td.get("status") or "ACTIVE"),
                creation_date=created_iso,
                estimated_cost="",
                potential_saving=None,
                flags=flags,
                confidence=60,
                signals=signals,
            )
        except Exception as exc:  # pylint: disable=broad-except
            log.warning("[ecs] write_row(task-def) failed: %s", exc)

        rows.append({"taskdef": arn, "potential": 0.0})

    return rows
