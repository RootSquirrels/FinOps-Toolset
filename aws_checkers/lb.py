"""Checkers: Elastic Load Balancing v2 (ALB / NLB / GWLB).

Checks included:

  - check_elbv2_idle_load_balancers
      Very low traffic over the lookback window (bytes and, for ALB, requests).
      Estimates monthly base hourly cost and treats it as potential saving.

  - check_elbv2_no_registered_targets
      Load balancers whose attached target groups have zero registered targets.

  - check_elbv2_unused_target_groups
      Target groups not attached to any load balancer or with zero registered targets.

Design:
  - Dependencies via finops_toolset.checkers.config.setup(...).
  - CloudWatch via finops_toolset.cloudwatch.CloudWatchBatcher.
  - Tolerant signatures; graceful skips; no return values.
  - UTC datetimes; pylint-friendly; lines ≤ 100 chars.

Pricebook keys used (safe defaults if absent):
  "ELBv2": {
      "ALB_HR": 0.0225,
      "NLB_HR": 0.0225,
      "GWLB_HR": 0.0225
      # (LCU or data processing not modeled for idle checks)
  }
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
from core.cloudwatch import CloudWatchBatcher


# -------------------------------- helpers -------------------------------- #

def _extract_writer_elbv2_cw(
    args: Tuple[Any, ...],
    kwargs: Dict[str, Any],
) -> Tuple[Any, Any, Any]:
    """Accept writer/elbv2/cloudwatch (positional or keyword)."""
    writer = kwargs.get("writer", args[0] if len(args) >= 1 else None)
    elbv2 = kwargs.get("elbv2", args[1] if len(args) >= 2 else None)
    cloudwatch = kwargs.get("cloudwatch", args[2] if len(args) >= 3 else None)
    if writer is None or elbv2 is None or cloudwatch is None:
        raise TypeError(
            "Expected 'writer', 'elbv2' and 'cloudwatch' "
            f"(got writer={writer!r}, elbv2={elbv2!r}, cloudwatch={cloudwatch!r})"
        )
    return writer, elbv2, cloudwatch


def _ns_for_type(lb_type: str) -> str:
    t = (lb_type or "").lower()
    if t == "application":
        return "AWS/ApplicationELB"
    if t == "network":
        return "AWS/NetworkELB"
    if t == "gateway":
        return "AWS/GatewayELB"
    return "AWS/ApplicationELB"


def _hour_price(lb_type: str) -> float:
    t = (lb_type or "").lower()
    if t == "network":
        return float(config.safe_price("ELBv2", "NLB_HR", 0.0225))
    if t == "gateway":
        return float(config.safe_price("ELBv2", "GWLB_HR", 0.0225))
    return float(config.safe_price("ELBv2", "ALB_HR", 0.0225))


def _cw_lb_dim_value(arn: str) -> Optional[str]:
    # ARN contains '...:loadbalancer/<kind>/<name>/<id>'
    try:
        return arn.split("loadbalancer/")[1]
    except Exception:  # pylint: disable=broad-except
        return None


def _sum_from_result(res: Any) -> float:
    if res is None:
        return 0.0
    if isinstance(res, list) and res and isinstance(res[0], tuple):
        try:
            return float(sum(float(v) for _, v in res))
        except Exception:  # pylint: disable=broad-except
            return 0.0
    if isinstance(res, dict):
        vals = res.get("Values") or res.get("values") or []
        try:
            return float(sum(vals))
        except Exception:  # pylint: disable=broad-except
            return 0.0
    return 0.0


# ------------------- 1) Idle load balancers (low traffic) ---------------- #

@retry_with_backoff(exceptions=(ClientError,))
def check_elbv2_idle_load_balancers(  # pylint: disable=unused-argument
    *args,
    logger: Optional[logging.Logger] = None,
    lookback_days: int = 14,
    min_requests: int = 10,
    min_processed_bytes: float = 10_000_000.0,  # 10 MB total over window
    **kwargs,
) -> None:
    """
    Flag ALB/NLB/GWLB with very low traffic in the lookback window.

    Criteria:
      - For ALB: RequestCount < min_requests AND ProcessedBytes < min_processed_bytes
      - For NLB/GWLB: ProcessedBytes < min_processed_bytes
    """
    log = _logger(kwargs.get("logger") or logger)

    try:
        writer, elbv2, cloudwatch = _extract_writer_elbv2_cw(args, kwargs)
    except TypeError as exc:
        log.warning("[check_elbv2_idle_load_balancers] Skipping: %s", exc)
        return
    if not (config.ACCOUNT_ID and config.WRITE_ROW and config.GET_PRICE):
        log.warning("[check_elbv2_idle_load_balancers] Skipping: checker config not provided.")
        return

    region = getattr(getattr(elbv2, "meta", None), "region_name", "") or ""
    lbs: List[Dict[str, Any]] = []
    try:
        p = elbv2.get_paginator("describe_load_balancers")
        for page in p.paginate():
            lbs.extend(page.get("LoadBalancers", []) or [])
    except ClientError as exc:
        log.error("[elbv2] describe_load_balancers failed: %s", exc)
        return
    if not lbs:
        return

    now_utc = datetime.now(timezone.utc).replace(microsecond=0)
    start = now_utc - timedelta(days=int(lookback_days))
    period = 300

    id_map: Dict[str, Dict[str, str]] = {}
    results: Dict[str, Any] = {}
    metrics_ok = True
    try:
        cw = CloudWatchBatcher(region=region, client=cloudwatch)
        for lb in lbs:
            arn = lb.get("LoadBalancerArn") or ""
            lb_type = lb.get("Type") or "application"
            full = _cw_lb_dim_value(arn)
            if not full:
                continue
            ns = _ns_for_type(lb_type)

            id_bytes = f"bytes_{full}"
            cw.add_q(
                id_hint=id_bytes,
                namespace=ns,
                metric="ProcessedBytes",
                dims=[("LoadBalancer", full)],
                stat="Sum",
                period=period,
            )

            ids: Dict[str, str] = {"bytes": id_bytes}

            if lb_type.lower() == "application":
                id_req = f"req_{full}"
                cw.add_q(
                    id_hint=id_req,
                    namespace=ns,
                    metric="RequestCount",
                    dims=[("LoadBalancer", full)],
                    stat="Sum",
                    period=period,
                )
                ids["req"] = id_req

            id_map[arn] = ids

        results = cw.execute(start=start, end=now_utc)
    except ClientError as exc:
        log.warning("[elbv2] CloudWatch metrics unavailable: %s", exc)
        metrics_ok = False
    except Exception as exc:  # pylint: disable=broad-except
        log.warning("[elbv2] CloudWatch batch error: %s", exc)
        metrics_ok = False

    if not metrics_ok:
        return

    for lb in lbs:
        arn = lb.get("LoadBalancerArn") or ""
        name = lb.get("LoadBalancerName") or arn
        lb_type = (lb.get("Type") or "application").lower()
        scheme = lb.get("Scheme")  # internet-facing or internal
        created = lb.get("CreatedTime")
        full = _cw_lb_dim_value(arn)
        if not arn or not full:
            continue

        ids = id_map.get(arn, {})
        total_bytes = _sum_from_result(results.get(ids.get("bytes")))
        total_req = _sum_from_result(results.get("req") and results.get(ids.get("req")))

        is_idle = False
        if lb_type == "application":
            is_idle = (total_req < float(min_requests)) and (
                total_bytes < float(min_processed_bytes)
            )
        else:
            is_idle = total_bytes < float(min_processed_bytes)

        if not is_idle:
            continue

        hr = _hour_price(lb_type)
        est = 730.0 * hr
        potential = est

        signals = _signals_str(
            {
                "Region": region,
                "LBArn": arn,
                "Name": name,
                "Type": lb_type,
                "Scheme": scheme,
                "CreatedAt": _to_utc_iso(created) if isinstance(created, datetime) else None,
                "ReqSum": int(total_req),
                "BytesSum": int(total_bytes),
                "LookbackDays": lookback_days,
                "MinReq": min_requests,
                "MinBytes": int(min_processed_bytes),
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
                resource_type="ELBv2",
                estimated_cost=est,
                potential_saving=potential,
                flags=["ELBv2Idle"],
                confidence=100,
                signals=signals,
            )
        except Exception as exc:  # pylint: disable=broad-except
            log.warning("[elbv2] write_row idle LB %s: %s", arn, exc)

        log.info("[elbv2] Wrote idle LB: %s (%s)", name, lb_type)


# -------------- 2) LBs with zero registered targets across TGs ----------- #

@retry_with_backoff(exceptions=(ClientError,))
def check_elbv2_no_registered_targets(  # pylint: disable=unused-argument
    *args,
    logger: Optional[logging.Logger] = None,
    **kwargs,
) -> None:
    """Flag load balancers whose attached target groups have zero registered targets."""
    log = _logger(kwargs.get("logger") or logger)

    try:
        writer, elbv2, cloudwatch = _extract_writer_elbv2_cw(args, kwargs)  # cloudwatch unused
    except TypeError as exc:
        log.warning("[check_elbv2_no_registered_targets] Skipping: %s", exc)
        return
    if not (config.ACCOUNT_ID and config.WRITE_ROW and config.GET_PRICE):
        log.warning("[check_elbv2_no_registered_targets] Skipping: checker config not provided.")
        return

    region = getattr(getattr(elbv2, "meta", None), "region_name", "") or ""

    lbs: List[Dict[str, Any]] = []
    try:
        p = elbv2.get_paginator("describe_load_balancers")
        for page in p.paginate():
            lbs.extend(page.get("LoadBalancers", []) or [])
    except ClientError as exc:
        log.error("[elbv2] describe_load_balancers failed: %s", exc)
        return

    for lb in lbs:
        arn = lb.get("LoadBalancerArn") or ""
        name = lb.get("LoadBalancerName") or arn
        lb_type = (lb.get("Type") or "application").lower()
        if not arn:
            continue

        # Gather TGs for this LB
        tgs: List[Dict[str, Any]] = []
        try:
            p = elbv2.get_paginator("describe_target_groups")
            for page in p.paginate(LoadBalancerArn=arn):
                tgs.extend(page.get("TargetGroups", []) or [])
        except ClientError as exc:
            log.debug("[elbv2] describe_target_groups for %s failed: %s", arn, exc)
            continue

        # Count all registered targets across TGs
        reg = 0
        for tg in tgs:
            tg_arn = tg.get("TargetGroupArn")
            if not tg_arn:
                continue
            try:
                th = elbv2.describe_target_health(TargetGroupArn=tg_arn)
                reg += len(th.get("TargetHealthDescriptions", []) or [])
            except ClientError as exc:
                log.debug("[elbv2] describe_target_health %s failed: %s", tg_arn, exc)

        if reg > 0:
            continue

        hr = _hour_price(lb_type)
        est = 730.0 * hr
        potential = est

        signals = _signals_str(
            {
                "Region": region,
                "LBArn": arn,
                "Name": name,
                "Type": lb_type,
                "TargetGroupCount": len(tgs),
                "RegisteredTargets": reg,
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
                resource_type="ELBv2",
                estimated_cost=est,
                potential_saving=potential,
                flags=["ELBv2NoRegisteredTargets"],
                confidence=100,
                signals=signals,
            )
        except Exception as exc:  # pylint: disable=broad-except
            log.warning("[elbv2] write_row no-targets %s: %s", arn, exc)

        log.info("[elbv2] Wrote LB with no registered targets: %s", name)


# ---------------- 3) Unused / orphaned target groups (no LB) ------------- #

@retry_with_backoff(exceptions=(ClientError,))
def check_elbv2_unused_target_groups(  # pylint: disable=unused-argument
    *args,
    logger: Optional[logging.Logger] = None,
    **kwargs,
) -> None:
    """Flag target groups not attached to any load balancer or with zero targets."""
    log = _logger(kwargs.get("logger") or logger)

    try:
        writer, elbv2, cloudwatch = _extract_writer_elbv2_cw(args, kwargs)  # cloudwatch unused
    except TypeError as exc:
        log.warning("[check_elbv2_unused_target_groups] Skipping: %s", exc)
        return
    if not (config.ACCOUNT_ID and config.WRITE_ROW):
        log.warning("[check_elbv2_unused_target_groups] Skipping: checker config not provided.")
        return

    region = getattr(getattr(elbv2, "meta", None), "region_name", "") or ""

    tgs: List[Dict[str, Any]] = []
    try:
        p = elbv2.get_paginator("describe_target_groups")
        for page in p.paginate():
            tgs.extend(page.get("TargetGroups", []) or [])
    except ClientError as exc:
        log.error("[elbv2] describe_target_groups failed: %s", exc)
        return

    for tg in tgs:
        arn = tg.get("TargetGroupArn") or ""
        name = tg.get("TargetGroupName") or arn
        if not arn:
            continue

        lbs = tg.get("LoadBalancerArns") or []
        reg = 0
        try:
            th = elbv2.describe_target_health(TargetGroupArn=arn)
            reg = len(th.get("TargetHealthDescriptions", []) or [])
        except ClientError as exc:
            log.debug("[elbv2] describe_target_health %s failed: %s", arn, exc)

        if lbs or reg > 0:
            continue

        # No hourly cost for TGs; still a good hygiene signal
        try:
            # type: ignore[call-arg]
            config.WRITE_ROW(
                writer=writer,
                resource_id=arn,
                name=name,
                owner_id=config.ACCOUNT_ID,  # type: ignore[arg-type]
                resource_type="ELBv2TargetGroup",
                estimated_cost=0.0,
                potential_saving=0.0,
                flags=["ELBv2TargetGroupUnused"],
                confidence=100,
                signals=_signals_str(
                    {"Region": region, "TargetGroup": name, "RegisteredTargets": reg}
                ),
            )
        except Exception as exc:  # pylint: disable=broad-except
            log.warning("[elbv2] write_row unused TG %s: %s", arn, exc)

        log.info("[elbv2] Wrote unused target group: %s", name)
