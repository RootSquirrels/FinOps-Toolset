"""Checkers: Amazon VPC NAT Gateways.

Detects NAT Gateways that are likely wasting money:
  - Unreferenced by any route table (very likely unused).
  - No traffic in the recent window (heuristic "unused" via CloudWatch).
  - Failed/deleting states surfaced for ops hygiene.

Emits:
  - Flags
  - Estimated_Cost_USD (fixed monthly + data projection)
  - Potential_Saving_USD (set when unreferenced or unused)
  - Signals (compact k=v string)

Design:
  - Dependencies provided once via finops_toolset.checkers.config.setup(...).
  - Signature tolerant to run_check calling style; skips gracefully if deps/clients
    are missing (tests/mocks).
  - Uses finops_toolset.cloudwatch.CloudWatchBatcher with:
      cw = CloudWatchBatcher(region=..., client=...)
      cw.add_q(id_hint=..., namespace="AWS/NATGateway", metric=..., dims=[...], stat=..., period=...)
      results = cw.execute(start=..., end=...)
  - Timezone-aware (datetime.now(timezone.utc)).
  - Pylint-friendly lazy %s logging.
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


# ----------------------------- helpers --------------------------------- #

def _extract_writer_ec2_cw(
    args: Tuple[Any, ...],
    kwargs: Dict[str, Any],
) -> Tuple[Any, Any, Any]:
    """Accept writer/ec2/cloudwatch passed positionally or by keyword; prefer keywords."""
    writer = kwargs.get("writer", args[0] if len(args) >= 1 else None)
    ec2 = kwargs.get("ec2", args[1] if len(args) >= 2 else None)
    cloudwatch = kwargs.get("cloudwatch", args[2] if len(args) >= 3 else None)
    if writer is None or ec2 is None or cloudwatch is None:
        raise TypeError(
            "check_nat_gateways expected 'writer', 'ec2', and 'cloudwatch' "
            f"(got writer={writer!r}, ec2={ec2!r}, cloudwatch={cloudwatch!r})"
        )
    return writer, ec2, cloudwatch


def _sum_from_result(res: Any) -> float:
    """Reduce CloudWatchBatcher result → sum of values; supports [(ts, val)]."""
    if res is None:
        return 0.0
    if isinstance(res, list) and res and isinstance(res[0], tuple):
        try:
            return float(sum(float(v) for _, v in res))
        except Exception:  # pylint: disable=broad-except
            return 0.0
    if isinstance(res, dict):
        values = res.get("Values") or res.get("values") or []
        try:
            return float(sum(values))
        except Exception:  # pylint: disable=broad-except
            return 0.0
    return 0.0


def _route_table_nat_refs(ec2, nat_ids: List[str], log: logging.Logger) -> Dict[str, int]:
    """Return counts of route-table references for each NAT GW id."""
    refs: Dict[str, int] = {nid: 0 for nid in nat_ids}
    try:
        paginator = ec2.get_paginator("describe_route_tables")
        for page in paginator.paginate():
            for rt in page.get("RouteTables", []) or []:
                for route in rt.get("Routes", []) or []:
                    ngw = route.get("NatGatewayId")
                    if ngw and ngw in refs:
                        refs[ngw] += 1
    except ClientError as exc:
        log.debug("[nat] describe_route_tables failed: %s", exc)
    return refs


# ------------------------------ checker -------------------------------- #

@retry_with_backoff(exceptions=(ClientError,))
def check_nat_gateways(  # pylint: disable=unused-argument
    *args,
    logger: Optional[logging.Logger] = None,
    lookback_days: int = 30,
    **kwargs,
) -> None:
    """
    Enumerate NAT Gateways and flag:
      - Unreferenced (no route tables point to them) → 'NATGatewayUnreferenced'
      - No traffic in the window (via CloudWatch metrics) → 'NATGatewayUnused'
      - Failed/Deleting states → 'NATGatewayStateAttention'

    Estimated cost:
      - NATGW_MONTH (fixed monthly)
      - + projected data: (BytesInFromSource + BytesOutToDestination) scaled to month
        by factor (30 / lookback_days) * NATGW_DATA_GB
    """
    log = _logger(kwargs.get("logger") or logger)

    # Tolerate missing deps in tests
    try:
        writer, ec2, cloudwatch = _extract_writer_ec2_cw(args, kwargs)
    except TypeError as exc:
        log.warning("[check_nat_gateways] Skipping: %s", exc)
        return
    if not (config.ACCOUNT_ID and config.WRITE_ROW and config.GET_PRICE):
        log.warning("[check_nat_gateways] Skipping: checker config not provided.")
        return

    region = getattr(getattr(ec2, "meta", None), "region_name", "") or ""
    now_utc = datetime.now(timezone.utc).replace(microsecond=0)
    start_time = now_utc - timedelta(days=lookback_days)
    period = 3600  # 1 hour buckets

    # --- List NAT Gateways (guarded) ---
    nat_gws: List[Dict[str, Any]] = []
    try:
        paginator = ec2.get_paginator("describe_nat_gateways")
        for page in paginator.paginate():
            nat_gws.extend(page.get("NatGateways", []) or [])
    except ClientError as exc:
        log.error("[check_nat_gateways] describe_nat_gateways failed: %s", exc)
        return

    if not nat_gws:
        log.info("[check_nat_gateways] No NAT Gateways found in region %s", region)
        return

    nat_ids = [g.get("NatGatewayId") for g in nat_gws if g.get("NatGatewayId")]
    # --- Route table references (guarded) ---
    ref_counts = _route_table_nat_refs(ec2, nat_ids, log)

    # --- CloudWatch metrics (best-effort) ---
    metrics_ok = True
    cw_results: Dict[str, Any] = {}
    id_map: Dict[str, Dict[str, str]] = {}

    try:
        cw_batch = CloudWatchBatcher(region=region, client=cloudwatch)
        for g in nat_gws:
            nid = g.get("NatGatewayId")
            if not nid:
                continue
            # Two key volume metrics for data-processing charges
            id_in_src = f"in_src_{nid}"      # BytesInFromSource
            id_out_dst = f"out_dst_{nid}"    # BytesOutToDestination
            dims = [("NatGatewayId", nid)]

            cw_batch.add_q(
                id_hint=id_in_src,
                namespace="AWS/NATGateway",
                metric="BytesInFromSource",
                dims=dims,
                stat="Sum",
                period=period,
            )
            cw_batch.add_q(
                id_hint=id_out_dst,
                namespace="AWS/NATGateway",
                metric="BytesOutToDestination",
                dims=dims,
                stat="Sum",
                period=period,
            )
            id_map[nid] = {"in_src": id_in_src, "out_dst": id_out_dst}

        cw_results = cw_batch.execute(start=start_time, end=now_utc)
    except ClientError as exc:
        log.warning("[check_nat_gateways] CloudWatch metrics unavailable: %s", exc)
        metrics_ok = False
    except Exception as exc:  # pylint: disable=broad-except
        log.warning("[check_nat_gateways] CloudWatch batch error: %s", exc)
        metrics_ok = False

    # --- Pricing (heuristic) ---
    nat_fixed_month = config.safe_price("NATGateway", "NATGW_MONTH", default=32.85)
    nat_per_gb = config.safe_price("NATGateway", "NATGW_DATA_GB", default=0.045)

    # --- Emit rows ---
    for g in nat_gws:
        nid = g.get("NatGatewayId")
        if not nid:
            continue

        state = g.get("State")
        vpc_id = g.get("VpcId") or ""
        subnet_id = g.get("SubnetId") or ""
        conn_type = g.get("ConnectivityType") or "public"
        created_at = _to_utc_iso(g.get("CreateTime"))
        delete_time = _to_utc_iso(g.get("DeleteTime"))

        refs = ref_counts.get(nid, 0)

        # Metric reductions
        bytes_in_src = 0.0
        bytes_out_dst = 0.0
        if metrics_ok:
            ids = id_map.get(nid, {})
            in_series = cw_results.get(ids.get("in_src"))
            out_series = cw_results.get(ids.get("out_dst"))
            bytes_in_src = _sum_from_result(in_series)
            bytes_out_dst = _sum_from_result(out_series)

        total_bytes = bytes_in_src + bytes_out_dst
        observed_gb = total_bytes / (1024.0 ** 3) if total_bytes > 0 else 0.0
        # Project to ~monthly if the lookback != 30d
        scale = 30.0 / float(lookback_days) if lookback_days > 0 else 1.0
        monthly_data_gb = observed_gb * scale if metrics_ok else 0.0

        # Estimated monthly cost: fixed + data projection
        estimated_cost = nat_fixed_month + (monthly_data_gb * nat_per_gb)

        # Flags
        flags: List[str] = []
        if refs == 0:
            flags.append("NATGatewayUnreferenced")
        if metrics_ok and total_bytes <= 0.0:
            flags.append("NATGatewayUnused")
        if state in {"failed", "deleting"}:
            flags.append("NATGatewayStateAttention")

        if not flags:
            log.info(
                "[check_nat_gateways] Processed NAT: %s (refs=%d bytes=%.0f state=%s)",
                nid,
                refs,
                total_bytes,
                state,
            )
            continue

        # Potential savings: if unreferenced OR unused → we can likely remove it
        potential_saving = estimated_cost if ("NATGatewayUnreferenced" in flags or "NATGatewayUnused" in flags) else 0.0

        signals = _signals_str(
            {
                "Region": region,
                "NatGatewayId": nid,
                "VpcId": vpc_id,
                "SubnetId": subnet_id,
                "ConnectivityType": conn_type,
                "State": state,
                "CreatedAt": created_at,
                "DeletedAt": delete_time,
                "RouteTableRefs": refs,
                "BytesInFromSourceSum": int(bytes_in_src),
                "BytesOutToDestinationSum": int(bytes_out_dst),
                "ObservedDataGB": round(observed_gb, 3),
                "MonthlyDataGBEstimate": round(monthly_data_gb, 3),
                "LookbackDays": lookback_days,
                "MetricsAvailable": metrics_ok,
            }
        )

        try:
            # type: ignore[call-arg]
            config.WRITE_ROW(
                writer=writer,
                resource_id=nid,
                name=nid,
                owner_id=config.ACCOUNT_ID,  # type: ignore[arg-type]
                resource_type="NATGateway",
                estimated_cost=estimated_cost,
                potential_saving=potential_saving,
                flags=flags,
                confidence=100,
                signals=signals,
            )
        except Exception as exc:  # pylint: disable=broad-except
            log.warning("[check_nat_gateways] write_row failed for %s: %s", nid, exc)

        log.info(
            "[check_nat_gateways] Wrote NAT: %s (flags=%s est=%.2f save=%.2f)",
            nid,
            flags,
            estimated_cost,
            potential_saving,
        )
