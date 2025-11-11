"""Checkers: Amazon VPC & Transit Gateway (TGW).

Checks included:

  - check_vpc_no_flow_logs
      VPCs without Flow Logs configured (hygiene).

  - check_vpc_unused
      Heuristic: non-default VPCs with zero subnets OR with zero instances/ENIs/endpoints/NAT.

  - check_tgw_no_attachments
      Transit Gateways with zero AVAILABLE attachments (hygiene).

  - check_tgw_attachments_low_traffic
      TGW attachments with very low traffic over the lookback window; estimates
      monthly attachment-hours cost via price("TGW","ATTACHMENT_HR").

Design:
  - Dependencies via finops_toolset.checkers.config.setup(...).
  - CloudWatch via finops_toolset.cloudwatch.CloudWatchBatcher.
  - Tolerant signatures; no return values.
  - UTC datetimes; pylint-friendly; lines ≤ 100 chars.

Pricing keys used (safe defaults if absent):
  "TGW": {
      "ATTACHMENT_HR": 0.05,   # $/hr per attachment
      "DATA_GB": 0.02          # optional, not used by these checks
  }
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
)
from core.retry import retry_with_backoff
from core.cloudwatch import CloudWatchBatcher


# -------------------------------- helpers -------------------------------- #

def _extract_writer_ec2_cw(
    args: Tuple[Any, ...],
    kwargs: Dict[str, Any],
) -> Tuple[Any, Any, Any]:
    """Accept writer/ec2/cloudwatch passed positionally or by keyword."""
    writer = kwargs.get("writer", args[0] if len(args) >= 1 else None)
    ec2 = kwargs.get("ec2", args[1] if len(args) >= 2 else None)
    cloudwatch = kwargs.get("cloudwatch", args[2] if len(args) >= 3 else None)
    if writer is None or ec2 is None or cloudwatch is None:
        raise TypeError(
            "Expected 'writer', 'ec2', and 'cloudwatch' "
            f"(got writer={writer!r}, ec2={ec2!r}, cloudwatch={cloudwatch!r})"
        )
    return writer, ec2, cloudwatch


def _extract_writer_ec2(
    args: Tuple[Any, ...],
    kwargs: Dict[str, Any],
) -> Tuple[Any, Any]:
    """Accept writer/ec2 passed positionally or by keyword."""
    writer = kwargs.get("writer", args[0] if len(args) >= 1 else None)
    ec2 = kwargs.get("ec2", args[1] if len(args) >= 2 else None)
    if writer is None or ec2 is None:
        raise TypeError(
            "Expected 'writer' and 'ec2' "
            f"(got writer={writer!r}, ec2={ec2!r})"
        )
    return writer, ec2


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


def _price_tgw_attachment_hr() -> float:
    return float(config.safe_price("TGW", "ATTACHMENT_HR", 0.05))


def _chunk(lst: List[str], n: int) -> List[List[str]]:
    return [lst[i:i + n] for i in range(0, len(lst), n)]


# ---------------------------- VPC: no Flow Logs -------------------------- #

@retry_with_backoff(exceptions=(ClientError,))
def check_vpc_no_flow_logs(  # pylint: disable=unused-argument
    *args,
    logger: Optional[logging.Logger] = None,
    **kwargs,
) -> None:
    """Flag VPCs without any Flow Logs (hygiene)."""
    log = _logger(kwargs.get("logger") or logger)

    try:
        writer, ec2 = _extract_writer_ec2(args, kwargs)
    except TypeError as exc:
        log.warning("[check_vpc_no_flow_logs] Skipping: %s", exc)
        return
    if not (config.ACCOUNT_ID and config.WRITE_ROW):
        log.warning("[check_vpc_no_flow_logs] Skipping: checker config not provided.")
        return

    region = getattr(getattr(ec2, "meta", None), "region_name", "") or ""

    vpcs: List[Dict[str, Any]] = []
    try:
        p = ec2.get_paginator("describe_vpcs")
        for page in p.paginate():
            vpcs.extend(page.get("Vpcs", []) or [])
    except ClientError as exc:
        log.error("[vpc] describe_vpcs failed: %s", exc)
        return
    if not vpcs:
        return

    vpc_ids = [v.get("VpcId") for v in vpcs if v.get("VpcId")]
    vpcs_with_logs: set = set()

    try:
        p = ec2.get_paginator("describe_flow_logs")
        for chunk_ids in _chunk(vpc_ids, 100):
            for page in p.paginate(
                Filters=[{"Name": "resource-id", "Values": chunk_ids}]
            ):
                for fl in page.get("FlowLogs", []) or []:
                    rid = fl.get("ResourceId")
                    if rid:
                        vpcs_with_logs.add(rid)
    except ClientError as exc:
        log.error("[vpc] describe_flow_logs failed: %s", exc)
        return

    for v in vpcs:
        vid = v.get("VpcId") or ""
        if not vid or vid in vpcs_with_logs:
            continue

        name = next(
            (t.get("Value") for t in v.get("Tags", []) or [] if t.get("Key") == "Name"),
            "",
        )
        is_default = bool(v.get("IsDefault"))

        try:
            # type: ignore[call-arg]
            config.WRITE_ROW(
                writer=writer,
                resource_id=vid,
                name=name or vid,
                owner_id=config.ACCOUNT_ID,  # type: ignore[arg-type]
                resource_type="VPC",
                estimated_cost=0.0,
                potential_saving=0.0,
                flags=["VPCNoFlowLogs"],
                confidence=100,
                signals=_signals_str({"Region": region, "VpcId": vid, "IsDefault": is_default}),
            )
        except Exception as exc:  # pylint: disable=broad-except
            log.warning("[vpc] write_row no-flow-logs %s: %s", vid, exc)

        log.info("[vpc] Wrote VPC without Flow Logs: %s", vid)


# ----------------------------- VPC: unused -------------------------------- #

def _count_desc(ec2, fn_name: str, **kwargs) -> int:
    """Describe helper that returns count, best-effort."""
    try:
        paginator = ec2.get_paginator(fn_name)
        total = 0
        for page in paginator.paginate(**kwargs):
            # pick key by call type
            if fn_name == "describe_network_interfaces":
                total += len(page.get("NetworkInterfaces", []) or [])
            elif fn_name == "describe_vpc_endpoints":
                total += len(page.get("VpcEndpoints", []) or [])
            elif fn_name == "describe_nat_gateways":
                total += len(page.get("NatGateways", []) or [])
            elif fn_name == "describe_subnets":
                total += len(page.get("Subnets", []) or [])
            elif fn_name == "describe_internet_gateways":
                total += len(page.get("InternetGateways", []) or [])
            elif fn_name == "describe_instances":
                for r in page.get("Reservations", []) or []:
                    total += len(r.get("Instances", []) or [])
            else:
                # fallback: count all values in page
                for v in page.values():
                    if isinstance(v, list):
                        total += len(v)
        return total
    except ClientError:
        return 0


@retry_with_backoff(exceptions=(ClientError,))
def check_vpc_unused(  # pylint: disable=unused-argument
    *args,
    logger: Optional[logging.Logger] = None,
    **kwargs,
) -> None:
    """
    Heuristic 'unused' VPCs:
      - Not default, and
      - (no subnets) OR (zero instances AND zero ENIs AND zero endpoints AND zero NAT)
    """
    log = _logger(kwargs.get("logger") or logger)

    try:
        writer, ec2 = _extract_writer_ec2(args, kwargs)
    except TypeError as exc:
        log.warning("[check_vpc_unused] Skipping: %s", exc)
        return
    if not (config.ACCOUNT_ID and config.WRITE_ROW):
        log.warning("[check_vpc_unused] Skipping: checker config not provided.")
        return

    region = getattr(getattr(ec2, "meta", None), "region_name", "") or ""

    vpcs: List[Dict[str, Any]] = []
    try:
        p = ec2.get_paginator("describe_vpcs")
        for page in p.paginate():
            vpcs.extend(page.get("Vpcs", []) or [])
    except ClientError as exc:
        log.error("[vpc] describe_vpcs failed: %s", exc)
        return

    for v in vpcs:
        vid = v.get("VpcId") or ""
        if not vid or v.get("IsDefault"):
            continue

        name = next(
            (t.get("Value") for t in v.get("Tags", []) or [] if t.get("Key") == "Name"),
            "",
        )

        subnets = _count_desc(ec2, "describe_subnets", Filters=[{"Name": "vpc-id", "Values": [vid]}])
        insts = _count_desc(
            ec2,
            "describe_instances",
            Filters=[{"Name": "vpc-id", "Values": [vid]},
                     {"Name": "instance-state-name",
                      "Values": ["pending", "running", "stopping", "stopped"]}],
        )
        enis = _count_desc(
            ec2, "describe_network_interfaces", Filters=[{"Name": "vpc-id", "Values": [vid]}]
        )
        endpoints = _count_desc(
            ec2, "describe_vpc_endpoints", Filters=[{"Name": "vpc-id", "Values": [vid]}]
        )
        nat = _count_desc(
            ec2,
            "describe_nat_gateways",
            Filter=[{"Name": "vpc-id", "Values": [vid]}],
        )
        # IGW presence doesn't imply cost; fetch as signal only
        igw = _count_desc(
            ec2,
            "describe_internet_gateways",
            Filters=[{"Name": "attachment.vpc-id", "Values": [vid]}],
        )

        unused = (subnets == 0) or (insts == 0 and enis == 0 and endpoints == 0 and nat == 0)
        if not unused:
            continue

        try:
            # type: ignore[call-arg]
            config.WRITE_ROW(
                writer=writer,
                resource_id=vid,
                name=name or vid,
                owner_id=config.ACCOUNT_ID,  # type: ignore[arg-type]
                resource_type="VPC",
                estimated_cost=0.0,
                potential_saving=0.0,
                flags=["VPCUnusedHeuristic"],
                confidence=100,
                signals=_signals_str(
                    {
                        "Region": region,
                        "VpcId": vid,
                        "Subnets": subnets,
                        "Instances": insts,
                        "ENIs": enis,
                        "Endpoints": endpoints,
                        "NATGateways": nat,
                        "InternetGateways": igw,
                    }
                ),
            )
        except Exception as exc:  # pylint: disable=broad-except
            log.warning("[vpc] write_row unused %s: %s", vid, exc)

        log.info("[vpc] Wrote unused VPC: %s", vid)


# -------------------------- TGW: no attachments -------------------------- #

@retry_with_backoff(exceptions=(ClientError,))
def check_tgw_no_attachments(  # pylint: disable=unused-argument
    *args,
    logger: Optional[logging.Logger] = None,
    **kwargs,
) -> None:
    """Flag Transit Gateways with zero AVAILABLE attachments (hygiene)."""
    log = _logger(kwargs.get("logger") or logger)

    try:
        writer, ec2 = _extract_writer_ec2(args, kwargs)
    except TypeError as exc:
        log.warning("[check_tgw_no_attachments] Skipping: %s", exc)
        return
    if not (config.ACCOUNT_ID and config.WRITE_ROW):
        log.warning("[check_tgw_no_attachments] Skipping: checker config not provided.")
        return

    region = getattr(getattr(ec2, "meta", None), "region_name", "") or ""

    tgws: List[Dict[str, Any]] = []
    try:
        p = ec2.get_paginator("describe_transit_gateways")
        for page in p.paginate():
            tgws.extend(page.get("TransitGateways", []) or [])
    except ClientError as exc:
        log.error("[tgw] describe_transit_gateways failed: %s", exc)
        return

    for t in tgws:
        tid = t.get("TransitGatewayId") or ""
        if not tid:
            continue

        # Count AVAILABLE attachments
        count = 0
        try:
            p = ec2.get_paginator("describe_transit_gateway_attachments")
            for page in p.paginate(
                Filters=[{"Name": "transit-gateway-id", "Values": [tid]},
                         {"Name": "state", "Values": ["available"]}]
            ):
                count += len(page.get("TransitGatewayAttachments", []) or [])
        except ClientError as exc:
            log.debug("[tgw] describe_transit_gateway_attachments %s failed: %s", tid, exc)
            continue

        if count != 0:
            continue

        name = next(
            (t.get("Value") for t in t.get("Tags", []) or [] if t.get("Key") == "Name"),
            "",
        )

        try:
            # type: ignore[call-arg]
            config.WRITE_ROW(
                writer=writer,
                resource_id=tid,
                name=name or tid,
                owner_id=config.ACCOUNT_ID,  # type: ignore[arg-type]
                resource_type="TransitGateway",
                estimated_cost=0.0,
                potential_saving=0.0,
                flags=["TGWNoAttachments"],
                confidence=100,
                signals=_signals_str({"Region": region, "TransitGatewayId": tid}),
            )
        except Exception as exc:  # pylint: disable=broad-except
            log.warning("[tgw] write_row no-attachments %s: %s", tid, exc)

        log.info("[tgw] Wrote TGW with no attachments: %s", tid)


# ------------------- TGW: low-traffic attachments (cost) ----------------- #

@retry_with_backoff(exceptions=(ClientError,))
def check_tgw_attachments_low_traffic(  # pylint: disable=unused-argument
    *args,
    logger: Optional[logging.Logger] = None,
    lookback_days: int = 14,
    bytes_threshold: float = 50_000_000.0,  # 50 MB total over window
    **kwargs,
) -> None:
    """
    Flag TGW attachments with very low traffic over the lookback window.

    Metrics (best-effort; may vary by region/feature):
      - Namespace: "AWS/TransitGateway"
      - Metrics: BytesIn, BytesOut
      - Dims: ("TransitGateway", <tgw-id>), ("Attachment", <attachment-id>)

    Estimated monthly cost uses price("TGW","ATTACHMENT_HR") per attachment.
    """
    log = _logger(kwargs.get("logger") or logger)

    try:
        writer, ec2, cloudwatch = _extract_writer_ec2_cw(args, kwargs)
    except TypeError as exc:
        log.warning("[check_tgw_attachments_low_traffic] Skipping: %s", exc)
        return
    if not (config.ACCOUNT_ID and config.WRITE_ROW and config.GET_PRICE):
        log.warning("[check_tgw_attachments_low_traffic] Skipping: checker config not provided.")
        return

    region = getattr(getattr(ec2, "meta", None), "region_name", "") or ""

    # Collect all AVAILABLE attachments with their TGW id
    attaches: List[Dict[str, str]] = []
    try:
        p = ec2.get_paginator("describe_transit_gateway_attachments")
        for page in p.paginate(
            Filters=[{"Name": "state", "Values": ["available"]}]
        ):
            for a in page.get("TransitGatewayAttachments", []) or []:
                aid = a.get("TransitGatewayAttachmentId")
                tid = a.get("TransitGatewayId")
                if aid and tid:
                    attaches.append({"aid": aid, "tid": tid})
    except ClientError as exc:
        log.error("[tgw] describe_transit_gateway_attachments failed: %s", exc)
        return
    if not attaches:
        return

    now_utc = datetime.now(timezone.utc).replace(microsecond=0)
    start = now_utc - timedelta(days=int(lookback_days))
    period = 300

    id_map: Dict[str, Dict[str, str]] = {}
    results: Dict[str, Any] = {}
    metrics_ok = True
    try:
        cw = CloudWatchBatcher(region=region, client=cloudwatch)
        for a in attaches:
            aid, tid = a["aid"], a["tid"]
            dims = [("TransitGateway", tid), ("Attachment", aid)]

            id_in = f"in_{aid}"
            id_out = f"out_{aid}"

            cw.add_q(
                id_hint=id_in,
                namespace="AWS/TransitGateway",
                metric="BytesIn",
                dims=dims,
                stat="Sum",
                period=period,
            )
            cw.add_q(
                id_hint=id_out,
                namespace="AWS/TransitGateway",
                metric="BytesOut",
                dims=dims,
                stat="Sum",
                period=period,
            )

            id_map[aid] = {"in": id_in, "out": id_out}

        results = cw.execute(start=start, end=now_utc)
    except ClientError as exc:
        log.warning("[tgw] CloudWatch metrics unavailable: %s", exc)
        metrics_ok = False
    except Exception as exc:  # pylint: disable=broad-except
        log.warning("[tgw] CloudWatch batch error: %s", exc)
        metrics_ok = False

    if not metrics_ok:
        return

    hr = _price_tgw_attachment_hr()
    monthly = const.HOURS_PER_MONTH * hr

    for a in attaches:
        aid, tid = a["aid"], a["tid"]

        b_in = _sum_from_result(results.get(id_map.get(aid, {}).get("in")))
        b_out = _sum_from_result(results.get(id_map.get(aid, {}).get("out")))
        total = float(b_in + b_out)

        if total > float(bytes_threshold):
            continue

        # Best-effort name via tags
        name = ""
        try:
            resp = ec2.describe_transit_gateway_attachments(
                TransitGatewayAttachmentIds=[aid]
            )
            items = resp.get("TransitGatewayAttachments", []) or []
            if items:
                tags = items[0].get("Tags", []) or []
                name = next((t.get("Value") for t in tags if t.get("Key") == "Name"), "")
        except ClientError:
            name = ""

        signals = _signals_str(
            {
                "Region": region,
                "AttachmentId": aid,
                "TransitGatewayId": tid,
                "BytesInSum": int(b_in),
                "BytesOutSum": int(b_out),
                "TotalBytes": int(total),
                "LookbackDays": lookback_days,
                "BytesThreshold": int(bytes_threshold),
                "HrPrice_Attachment": hr,
            }
        )

        try:
            # type: ignore[call-arg]
            config.WRITE_ROW(
                writer=writer,
                resource_id=aid,
                name=name or aid,
                owner_id=config.ACCOUNT_ID,  # type: ignore[arg-type]
                resource_type="TransitGatewayAttachment",
                estimated_cost=monthly,
                potential_saving=monthly,
                flags=["TGWAttachmentLowTraffic"],
                confidence=100,
                signals=signals,
            )
        except Exception as exc:  # pylint: disable=broad-except
            log.warning("[tgw] write_row low-traffic %s: %s", aid, exc)

        log.info("[tgw] Wrote low-traffic TGW attachment: %s", aid)
