"""
AWS Cleanup & Cost Optimization Analyzer
========================================

This script performs a comprehensive analysis of AWS resources across multiple services
to identify unused, misconfigured, or cost-inefficient components. It generates a CSV
report with metadata, estimated costs, and optimization flags for review.

Key Features
------------
1. **Amazon Machine Images (AMIs)**
   - Lists owned AMIs, checks references in EC2, ASG, Launch Templates, and CloudFormation.
   - Flags unreferenced, old, or externally shared AMIs.
   - Estimates snapshot storage cost.

2. **Amazon S3**
   - Lists all buckets, analyzes object count, size, and last modified date.
   - Flags large, old, or untagged buckets.
   - Estimates storage cost.
   - Detect >7‑day old multipart uploads, sum part sizes, and estimate storage cost.


3. **Elastic IPs**
   - Detects unused Elastic IP addresses and estimates monthly cost.

4. **Elastic Network Interfaces (ENIs)**
   - Identifies detached ENIs.

5. **Elastic File System (EFS)**
   - Finds unused file systems (no mount targets).
   - Flags storage class usage (Standard vs IA).
   - Estimates monthly cost.
   - Idle EFS, Provisioned Throughput under-utilization
   - HighIAReads -> large IA footprint + frequent read activity (can incur IA retrieval cost).
   - checks for too many AZ mount targets for a low-traffic FS
   - Consider Archive lifecycle when STD is large

6. **Elastic Load Balancers (ALB/NLB)**
   - Flags idle load balancers (no healthy targets).

7. **NAT Gateways**
   - Detects potentially unused NAT Gateways and estimates monthly cost.

8. **CloudWatch Logs**
   - Identifies log groups with infinite retention and estimates storage cost.

9. **AWS Backup**
   - Flags backup plans with misconfigured retention policies.

10. **Amazon FSx**
    - Detects orphaned FSx backups and estimates storage cost.

11. **Route 53**
    - Flags stale DNS records pointing to non-existent ELB or S3 targets.

12. **AWS Lambda**
    - Flags functions with no invocations in 90 days or high error rates.
    - Stale published versions: find versions with zero invocations over the lookback window.
    - Version sprawl: flag functions with many published versions.
    - Reserved concurrency underuse: compare reserved vs observed max concurrency.
    - Package bloat: flag large deployment packages.
    - Layer review: flag large or old layers (by size and creation date when retrievable).
    - Memory rightsizing heuristic: propose a lower memory setting and estimate potential savings.
    - Low traffic categorization: distinguish “no traffic” from “low traffic” functions.
    - /tmp usage heuristic: highlight functions likely incurring time due to heavy temp usage.

13. **Amazon DynamoDB**
    - Analyzes tables for:
        * Over-provisioned capacity (rightsizing recommendations).
        * Idle tables.
        * Missing TTL.
        * PITR and backup hygiene.
        * Table class optimization (Standard → Standard-IA).
        * Unused or over-provisioned GSIs.
    - Estimates current monthly cost (storage + capacity).
    - Reports potential savings in flags.

14. **EBS Snapshots**
    - Flags replicated snapshots and estimates storage cost.

15. **VPC & TGW**
    - Lists active inter-region VPC peerings (`describe_vpc_peering_connections`).
    - Lists inter-region TGW peering attachments (`describe_transit_gateway_peering_attachments`).
    - Queries CloudWatch `BytesOutToRegion` metrics to estimate monthly transfer volume and cost.
    - Adds FinOps flags including PotentialSaving≈X$ and high-level remediation advice. 

16. **FSR**
    - Checks EBS that has FSR and flags them

17. **ECR**
    - Checks storage and staleness for ECR

18. **EKS**
    - Checks EKS for empty clusters

19. **EBS**
    - Flags unattached volumes (state=available) with monthly storage cost.
    - Flags gp2 volumes for gp3 migration with savings estimate.
    - Flags EBS Cold Volumes with savings estimate
    - Flags gp3 volumes with over-provisioned add-ons (IOPS/Throughput) vs observed IO.
      Suggests reductions and estimates PotentialSaving using PRICING['EBS'] add-on rates.
    - Flags io1/io2 as "ConsiderGP3" when observed IO is low (no exact $ without pricing here).

20. **SSM**
    - Flag Advanced tier parameters not updated >180 days

21. **EC2**
    - Flags idle instances 

22. **CF**
    - Flags IdleDistribution when requests and data are near zero over the lookback window.
    - Detects Dedicated IP custom SSL

23. **RDS**
    - Identity deprecated RDS (mysql 5.7 or aurora 2) that leads in expensive extended support 
    - Identify orphans / old snapshots 

24. **KMS**
    - Identify KMS keys with no usage in the last 90d

25. **Certificates**
    - Identify private certificates not used

Output
------
- CSV file (`cleanup_estimates.csv`) with columns:
  Resource_ID, Name, ResourceType, OwnerId, State, Creation_Date,
  Storage_GB, Estimated_Cost_USD, ApplicationID, Application, Environment,
  ReferencedIn, FlaggedForReview

Additional Features
-------------------
- Multi-region support (configured via REGIONS constant).
- Retry logic with exponential backoff and jitter for API calls.
- Logging to `cleanup_analysis.log`.
- Threaded processing for AMI analysis.
- Tag validation for ApplicationID, Application, Environment.
- Profiler active that enables to check script performance 

Usage
-----
- Configure AWS credentials and permissions.
- Adjust constants for pricing assumptions and thresholds.
"""

#region Imports SECTION

import csv
import os
import logging
from typing import Dict, Optional, List, Union, Callable, Any, Set
from datetime import datetime, timezone, timedelta

from dataclasses import dataclass, field
import re

from time import perf_counter
import boto3 # type: ignore
from botocore.exceptions import ClientError # type: ignore
#from correlator import build_certificate_graph, summarize_cert_usage

from finops_toolset.config import (
    SDK_CONFIG,
    REGIONS, OUTPUT_FILE, LOG_FILE,
    VPC_LOOKBACK_DAYS, MIN_COST_THRESHOLD,
)

from finops_toolset.pricing import get_price
from aws_checkers.eip import check_unused_elastic_ips as eip
from aws_checkers.network_interfaces import check_detached_network_interfaces as eni
from aws_checkers import ssm as ssm_checks
from core.retry import retry_with_backoff
from aws_checkers import config as checkers_config
from aws_checkers.private_ca import check_private_certificate_authorities
from aws_checkers.kms import check_kms_customer_managed_keys
from aws_checkers.efs import check_unused_efs_filesystems
from aws_checkers import backup as backup_checks
from aws_checkers.cloudfront import check_cloudfront_distributions
from aws_checkers import ecr as ecr_checks
from aws_checkers.nat_gateways import check_nat_gateways
from aws_checkers import ebs as ebs_checks
from aws_checkers import kinesis as kinesis_checks
from aws_checkers import dynamodb as ddb_checks
from aws_checkers import s3 as s3_checks
from aws_checkers import ami as ami_checks
from aws_checkers import lambda_svc as lambda_checks
from aws_checkers import ec2 as ec2_checks
from aws_checkers import loggroups as lg_checks
from aws_checkers import fsx as fsx_checks
from aws_checkers import rds_snapshots as rds_snaps
from aws_checkers import lb as lb_checks
from aws_checkers import wafv2 as waf_checks
from aws_checkers import acm as acm_checks
#endregion

# Configure logging
logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)

#logger = logging.getLogger("aws-finops")  # base logger for your script

#region CSV Helpers 

def write_resource_to_csv(
    writer: csv.writer,
    resource_id: str,
    name: str,
    resource_type: str,
    owner_id: str = "",
    state: str = "",
    creation_date: str = "",
    storage_gb: Union[float, str] = 0.0,
    estimated_cost: Union[float, str] = 0.0,
    app_id: str = "",
    app: str = "",
    env: str = "",
    referenced_in: str = "",
    flags: Union[str, List[str]] = "",
    object_count: Union[int, str, None] = "",
    potential_saving: Union[float, str, None] = None,
    confidence: Optional[int] = None,
    signals: Union[str, Dict[str, Any], List[str], None] = None,
) -> None:
    """
    Unified CSV writer with extended columns:
      - Object_Count: numeric count (e.g., S3 NumberOfObjects).
      - Potential_Saving_USD: numeric, auto-parsed from flags 'PotentialSaving=12.34$' (if not provided).
      - Confidence: int 0-100 indicating how strong the evidence is.
      - Signals: compact diagnostics (str or 'k=v;...' built from dict/list).
    """
    try:
        # normalize flags
        if isinstance(flags, list):
            flagged = ", ".join(flags)
            flags_list = flags
        else:
            flagged = flags or ""
            flags_list = [f.strip() for f in flagged.split(",") if f.strip()] if flagged else []

        # derive potential saving if not given
        if potential_saving is None:
            potential_saving = ""
            for f in flags_list:
                if f.startswith("PotentialSaving"):
                    m = re.search(r"PotentialSaving[=≈]\s*([0-9]+(?:\.[0-9]+)?)\$", f)
                    if m:
                        try:
                            potential_saving = float(m.group(1))
                            break
                        except ValueError:
                            pass

        # normalize signals
        if signals is None:
            signals_str = ""
        elif isinstance(signals, str):
            signals_str = signals
        elif isinstance(signals, list):
            signals_str = " | ".join(str(x) for x in signals)
        elif isinstance(signals, dict):
            parts = []
            for k, v in signals.items():
                try:
                    parts.append(f"{k}={v}")
                except Exception:
                    parts.append(f"{k}=<err>")
            signals_str = " | ".join(parts)
        else:
            signals_str = str(signals)

        writer.writerow([
            resource_id, name, resource_type, owner_id, state, creation_date,
            storage_gb, object_count if object_count is not None else "",
            estimated_cost, potential_saving if potential_saving is not None else "",
            app_id, app, env, referenced_in, flagged,
            confidence if confidence is not None else "", signals_str
        ])
    except Exception as e:
        logging.error(f"[write_resource_to_csv] Failed to write row for {resource_id or name}: {e}")


def _fmt_dt(dt: Optional[datetime]) -> str:
    if not dt:
        return ""
    # unify to ISO-8601 Z (CSV-friendly)
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


#endregion

#region ENGINE SECTION

LOGGER = logging.getLogger(__name__)
LOGGER.addHandler(logging.NullHandler())

def init_clients(region: str):
    """Create boto3 clients for the toolset."""
    return {
        "ec2": boto3.client("ec2", region_name=region, config=SDK_CONFIG),
        "autoscaling": boto3.client("autoscaling", region_name=region, config=SDK_CONFIG),
        "elbv2": boto3.client("elbv2", region_name=region, config=SDK_CONFIG),
        "efs": boto3.client("efs", region_name=region, config=SDK_CONFIG),
        "s3": boto3.client("s3", config=SDK_CONFIG),
        "cfn": boto3.client("cloudformation", region_name=region, config=SDK_CONFIG),
        "logs": boto3.client("logs", region_name=region, config=SDK_CONFIG),
        "backup": boto3.client("backup", region_name=region, config=SDK_CONFIG),
        "fsx": boto3.client("fsx", region_name=region, config=SDK_CONFIG),
        "route53": boto3.client("route53", config=SDK_CONFIG),
        "lambda": boto3.client("lambda", region_name=region, config=SDK_CONFIG),
        "cloudwatch": boto3.client("cloudwatch", region_name=region, config=SDK_CONFIG),
        "sts": boto3.client("sts", config=SDK_CONFIG),
        "dynamodb": boto3.client("dynamodb", region_name=region, config=SDK_CONFIG),
        "dynamodbstreams": boto3.client("dynamodbstreams", region_name=region, config=SDK_CONFIG),
        "ecr": boto3.client("ecr", region_name=region, config=SDK_CONFIG),
        "eks": boto3.client("eks", region_name=region, config=SDK_CONFIG),
        "rds": boto3.client("rds", region_name=region, config=SDK_CONFIG),
        "kinesis": boto3.client("kinesis", region_name=region, config=SDK_CONFIG),
        "wafv2": boto3.client("wafv2", region_name=region, config=SDK_CONFIG),
        "ssm": boto3.client("ssm", region_name=region, config=SDK_CONFIG),
        "cloudfront": boto3.client("cloudfront", config=SDK_CONFIG),
        "cloudtrail": boto3.client("cloudtrail", config=SDK_CONFIG),
        "kms": boto3.client("kms", region_name=region, config=SDK_CONFIG),
        "acm-pca": boto3.client("acm-pca", region_name=region, config=SDK_CONFIG),
        "acm": boto3.client("acm", region_name=region, config=SDK_CONFIG),
        "firehose": boto3.client("firehose", region_name=region, config=SDK_CONFIG),
    }


def get_account_id(sts_client=None) -> str:
    try:
        c = sts_client or boto3.client("sts", config=SDK_CONFIG)
        return c.get_caller_identity().get("Account", "")
    except Exception:
        return ""
    
ACCOUNT_ID = get_account_id()


def score_confidence(signal_weights: Dict[str, float], evidence_ok: bool = True) -> int:
    """
    Simple confidence score: weighted mean of signals [0..1], scaled to 0..100.
    Example signal_weights: {'cpu_quiet':1.0, 'net_quiet':1.0, 'disk_quiet':0.5, 'health_ok':1.0}
    """
    if not signal_weights:
        return 50
    total_w = sum(max(0.0, w) for w in signal_weights.values())
    if total_w <= 0.0:
        return 50
    weighted = 0.0
    for k, w in signal_weights.items():
        # each value should already be 0..1; clamp just in case
        v = signal_weights.get(k, 0.0)
        v = 0.0 if v < 0 else (1.0 if v > 1 else v)
        weighted += v * w
    base = int(round((weighted / total_w) * 100))
    if not evidence_ok:
        base = max(0, base - 20)
    return max(0, min(100, base))


def pct_to_signal(val_pct: float, threshold_pct: float) -> float:
    """
    Turn 'lower-is-better' metric into a 0..1 signal.
    ≤ threshold => 1.0 (good/quiet); scales down linearly until 0 at 2x threshold.
    """
    if threshold_pct <= 0:
        return 0.0
    if val_pct <= threshold_pct:
        return 1.0
    if val_pct >= 2 * threshold_pct:
        return 0.0
    # linear between threshold and 2*threshold
    return 1.0 - (val_pct - threshold_pct) / float(threshold_pct)


# ===== Profiling helpers =====

PROFILE_FILE = "cleanup_profile.csv"

class CountingCSVWriter:
    """
    Wraps a csv.writer to count how many rows a given check wrote.
    Only counts rows written during that check's execution.
    """
    def __init__(self, inner_writer: csv.writer):
        self._inner = inner_writer
        self.rows = 0

    def writerow(self, row):
        self._inner.writerow(row)
        self.rows += 1


class RunProfiler:
    """
    Collects per-step metrics (duration, rows, ok/error) and can dump to CSV + logs.
    """
    def __init__(self, profile_file: str = PROFILE_FILE):
        self.profile_file = profile_file
        self.records: list[dict[str, Any]] = []
        self.run_start = datetime.now(timezone.utc)

    def add(self, *, step: str, region: str, seconds: float, rows: int,
            ok: bool, error: Optional[str] = None,
            started_at: Optional[datetime] = None,
            ended_at: Optional[datetime] = None):
        self.records.append({
            "TimestampUTC": datetime.now(timezone.utc).isoformat(),
            "Step": step,
            "Region": region,
            "Seconds": round(seconds, 3),
            "RowsWritten": rows,
            "OK": int(bool(ok)),
            "Error": (error or ""),
            "StartedAtUTC": (started_at or (datetime.now(timezone.utc) - timedelta(seconds=seconds))).isoformat(),
            "EndedAtUTC": (ended_at or datetime.now(timezone.utc)).isoformat(),
        })

    def dump_csv(self, path: Optional[str] = None):
        path = path or self.profile_file
        header = ["TimestampUTC", "Step", "Region", "Seconds", "RowsWritten", "OK",
                  "Error", "StartedAtUTC", "EndedAtUTC"]
        file_exists = os.path.exists(path)
        with open(path, "a", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            if not file_exists:
                w.writerow(header)
            for r in self.records:
                w.writerow([r[h] for h in header])

    def log_summary(self, top_n: int = 15):
        if not self.records:
            logging.info("[PROFILE] No records.")
            return
        sorted_recs = sorted(self.records, key=lambda r: r["Seconds"], reverse=True)
        logging.info("[PROFILE] Top %d slowest steps:", min(top_n, len(sorted_recs)))
        for rec in sorted_recs[:top_n]:
            logging.info("  %-40s  %-12s  %6.2fs  rows=%-6d  ok=%s  err=%s",
                         rec["Step"], rec["Region"], rec["Seconds"],
                         rec["RowsWritten"], rec["OK"], rec["Error"])


def run_check(profiler: RunProfiler,
              check_name: str,
              region: str,
              fn: Callable[..., None],
              writer: csv.writer,
              **fn_kwargs) -> int:
    """
    Time a 'check_*' function that writes via our CSV writer. We wrap the writer so
    we can count rows written for this specific check.

    Usage:
        run_check(profiler, "check_xyz", region, check_xyz, writer, arg1=..., arg2=...)
    """
    counting_writer = CountingCSVWriter(inner_writer=writer)
    start_ts = datetime.now(timezone.utc)
    t0 = perf_counter()
    ok, err = True, None
    try:
        fn(counting_writer, **fn_kwargs)
    except Exception as e:
        ok, err = False, f"{type(e).__name__}: {e}"
        raise
    finally:
        dt = perf_counter() - t0
        profiler.add(step=check_name, region=region, seconds=dt, rows=counting_writer.rows,
                     ok=ok, error=err, started_at=start_ts, ended_at=datetime.now(timezone.utc))
        logging.info("[PROFILE] %-40s  %-12s  %6.2fs  rows=%d  ok=%s",
                     check_name, region, dt, counting_writer.rows, ok)
    return counting_writer.rows


def run_step(profiler: RunProfiler,
             step_name: str,
             region: str,
             fn: Callable[..., Any],
             **fn_kwargs) -> Any:
    """
    Time any function (no CSV writing). Useful for preparatory steps like CFN template cache.

    Usage:
        cached = run_step(profiler, "cache_templates", region, cache_all_cfn_templates, cfn=...)
    """
    start_ts = datetime.now(timezone.utc)
    t0 = perf_counter()
    ok, err = True, None
    result = None
    try:
        result = fn(**fn_kwargs)
        return result
    except Exception as e:
        ok, err = False, f"{type(e).__name__}: {e}"
        raise
    finally:
        dt = perf_counter() - t0
        profiler.add(step=step_name, region=region, seconds=dt, rows=0,
                     ok=ok, error=err, started_at=start_ts, ended_at=datetime.now(timezone.utc))
        logging.info("[PROFILE] %-40s  %-12s  %6.2fs  rows=%d  ok=%s",
                     step_name, region, dt, 0, ok)

#endregion

#region Route53 SECTION

@dataclass
class Route53RecordMetadata:
    zone_id: str
    zone_name: str
    record_name: str
    record_type: str
    targets: list[str]
    flags: list[str] = field(default_factory=list)


def resolve_elb_targets(elbv2) -> set[str]:
    """Return set of all ELB DNS names (lowercased, no trailing dot)."""
    lb_dnsnames = set()
    try:
        paginator = elbv2.get_paginator("describe_load_balancers")
        for page in paginator.paginate():
            for lb in page.get("LoadBalancers", []):
                dns = lb.get("DNSName", "")
                if dns:
                    lb_dnsnames.add(dns.rstrip(".").lower())
    except Exception as e:
        logging.warning(f"[resolve_elb_targets] Could not fetch ELB DNS names: {e}")
    return lb_dnsnames


def flag_record(record: dict, lb_dnsnames: set[str], s3) -> list[str]:
    """Return list of flags for a single Route53 record."""
    flags: list[str] = []
    record_type = record.get("Type")
    if record_type not in ("A", "AAAA", "CNAME"):
        return flags

    is_alias = "AliasTarget" in record
    if is_alias:
        targets = [record["AliasTarget"]["DNSName"]]
    else:
        targets = [rr["Value"] for rr in record.get("ResourceRecords", [])]

    targets = [t.rstrip(".").lower() for t in targets if t]

    for target in targets:
        if ".elb.amazonaws.com" in target:
            if lb_dnsnames:
                if target not in lb_dnsnames:
                    flags.append("StaleELBTarget")
            else:
                flags.append("ELBTargetNeedsVerification")

        elif ".s3" in target or "s3-website" in target:
            bucket = target.split(".")[0]
            try:
                s3.head_bucket(Bucket=bucket)
            except Exception:
                flags.append("StaleS3Target")

        elif record_type == "CNAME" and "ec2" in target:
            flags.append("PotentialStaleEC2Target")

    return flags


@retry_with_backoff(exceptions=(ClientError,))
def check_redundant_route53_records(writer: csv.writer, route53, elbv2, s3) -> None:
    """
    Flags potentially redundant or stale Route53 records:
      - ELB targets no longer present
      - S3 bucket targets that no longer exist
      - EC2 private DNS targets in CNAMEs (cannot verify, marked potential)
    
    Writes a CSV row per flagged record.
    """
    try:
        hosted_zones = route53.list_hosted_zones().get("HostedZones", [])
        lb_dnsnames = resolve_elb_targets(elbv2)

        for zone in hosted_zones:
            zone_id = zone["Id"].split("/")[-1]
            zone_name = zone["Name"]
                        
            records = []
            req = {"HostedZoneId": zone_id}
            while True:
                resp = route53.list_resource_record_sets(**req)
                records.extend(resp.get("ResourceRecordSets", []) or [])
                if not resp.get("IsTruncated"):
                    break
                req.update({
                    "StartRecordName": resp.get("NextRecordName"),
                    "StartRecordType": resp.get("NextRecordType"),
                    **({"StartRecordIdentifier": resp.get("NextRecordIdentifier")} 
                        if resp.get("NextRecordIdentifier") else {})
                })

            for record in records:
                rec_flags = flag_record(record, lb_dnsnames, s3)
                if rec_flags:
                    targets = record.get("ResourceRecords") or [record.get("AliasTarget", {}).get("DNSName", "")]
                    for t in targets:
                        t_val = t.get("Value") if isinstance(t, dict) else t
                        write_resource_to_csv(
                            writer=writer,
                            resource_id=record.get("Name", ""),
                            name=t_val or "",
                            owner_id=ACCOUNT_ID,
                            resource_type="Route53Record",
                            flags=rec_flags
                        )

    except ClientError as e:
        logging.error(f"[check_redundant_route53_records] AWS error: {e}")
    except Exception as e:
        logging.error(f"[check_redundant_route53_records] Unexpected error: {e}")

#endregion

#region VPC/TGW SECTION

@retry_with_backoff(exceptions=(ClientError,))
def check_inter_region_vpc_and_tgw_peerings(writer: csv.writer, ec2, cloudwatch) -> None:
    """
    Detect and cost-estimate inter-region VPC Peering and Transit Gateway (TGW) peering attachments.

    For each active inter-region attachment, this function:
      - Calculates monthly outbound transfer in GB using CloudWatch BytesOutToRegion.
      - Estimates monthly transfer cost.
      - Flags potential savings and provides high-level remediation advice.

    Args:
        writer (csv.writer): CSV writer instance.
        ec2: boto3 EC2 client.
        cloudwatch: boto3 CloudWatch client.

    Pricing assumption:
        $0.02 per GB for inter-region data transfer (update to match EDP/regional rates).
    """
    try:
        end = datetime.now(timezone.utc)
        start = end - timedelta(days=VPC_LOOKBACK_DAYS)
        period = 86400  # daily datapoints

        def get_bytes_out(dimensions: list[dict]) -> float:
            """Return total GB over LOOKBACK_DAYS for given CW metric dimensions."""
            namespace = "AWS/TransitGateway" if any(d['Name'].startswith("TransitGateway") for d in dimensions) else "AWS/VPC"
            try:
                resp = cloudwatch.get_metric_statistics(
                    Namespace=namespace,
                    MetricName="BytesOutToRegion",
                    Dimensions=dimensions,
                    StartTime=start,
                    EndTime=end,
                    Period=period,
                    Statistics=["Sum"]
                )
                total_bytes = sum(dp.get("Sum", 0.0) for dp in resp.get("Datapoints", []))
                return total_bytes / (1024**3)  # GB
            except ClientError as e:
                logging.warning(f"[check_inter_region_vpc_and_tgw_peerings] CW metric failed: {e}")
                return 0.0

        # -------- Inter-region VPC Peering --------
        peerings = ec2.describe_vpc_peering_connections().get("VpcPeeringConnections", [])
        for pcx in peerings:
            status = pcx.get("Status", {}).get("Code", "")
            if status != "active":
                continue

            req_region = pcx.get("RequesterVpcInfo", {}).get("Region")
            acc_region = pcx.get("AccepterVpcInfo", {}).get("Region")
            if not req_region or not acc_region or req_region == acc_region:
                continue

            pcx_id = pcx.get("VpcPeeringConnectionId", "")
            gb_out = get_bytes_out([{"Name": "VpcPeeringConnectionId", "Value": pcx_id}])
            est_cost = round(gb_out * get_price("NETWORK", "INTER_REGION_GB"), 2)

            flags = ["InterRegionPeering"]
            if est_cost >= MIN_COST_THRESHOLD:
                flags.append(f"PotentialSaving={est_cost}$")
                flags.append("ReviewPeering:Co-locateWorkloadsOrUseSameRegion")

            write_resource_to_csv(
                writer=writer,
                resource_id=pcx_id,
                name="",
                owner_id=ACCOUNT_ID,
                resource_type="VPCPeeringConnection",
                state=status,
                estimated_cost=est_cost,
                flags=flags
            )

        # -------- Inter-region TGW Peering --------
        try:
            tgw_peerings = ec2.describe_transit_gateway_peering_attachments().get("TransitGatewayPeeringAttachments", [])
        except ClientError:
            tgw_peerings = []

        for tgw in tgw_peerings:
            state = tgw.get("State", "")
            if state != "available":
                continue

            req_region = tgw.get("RequesterTgwInfo", {}).get("Region")
            acc_region = tgw.get("AccepterTgwInfo", {}).get("Region")
            if not req_region or not acc_region or req_region == acc_region:
                continue

            tgw_id = tgw.get("TransitGatewayAttachmentId", "")
            gb_out = get_bytes_out([{"Name": "TransitGatewayAttachmentId", "Value": tgw_id}])
            est_cost = round(gb_out * get_price("NETWORK", "INTER_REGION_GB"), 2)

            flags = ["InterRegionTGWPeering"]
            if est_cost >= MIN_COST_THRESHOLD:
                flags.append(f"PotentialSaving={est_cost}$")
                flags.append("ReviewTGWPeering:ConsiderRegionalConsolidation")

            write_resource_to_csv(
                writer=writer,
                resource_id=tgw_id,
                name="",
                owner_id=ACCOUNT_ID,
                resource_type="TGWPeeringAttachment",
                state=state,
                estimated_cost=est_cost,
                flags=flags
            )

    except ClientError as e:
        logging.error(f"[check_inter_region_vpc_and_tgw_peerings] AWS error: {e}")
    except Exception as e:
        logging.error(f"[check_inter_region_vpc_and_tgw_peerings] Unexpected error: {e}")

#endregion

#region FSR SECTION

@retry_with_backoff(exceptions=(ClientError,))
def check_ebs_fast_snapshot_restore(writer: csv.writer, ec2):
    try:
        resp = ec2.describe_fast_snapshot_restores().get("FastSnapshotRestores", [])
        for fsr in resp:
            snap = fsr.get("SnapshotId","")
            az = fsr.get("AvailabilityZone","")
            state = fsr.get("State","")
            if state != "enabled": 
                continue
            # Cost: per snapshot-AZ hour; emit monthly rough
            monthly = round(get_price("EBS","FSR_PER_AZ_HOUR")*24*30, 2)
            flags = [f"FSREnabled({az})", f"PotentialSaving={monthly}$"]
            write_resource_to_csv(
                writer, snap, "", "EBSFastSnapshotRestore", owner_id=get_account_id(),
                state=state, estimated_cost=monthly, flags=flags
            )
    except ClientError as e:
        logging.error(f"[check_ebs_fast_snapshot_restore] {e}")

#endregion


#region EKS SECTION
@retry_with_backoff(exceptions=(ClientError,))
def check_eks_empty_clusters(writer: csv.writer, eks, ec2) -> None:
    """
    Flag clusters with no nodegroups and no Fargate profiles; estimate control-plane burn.
    """
    try:
        monthly = round(get_price("EKS","CONTROL_PLANE_HOUR")*24*30, 2)
        for page in eks.get_paginator("list_clusters").paginate():
            for name in page.get("clusters", []):
                d = eks.describe_cluster(name=name).get("cluster", {})
                if d.get("status") != "ACTIVE":
                    continue
                ng = eks.list_nodegroups(clusterName=name).get("nodegroups", [])
                fg = eks.list_fargate_profiles(clusterName=name).get("fargateProfileNames", [])
                if not ng and not fg:
                    write_resource_to_csv(
                        writer, d.get("arn", name), name, "EKSCluster", owner_id=ACCOUNT_ID,
                        state=d.get("status",""), estimated_cost=monthly,
                        flags=[f"EmptyEKSCluster", f"PotentialSaving={monthly}$"]
                    )
    except ClientError as e:
        logging.error(f"[check_eks_empty_clusters] {e}")
#endregion

#region EXTENDED SUPPORT

@retry_with_backoff(exceptions=(ClientError,))
def check_rds_extended_support_mysql(writer: csv.writer, rds) -> None:
    """
    Detect RDS MySQL 5.7 and Aurora MySQL 2.x instances under extended support.
    Flags them for upgrade and writes findings to CSV.
    """
    try:
        paginator = rds.get_paginator("describe_db_instances")
        for page in paginator.paginate():
            for db in page.get("DBInstances", []):
                engine = db.get("Engine", "")
                version = db.get("EngineVersion", "")
                db_id = db.get("DBInstanceIdentifier", "")
                arn = db.get("DBInstanceArn", "")
                state = db.get("DBInstanceStatus", "")
                created = db.get("InstanceCreateTime")
                created_str = created.isoformat() if hasattr(created, "isoformat") else ""
                tags = {}
                try:
                    tag_resp = rds.list_tags_for_resource(ResourceName=arn)
                    tags = {t["Key"]: t["Value"] for t in tag_resp.get("TagList", [])}
                except Exception as e:
                    logging.warning(f"[RDS] Tag fetch failed for {db_id}: {e}")

                flags = []
                if engine == "mysql" and version.startswith("5.7"):
                    flags.append("ExtendedSupportMySQL57")
                    flags.append("ConsiderUpgradeToMySQL80")
                elif engine == "aurora-mysql" and version.startswith("5.7."):
                    flags.append("ExtendedSupportAuroraMySQL2")
                    flags.append("ConsiderUpgradeToAuroraMySQL3")
                elif engine == "aurora-mysql" and version.startswith("2."):
                    flags.append("ExtendedSupportAuroraMySQL2")
                    flags.append("ConsiderUpgradeToAuroraMySQL3")

                if flags:
                    write_resource_to_csv(
                        writer=writer,
                        resource_id=db_id,
                        name=db.get("DBName", ""),
                        resource_type="RDSInstance",
                        owner_id=ACCOUNT_ID,
                        state=state,
                        creation_date=created_str,
                        estimated_cost="",
                        app_id=tags.get("ApplicationID", "NULL"),
                        app=tags.get("Application", "NULL"),
                        env=tags.get("Environment", "NULL"),
                        flags=flags
                    )
                    logging.info(f"[RDS] {db_id} flagged: {flags}")
    except ClientError as e:
        logging.error(f"[check_rds_extended_support_mysql] AWS error: {e}")
    except Exception as e:
        logging.error(f"[check_rds_extended_support_mysql] Unexpected error: {e}")

#endregion

def main():
    """
    Orchestrate the analysis, write findings to cleanup_estimates.csv,
    and profile every check into cleanup_profile.csv.
    """
    profiler = RunProfiler(profile_file=PROFILE_FILE)


    try:
        file_exists = os.path.exists(OUTPUT_FILE)
        with open(OUTPUT_FILE, "a", newline="", encoding="utf-8") as csvfile:
            writer = csv.writer(csvfile)
            if not file_exists:
                writer.writerow([
                    "Resource_ID", "Name", "ResourceType", "OwnerId", "State", "Creation_Date",
                    "Storage_GB", "Object_Count", "Estimated_Cost_USD", "Potential_Saving_USD",
                    "ApplicationID", "Application", "Environment", "ReferencedIn",
                    "FlaggedForReview", "Confidence", "Signals"
                ])


            checkers_config.setup(
            account_id=ACCOUNT_ID,
            write_row=write_resource_to_csv,
            get_price=get_price,
            logger=LOGGER,
            )

            # -------- Global / cross-region steps first
            try:
                s3_global = boto3.client("s3", config=SDK_CONFIG)
                cloudwatch_global = boto3.client("cloudwatch", config=SDK_CONFIG)
                cloudfront_global = boto3.client("cloudfront", config=SDK_CONFIG)
                region="GLOBAL"
            except Exception as e:
                logging.error(f"[main] Failed to create global S3 client: {e}")
                s3_global = boto3.client("s3")  # fallback
                cloudfront_global = boto3.client("cloudfront")
                cloudwatch_global = boto3.client("cloudwatch")


            run_check(
                profiler,
                "check_s3_public_buckets",
                region,
                s3_checks.check_s3_public_buckets,
                writer=writer,
                s3=s3_global,
                cloudwatch=cloudwatch_global,
            )

            run_check(
                profiler,
                "check_s3_buckets_without_default_encryption",
                region,
                s3_checks.check_s3_buckets_without_default_encryption,
                writer=writer,
                s3=s3_global,
                cloudwatch=cloudwatch_global,
            )

            run_check(
                profiler,
                "check_s3_versioned_without_lifecycle",
                region,
                s3_checks.check_s3_versioned_without_lifecycle,
                writer=writer,
                s3=s3_global,
                cloudwatch=cloudwatch_global,
            )

            run_check(
                profiler,
                "check_s3_buckets_without_lifecycle",
                region,
                s3_checks.check_s3_buckets_without_lifecycle,
                writer=writer,
                s3=s3_global,
                cloudwatch=cloudwatch_global,
            )

            run_check(
                profiler,
                "check_s3_empty_buckets",
                region,
                s3_checks.check_s3_empty_buckets,
                writer=writer,
                s3=s3_global,
                cloudwatch=cloudwatch_global,
            )

            run_check(
                profiler,
                "check_s3_ia_tiering_candidates",
                region,
                s3_checks.check_s3_ia_tiering_candidates,
                writer=writer,
                s3=s3_global,
                cloudwatch=cloudwatch_global,
                # knobs: lookback_days=30, min_standard_gb=50, request_threshold=1000
            )

            run_check(
                profiler,
                "check_s3_stale_multipart_uploads",
                region,
                s3_checks.check_s3_stale_multipart_uploads,
                writer=writer,
                s3=s3_global,
                cloudwatch=cloudwatch_global,
                # knobs: stale_days=7
            )

            # -------- Per-region steps
            for region in REGIONS:
                logging.info(f"Running cleanup for region: {region}")
                try:
                    clients = init_clients(region)
                except Exception as e:
                    logging.error(f"[main] init_clients({region}) failed: {e}")
                    continue

                #correlator WIP
                #regions = REGIONS
                #graph = build_certificate_graph(regions=regions, account_id=ACCOUNT_ID)
                #cert_summary = summarize_cert_usage(graph)

                run_check(
                    profiler, check_name="check_unused_elastic_ips",
                    region=region, fn=eip, writer=writer, ec2=clients["ec2"],
                )

                run_check(
                    profiler, check_name="eni",
                    region=region, fn=eni, writer=writer, ec2=clients["ec2"],
                )

                run_check(profiler, check_name="check_unused_efs_filesystems", region=region,
                          fn=check_unused_efs_filesystems, writer=writer,
                          efs=clients['efs'], cloudwatch=clients['cloudwatch'])
                
                run_check(profiler, "check_backup_plans_without_selections", 
                          region, backup_checks.check_backup_plans_without_selections, writer=writer, 
                          backup=clients["backup"])
                run_check(profiler, "check_backup_rules_no_lifecycle",      
                          region, backup_checks.check_backup_rules_no_lifecycle, writer=writer, 
                          backup=clients["backup"])
                run_check(profiler, "check_backup_stale_recovery_points",   
                          region, backup_checks.check_backup_stale_recovery_points, writer=writer, 
                          backup=clients["backup"])

                run_check(
                    profiler,
                    "check_fsx_low_activity_filesystems",
                    region,
                    fsx_checks.check_fsx_low_activity_filesystems,
                    writer=writer,
                    fsx=clients["fsx"],
                    cloudwatch=clients["cloudwatch"],
                    # knobs: lookback_days=14, io_threshold_bytes=1_000_000_000
                )

                run_check(
                    profiler,
                    "check_fsx_high_free_capacity",
                    region,
                    fsx_checks.check_fsx_high_free_capacity,
                    writer=writer,
                    fsx=clients["fsx"],
                    cloudwatch=clients["cloudwatch"],
                    # knobs: lookback_days=3, free_pct_threshold=0.70
                )

                run_check(
                    profiler,
                    "check_fsx_old_backups",
                    region,
                    fsx_checks.check_fsx_old_backups,
                    writer=writer,
                    fsx=clients["fsx"],
                    cloudwatch=clients["cloudwatch"],
                    # knobs: stale_days=30
                )


                # Route 53 is global, ELB is regional; leave as-is but profile per region invocation
                run_check(profiler, check_name="check_redundant_route53_records", region=region,
                          fn=check_redundant_route53_records, writer=writer,
                          route53=clients['route53'], elbv2=clients['elbv2'], s3=clients['s3'])

                run_check(
                    profiler, "check_lambda_unused_functions",
                    region, lambda_checks.check_lambda_unused_functions,
                    writer=writer, lambda_client=clients["lambda"], 
                    cloudwatch=clients["cloudwatch"],
                )

                run_check(
                    profiler, "check_lambda_provisioned_concurrency_underutilized",
                    region, lambda_checks.check_lambda_provisioned_concurrency_underutilized,
                    writer=writer, lambda_client=clients["lambda"], 
                    cloudwatch=clients["cloudwatch"],
                    # knobs: lookback_days=14, util_threshold=0.05
                )

                run_check(
                    profiler, "check_lambda_runtime_deprecated",
                    region, lambda_checks.check_lambda_runtime_deprecated,
                    writer=writer, lambda_client=clients["lambda"],
                    cloudwatch=clients["cloudwatch"],
                )

                run_check(
                    profiler, "check_lambda_large_packages",
                    region, lambda_checks.check_lambda_large_packages,
                    writer=writer, lambda_client=clients["lambda"],
                    cloudwatch=clients["cloudwatch"],
                    # knobs: size_threshold_mb=50
                )

                run_check(
                    profiler, "check_lambda_old_functions",
                    region, lambda_checks.check_lambda_old_functions,
                    writer=writer, lambda_client=clients["lambda"], 
                    cloudwatch=clients["cloudwatch"],
                    # knobs: age_days=180
                )

                run_check(profiler, check_name="check_inter_region_vpc_and_tgw_peerings",
                          region=region, fn=check_inter_region_vpc_and_tgw_peerings,
                          writer=writer, ec2=clients['ec2'], cloudwatch=clients['cloudwatch'])

                run_check(profiler, "check_ecr_repositories_without_lifecycle_policy", region,
                        ecr_checks.check_ecr_repositories_without_lifecycle_policy,
                        writer=writer, ecr=clients["ecr"])

                run_check(profiler, "check_ecr_empty_repositories", region,
                        ecr_checks.check_ecr_empty_repositories,
                        writer=writer, ecr=clients["ecr"])

                run_check(profiler, "check_ecr_stale_or_untagged_images", region,
                        ecr_checks.check_ecr_stale_or_untagged_images,
                        writer=writer, ecr=clients["ecr"])

                run_check(profiler, check_name="check_ebs_fast_snapshot_restore", region=region,
                          fn=check_ebs_fast_snapshot_restore, writer=writer, ec2=clients['ec2'])

                run_check(profiler, check_name="check_eks_empty_clusters", region=region,
                          fn=check_eks_empty_clusters, writer=writer,
                          eks=clients['eks'], ec2=clients['ec2'])

                run_check(profiler, "check_unattached_ebs_volumes",
                          region, ebs_checks.check_unattached_ebs_volumes, writer=writer,
                          ec2=clients["ec2"], cloudwatch=clients["cloudwatch"])

                run_check(profiler, "check_ebs_low_activity_volumes",
                          region, ebs_checks.check_ebs_low_activity_volumes, writer=writer,
                          ec2=clients["ec2"], cloudwatch=clients["cloudwatch"])

                run_check(profiler, "check_ebs_gp2_to_gp3_migration",
                          region, ebs_checks.check_ebs_gp2_to_gp3_migration, writer=writer,
                          ec2=clients["ec2"], cloudwatch=clients["cloudwatch"])

                run_check(profiler, "check_ebs_snapshots_old_or_orphaned", region,
                          ebs_checks.check_ebs_snapshots_old_or_orphaned, writer=writer,
                          ec2=clients["ec2"], cloudwatch=clients["cloudwatch"])


                run_check(
                    profiler,
                    "check_acm_expiring_certificates",
                    region,
                    acm_checks.check_acm_expiring_certificates,
                    writer=writer,
                    acm=clients["acm"],
                    # knobs: days=30
                )

                run_check(
                    profiler,
                    "check_acm_unused_certificates",
                    region,
                    acm_checks.check_acm_unused_certificates,
                    writer=writer,
                    acm=clients["acm"],
                )

                run_check(
                    profiler,
                    "check_acm_validation_issues",
                    region,
                    acm_checks.check_acm_validation_issues,
                    writer=writer,
                    acm=clients["acm"],
                )

                run_check(
                    profiler,
                    "check_acm_renewal_problems",
                    region,
                    acm_checks.check_acm_renewal_problems,
                    writer=writer,
                    acm=clients["acm"],
                )
                #TODO: ignore slave instances (sap db)
                run_check(
                    profiler,
                    "check_ec2_underutilized_instances",
                    region,
                    ec2_checks.check_ec2_underutilized_instances,
                    writer=writer,
                    ec2=clients["ec2"],
                    cloudwatch=clients["cloudwatch"],
                    # knobs: lookback_days=14, cpu_avg_threshold=5.0, cpu_max_threshold=10.0,
                    #        net_avg_bps_threshold=100_000
                )

                run_check(
                    profiler,
                    "check_ec2_stopped_instances",
                    region,
                    ec2_checks.check_ec2_stopped_instances,
                    writer=writer,
                    ec2=clients["ec2"],
                    cloudwatch=clients["cloudwatch"],
                    # knobs: stale_days=14
                )

                run_check(
                    profiler,
                    "check_ec2_old_generation_instances",
                    region,
                    ec2_checks.check_ec2_old_generation_instances,
                    writer=writer,
                    ec2=clients["ec2"],
                    cloudwatch=clients["cloudwatch"],
                )

                run_check(
                    profiler,
                    "check_ec2_unused_security_groups",
                    region,
                    ec2_checks.check_ec2_unused_security_groups,
                    writer=writer,
                    ec2=clients["ec2"],
                    cloudwatch=clients["cloudwatch"],
                )

                # CloudFront is global; no impact to put it in the region loop
                run_check(profiler, check_name="check_cloudfront_idle_distributions", region=region,
                          fn=check_cloudfront_distributions, writer=writer,
                          cloudfront=clients['cloudfront'], cloudwatch=clients['cloudwatch'])

                run_check(profiler, check_name="check_rds_extended_support_mysql", region=region,
                          fn=check_rds_extended_support_mysql, writer=writer, rds=clients['rds'])

                run_check(profiler, check_name="check_private_certificate_authorities",
                region=region,fn=check_private_certificate_authorities,
                writer=writer, acmpca=clients["acm-pca"])

                run_check(profiler=profiler, check_name="check_kms_customer_managed_keys", 
                          region=region, fn=check_kms_customer_managed_keys, writer=writer, 
                          cloudtrail=clients['cloudtrail'], kms=clients['kms'])
                          # lookback_days=90,  # optional override

                run_check(profiler, "check_ssm_plaintext_parameters", region,
                          ssm_checks.check_ssm_plaintext_parameters,
                          writer=writer, ssm=clients["ssm"])
                run_check(profiler, "check_ssm_stale_parameters", region,
                          ssm_checks.check_ssm_stale_parameters,
                          writer=writer, ssm=clients["ssm"])
                run_check(profiler, "check_ssm_maintenance_windows_gaps", region,
                          ssm_checks.check_ssm_maintenance_windows_gaps,
                          writer=writer, ssm=clients["ssm"])

                run_check(profiler, check_name="check_nat_gateways",
                          region=region, fn=check_nat_gateways, writer=writer,
                          ec2=clients["ec2"], cloudwatch=clients["cloudwatch"],
                    # lookback_days=30,  # optional override
                )

                run_check(profiler, "check_kinesis_data_streams", region,
                          kinesis_checks.check_kinesis_data_streams,
                          writer=writer, kinesis=clients["kinesis"],
                          cloudwatch=clients["cloudwatch"])

                run_check(profiler, "check_firehose_delivery_streams",
                          region, kinesis_checks.check_firehose_delivery_streams,
                          writer=writer, firehose=clients["firehose"],
                          cloudwatch=clients["cloudwatch"])
                
                run_check(profiler, "check_dynamodb_unused_tables", region,
                          ddb_checks.check_dynamodb_unused_tables, writer=writer,
                          dynamodb=clients["dynamodb"], cloudwatch=clients["cloudwatch"])
                run_check(profiler, "check_dynamodb_underutilized_provisioned", region,
                          ddb_checks.check_dynamodb_underutilized_provisioned, writer=writer,
                          dynamodb=clients["dynamodb"], cloudwatch=clients["cloudwatch"])
                run_check(profiler, "check_dynamodb_continuous_backups", region,
                          ddb_checks.check_dynamodb_continuous_backups, writer=writer,
                          dynamodb=clients["dynamodb"], cloudwatch=clients["cloudwatch"])
                run_check(profiler, "check_dynamodb_gsi_underutilized", region,
                          ddb_checks.check_dynamodb_gsi_underutilized, writer=writer,
                          dynamodb=clients["dynamodb"], cloudwatch=clients["cloudwatch"])
                run_check(profiler, "check_dynamodb_streams_enabled_no_consumers", region,
                          ddb_checks.check_dynamodb_streams_enabled_no_consumers, writer=writer,
                          dynamodb=clients["dynamodb"], cloudwatch=clients["cloudwatch"],
                          dynamodbstreams=clients.get("dynamodbstreams"))
                run_check(profiler, "check_dynamodb_ttl_disabled", region,
                          ddb_checks.check_dynamodb_ttl_disabled, writer=writer,
                          dynamodb=clients["dynamodb"], cloudwatch=clients["cloudwatch"])
                run_check(profiler, "check_dynamodb_table_class_mismatch", region,
                          ddb_checks.check_dynamodb_table_class_mismatch, writer=writer,
                          dynamodb=clients["dynamodb"], cloudwatch=clients["cloudwatch"])
                run_check(profiler, "check_dynamodb_global_tables_low_activity", region,
                          ddb_checks.check_dynamodb_global_tables_low_activity, writer=writer,
                          dynamodb=clients["dynamodb"], cloudwatch=clients["cloudwatch"])
                
                run_check(profiler, "check_ebs_snapshots_public_or_shared", region,
                          ebs_checks.check_ebs_snapshots_public_or_shared, writer=writer,
                          ec2=clients["ec2"], cloudwatch=clients["cloudwatch"])
                run_check(profiler, "check_ebs_snapshots_unencrypted", region,
                          ebs_checks.check_ebs_snapshots_unencrypted, writer=writer,
                          ec2=clients["ec2"], cloudwatch=clients["cloudwatch"])
                run_check(profiler, "check_ebs_snapshots_missing_description", region,
                          ebs_checks.check_ebs_snapshots_missing_description, writer=writer,
                          ec2=clients["ec2"], cloudwatch=clients["cloudwatch"])
                
                run_check(
                            profiler, "check_ami_public_or_shared",
                            region, ami_checks.check_ami_public_or_shared,
                            writer=writer, ec2=clients["ec2"],)

                run_check(
                            profiler, "check_ami_unused_and_snapshot_cost",
                            region, ami_checks.check_ami_unused_and_snapshot_cost,
                            writer=writer, ec2=clients["ec2"],
                            autoscaling=clients.get("autoscaling"),  # optional
                            # knobs: min_age_days=14
                        )

                run_check(
                            profiler, "check_ami_old_images",
                            region, ami_checks.check_ami_old_images,
                            writer=writer, ec2=clients["ec2"],
                            # knobs: age_days=180
                        )

                run_check(profiler, "check_ami_unencrypted_snapshots",
                          region, ami_checks.check_ami_unencrypted_snapshots,
                          writer=writer, ec2=clients["ec2"],)

                run_check(
                    profiler, "check_loggroups_no_retention", region,
                    lg_checks.check_loggroups_no_retention, writer=writer,
                    logs=clients["logs"], cloudwatch=clients["cloudwatch"],
                )

                run_check(
                    profiler, "check_loggroups_stale", region,
                    lg_checks.check_loggroups_stale, writer=writer,
                    logs=clients["logs"], cloudwatch=clients["cloudwatch"],
                    # knobs: lookback_days=14
                )

                run_check(
                    profiler, "check_loggroups_large_storage",
                    region, lg_checks.check_loggroups_large_storage,
                    writer=writer, logs=clients["logs"], cloudwatch=clients["cloudwatch"],
                    # knobs: min_gb=50.0
                )

                run_check(
                    profiler, "check_loggroups_unencrypted", region,
                    lg_checks.check_loggroups_unencrypted, writer=writer,
                    logs=clients["logs"], cloudwatch=clients["cloudwatch"],
                )


                run_check(
                    profiler, "check_rds_manual_snapshots_old", region,
                    rds_snaps.check_rds_manual_snapshots_old,
                    writer=writer, rds=clients["rds"],
                    # knobs: stale_days=30
                )

                run_check(
                    profiler, "check_rds_snapshots_public_or_shared", region,
                    rds_snaps.check_rds_snapshots_public_or_shared,
                    writer=writer, rds=clients["rds"],
                )

                run_check(
                    profiler, "check_rds_snapshots_unencrypted", region,
                    rds_snaps.check_rds_snapshots_unencrypted,
                    writer=writer, rds=clients["rds"],
                )

                run_check(
                    profiler, "check_rds_snapshots_orphaned",
                    region, rds_snaps.check_rds_snapshots_orphaned,
                    writer=writer, rds=clients["rds"],
                )

                run_check(
                    profiler, "check_elbv2_idle_load_balancers",
                    region, lb_checks.check_elbv2_idle_load_balancers,
                    writer=writer, elbv2=clients["elbv2"],
                    cloudwatch=clients["cloudwatch"],
                    # knobs: lookback_days=14, min_requests=10, min_processed_bytes=10_000_000
                )

                run_check(
                    profiler, "check_elbv2_no_registered_targets",
                    region, lb_checks.check_elbv2_no_registered_targets,
                    writer=writer, elbv2=clients["elbv2"], cloudwatch=clients["cloudwatch"],
                )

                run_check(
                    profiler, "check_elbv2_unused_target_groups",
                    region, lb_checks.check_elbv2_unused_target_groups, writer=writer,
                    elbv2=clients["elbv2"], cloudwatch=clients["cloudwatch"],
                )

                run_check(
                    profiler,
                    "check_wafv2_unassociated_web_acls",
                    region,
                    waf_checks.check_wafv2_unassociated_web_acls,
                    writer=writer,
                    wafv2=clients["wafv2"],
                    # knobs: include_cloudfront=False
                )

                run_check(
                    profiler,
                    "check_wafv2_logging_disabled",
                    region,
                    waf_checks.check_wafv2_logging_disabled,
                    writer=writer,
                    wafv2=clients["wafv2"],
                )

                run_check(
                    profiler,
                    "check_wafv2_rules_no_matches",
                    region,
                    waf_checks.check_wafv2_rules_no_matches,
                    writer=writer,
                    wafv2=clients["wafv2"],
                    cloudwatch=clients["cloudwatch"],
                    # knobs: lookback_days=14, include_cloudfront=False
                )

                run_check(
                    profiler,
                    "check_wafv2_empty_acl_associated",
                    region,
                    waf_checks.check_wafv2_empty_acl_associated,
                    writer=writer,
                    wafv2=clients["wafv2"],
                )


        profiler.dump_csv()
        profiler.log_summary(top_n=30)
        logging.info(f"CSV export complete: {OUTPUT_FILE}")
        logging.info(f"Profile export complete: {PROFILE_FILE}")

    except Exception as e:
        logging.error(f"[main] Fatal error: {e}")

if __name__ == "__main__":
    main()
