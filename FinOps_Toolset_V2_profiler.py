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
import boto3 # type: ignore
import csv
import os
import logging
from typing import Dict, Iterable, Optional, List, Tuple, Union, Callable, Any, TypeVar, Set, Type
from datetime import datetime, timezone, timedelta
import json
from botocore.exceptions import ClientError # type: ignore
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from statistics import fmean
from enum import Enum
import string
import re
from time import perf_counter
import threading
#from correlator import build_certificate_graph, summarize_cert_usage

from finops_toolset.config import (
    SDK_CONFIG,
    REGIONS, OUTPUT_FILE, LOG_FILE, BATCH_SIZE, REQUIRED_TAG_KEYS,
    _S3_MPU_BUCKET_WORKERS, _S3_MPU_PART_WORKERS, _S3_MPU_PAGE_SIZE,
    _S3_MPU_GLOBAL_FINDINGS_CAP, _S3_MPU_PARTS_MODE,
    DDB_LOOKBACK_DAYS, DDB_CW_PERIOD, DDB_BACKUP_AGE_DAYS, HOURS_PER_MONTH,
    LAMBDA_LOOKBACK_DAYS, LAMBDA_ERROR_RATE_THRESHOLD, LAMBDA_LOW_CONCURRENCY_THRESHOLD,
    LAMBDA_LOW_TRAFFIC_THRESHOLD, LAMBDA_LARGE_PACKAGE_MB,
    LAMBDA_LOW_PROVISIONED_UTILIZATION, LAMBDA_VERSION_SPRAWL_THRESHOLD,
    VPC_LOOKBACK_DAYS, MIN_COST_THRESHOLD,
    EC2_LOOKBACK_DAYS, EC2_CW_PERIOD, EC2_IDLE_CPU_PCT, EC2_IDLE_NET_GB, EC2_IDLE_DISK_OPS,
    LOAD_BALANCER_LOOKBACK_DAYS,
)

from finops_toolset.pricing import PRICING, get_price
import core.cloudwatch as cw
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
#endregion

# Configure logging
logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)

#logger = logging.getLogger("aws-finops")  # base logger for your script


#region CW Helpers

# ---------- CloudWatch Bulk (GetMetricData) ----------

def _ebs_mdq_id(volume_id: str, metric: str, stat: str = "Sum") -> str:
    # Build a stable, CW-safe id (reuses your _cw_make_id helper)
    return _cw_make_id("ebs", volume_id, metric, stat)

def _ebs_build_mdqs(vol_ids: list[str],
                    need_bytes: set[str],
                    need_ops: set[str],
                    period: int = 86400) -> tuple[list[dict], dict[tuple[str, str], str]]:
    """
    Build MetricDataQueries for a set of volumes:
      - need_bytes: VolumeIds that require (ReadBytes, WriteBytes)
      - need_ops:   VolumeIds that require (ReadOps, WriteOps)
    Returns (queries, id_index) where id_index[(vol_id, metric)] -> mdq_id
    """
    queries: list[dict] = []
    id_index: dict[tuple[str, str], str] = {}
    for vid in vol_ids:
        dims = [{"Name": "VolumeId", "Value": vid}]
        if vid in need_bytes:
            for metric in ("VolumeReadBytes", "VolumeWriteBytes"):
                qid = _ebs_mdq_id(vid, metric, "Sum")
                queries.append(build_mdq(
                    id_hint=qid, namespace="AWS/EBS", metric=metric,
                    dims=dims, stat="Sum", period=period
                ))
                id_index[(vid, metric)] = qid
        if vid in need_ops:
            for metric in ("VolumeReadOps", "VolumeWriteOps"):
                qid = _ebs_mdq_id(vid, metric, "Sum")
                queries.append(build_mdq(
                    id_hint=qid, namespace="AWS/EBS", metric=metric,
                    dims=dims, stat="Sum", period=period
                ))
                id_index[(vid, metric)] = qid
    return queries, id_index

def _ebs_collect_cw(cloudwatch_region: str,
                    mdqs: list[dict],
                    start: datetime,
                    end: datetime,
                    scan_by: str = "TimestampAscending") -> dict[str, list[tuple[datetime, float]]]:
    """
    Create a thread-local CloudWatch client (to be safe) and run a single GetMetricData
    batch for the given MDQs. Returns id -> [(ts, value), ...].
    """
    cw_local = boto3.client("cloudwatch", region_name=cloudwatch_region, config=SDK_CONFIG)
    return cw_get_metric_data_bulk(cw_local, mdqs, start, end, scan_by=scan_by)

def _sum_values(series: list[tuple[datetime, float]]) -> float:
    return float(sum(v for _, v in (series or [])))

def _cw_id_safe(s: str) -> str:
    """CloudWatch MetricDataQuery.Id must be [a-zA-Z0-9_]."""
    return "".join(ch if (ch.isalnum() or ch == "_") else "_" for ch in s)[:255]


def _cw_make_id(*parts: str, max_len: int = 255) -> str:
    """
    Build a CloudWatch MetricDataQuery Id that matches ^[a-z][a-zA-Z0-9_]*$.

    - Joins the given parts, lowercases them.
    - Replaces any non [a-z0-9_] char with underscore.
    - Ensures the first character is a lowercase letter by prefixing 'a' if needed.
    - Collapses repeated underscores and trims to `max_len`.

    Args:
        *parts: Pieces to combine into an Id (e.g., prefixes and resource names).
        max_len: Maximum length of the resulting Id (CW allows up to 255).

    Returns:
        A safe Id string usable in GetMetricData.
    """
    raw = "_".join(p for p in parts if p is not None).lower()

    allowed = set(string.ascii_lowercase + string.digits + "_")
    cleaned_chars = []
    prev_us = False
    for ch in raw:
        if ch in allowed:
            cleaned_chars.append(ch)
            prev_us = (ch == "_")
        else:
            # replace with single underscore
            if not prev_us:
                cleaned_chars.append("_")
                prev_us = True
    safe = "".join(cleaned_chars).strip("_")

    if not safe or safe[0] not in string.ascii_lowercase:
        safe = "a_" + safe

    # final collapse and trim
    while "__" in safe:
        safe = safe.replace("__", "_")
    if len(safe) > max_len:
        safe = safe[:max_len]
    return safe


def build_mdq(
    *,
    id_hint: str,
    namespace: str,
    metric: str,
    dims: list[dict],
    stat: str,
    period: int,
    unit: Optional[str] = None,
) -> dict:
    """Build a single MetricDataQuery for GetMetricData."""
    mdq_id = _cw_id_safe(id_hint)
    q = {
        "Id": mdq_id,
        "MetricStat": {
            "Metric": {
                "Namespace": namespace,
                "MetricName": metric,
                "Dimensions": dims,
            },
            "Period": period,
            "Stat": stat,
        },
        "ReturnData": True,
    }
    if unit:
        q["MetricStat"]["Unit"] = unit
    return q

def cw_get_metric_data_bulk(
    cloudwatch,
    queries: list[dict],
    start: datetime,
    end: datetime,
    scan_by: str = "TimestampAscending",
    max_batch: int = 500,
) -> dict[str, list[tuple[datetime, float]]]:
    """
    Execute GetMetricData in batches (<=500 MDQs per call), handling NextToken.
    Returns: mapping id -> [(timestamp, value), ...] in ascending time order.
    """
    results: dict[str, list[tuple[datetime, float]]] = {}
    if not queries:
        return results

    for i in range(0, len(queries), max_batch):
        batch = queries[i : i + max_batch]
        next_token = None
        while True:
            kwargs = {
                "MetricDataQueries": batch,
                "StartTime": start,
                "EndTime": end,
                "ScanBy": scan_by,
            }
            if next_token:
                kwargs["NextToken"] = next_token
            resp = cloudwatch.get_metric_data(**kwargs)
            for r in resp.get("MetricDataResults", []):
                rid = r.get("Id")
                if not rid:
                    continue
                pts = list(zip(r.get("Timestamps", []), r.get("Values", [])))
                # CloudWatch may return timestamps unordered without ScanBy; we set ScanBy but sort anyway
                pts.sort(key=lambda x: x[0])
                results.setdefault(rid, []).extend((ts, float(val)) for ts, val in pts)
            next_token = resp.get("NextToken")
            if not next_token:
                break

    # Ensure each id is strictly time-ascending and merged (if multiple pages)
    for rid, pts in results.items():
        pts.sort(key=lambda x: x[0])
        results[rid] = pts
    return results

def series_sum(values: list[float]) -> float:
    return float(sum(values))

def series_avg(values: list[float]) -> float:
    return float(fmean(values)) if values else 0.0

def series_p95(values: list[float]) -> float:
    if not values:
        return 0.0
    s = sorted(values)
    idx = int(round(0.95 * (len(s) - 1)))
    return float(s[idx])

#endregion


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

def init_clients(region: str):
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


def _region_of(client) -> str:
    return getattr(getattr(client, "meta", None), "region_name", "") or ""

#endregion

#region POO SECTION

class ResourceFlagger:
    def __init__(self, tags: Dict[str, str], last_modified: Optional[datetime] = None):
        self.tags = tags
        self.last_modified = last_modified
        self.flags = []

    def check_missing_tags(self, required_keys: List[str]):
        if not all(self.tags.get(k) for k in required_keys):
            self.flags.append("MissingRequiredTags")

    def check_age(self, threshold_days: int = 91):
        if self.last_modified and self.last_modified < datetime.now(timezone.utc) - timedelta(days=threshold_days):
            self.flags.append("OlderThan3Months")

    def get_flags(self) -> List[str]:
        return self.flags

class AMIFlagger(ResourceFlagger):
    def __init__(self, tags: Dict[str, str], creation_date: str, referenced: str, shared: str):
        super().__init__(tags)
        self.creation_date_str = creation_date
        self.referenced = referenced
        self.shared = shared

    def apply_rules(self):
        self.check_missing_tags(REQUIRED_TAG_KEYS)
        self.check_creation_date()
        self.check_reference()
        self.check_shared()

    def check_creation_date(self):
        try:
            creation_dt = datetime.strptime(self.creation_date_str, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=timezone.utc)
            self.last_modified = creation_dt
            self.check_age()
        except Exception:
            pass

    def check_reference(self):
        if self.referenced == "No":
            self.flags.append("Unreferenced")

    def check_shared(self):
        if self.shared == "Yes":
            self.flags.append("SharedExternally")

#endregion

#region LB SECTION

_T = TypeVar("_T")
LOGGER = logging.getLogger(__name__)
LOGGER.addHandler(logging.NullHandler())

ExceptionTypes = Union[Type[BaseException], Tuple[Type[BaseException], ...]]

def _normalize_swallow(swallow: Optional[ExceptionTypes]) -> Tuple[Type[BaseException], ...]:
    """Normalize the `swallow` argument to a tuple of exception classes.

    - None  -> (Exception,)
    - Class -> (Class,)
    - Tuple -> Tuple (validated)
    """
    if swallow is None:
        return (Exception,)  # catch broad exceptions by default
    if isinstance(swallow, type) and issubclass(swallow, BaseException):
        return (swallow,)
    if isinstance(swallow, tuple) and all(isinstance(t, type) and issubclass(t, BaseException) for t in swallow):
        return swallow
    # Fallback to broad catch if a bad value is passed
    return (Exception,)

def safe_aws_call(
    func: Callable[[], _T],
    *,
    default: Optional[_T] = None,
    context: str = "",
    fallback: Optional[_T] = None,
    swallow: Optional[ExceptionTypes] = None,
    logger: Optional[logging.Logger] = None,
) -> Optional[_T]:
    """Run ``func()`` and return its value, or a default/fallback on exception.

    Args:
        func: Zero-arg callable to execute.
        default: Preferred value when an exception is raised.
        context: Short label for logs (e.g., 'ec2.describe_instances').
        fallback: Secondary value if ``default`` is None (kept for backward compatibility).
        swallow: Exception class or tuple of classes to catch. Defaults to ``Exception``.
        logger: Optional logger (defaults to this module's ``LOGGER``).

    Returns:
        The function's return value on success; otherwise ``default`` if provided,
        else ``fallback`` (which may be ``None``).
    """
    log = logger or LOGGER
    catch: Tuple[Type[BaseException], ...] = _normalize_swallow(swallow)
    try:
        return func()
    except catch as exc:  # pylint: disable=broad-exception-caught
        log.debug("safe_aws_call(%s) failed: %s", context, exc, exc_info=True)
        return default if default is not None else fallback


def estimate_lb_cost(lb_type: str, region: Optional[str] = None) -> float:
    """Return monthly base cost for a load balancer, based on hourly pricing."""
    t = (lb_type or "").lower()
    key = "ALB" if t in ("application", "alb") else ("NLB" if t in ("network", "nlb") else "CLB")
    hourly_price = get_price(key, "HOUR", region=region)
    return round(float(hourly_price) * 24 * 30, 2)


def check_idle_load_balancers(
    writer,
    elbv2,       # boto3.client('elbv2') for THIS region (orchestrator-provided)
    cloudwatch,  # boto3.client('cloudwatch') for THIS region (orchestrator-provided)
) -> None:
    """
    LB checker using CloudWatch batcher with cross-AZ transfer detection.
    - Supports both ALB and NLB.
    - Adds per-AZ ProcessedBytes to detect skew when cross-zone is enabled.
    - Appends flags: 'cross_az_transfer_high', 'disable_cross_zone_candidate' (conservative).
    - Estimated cost is not asserted here (to avoid pricing regressions). Potential saving is provided for cross-AZ only.
    """
    try:
        region = (
            getattr(getattr(cloudwatch, "meta", None), "region_name", "")
            or getattr(getattr(elbv2, "meta", None), "region_name", "")
            or ""
        )

        now = datetime.now(timezone.utc)
        lookback_days = max(1, LOAD_BALANCER_LOOKBACK_DAYS)  # from config.py
        start = now - timedelta(days=lookback_days)
        PERIOD = 300  # 5 min granularity is reasonable for ELB metrics

        # ---------- 1) list LBs (ALB + NLB) ----------
        load_balancers = []
        marker = None
        while True:
            try:
                kwargs = {"Marker": marker} if marker else {}
                resp = elbv2.describe_load_balancers(**kwargs)
            except ClientError as e:
                logging.error(f"[ELB] describe_load_balancers failed in {region}: {e}")
                break
            load_balancers.extend(resp.get("LoadBalancers", []) or [])
            marker = resp.get("NextMarker")
            if not marker:
                break

        if not load_balancers:
            return

        # ---------- 2) tags ----------
        arn_to_tags: Dict[str, Dict[str, str]] = {}
        try:
            # elbv2.describe_tags supports up to 20 arns per call
            for i in range(0, len(load_balancers), 20):
                chunk = load_balancers[i:i+20]
                arns = [lb["LoadBalancerArn"] for lb in chunk]
                try:
                    tresp = elbv2.describe_tags(ResourceArns=arns) or {}
                    for td in (tresp.get("TagDescriptions") or []):
                        tmap = {t.get("Key",""): t.get("Value","") for t in (td.get("Tags") or [])}
                        arn_to_tags[td.get("ResourceArn","")] = tmap
                except ClientError:
                    for a in arns:
                        arn_to_tags[a] = {}
        except Exception:
            pass

        # ---------- 3) attributes (for cross-zone) ----------
        lb_attrs: Dict[str, Dict[str, str]] = {}
        for lb in load_balancers:
            arn = lb["LoadBalancerArn"]
            try:
                aresp = elbv2.describe_load_balancer_attributes(LoadBalancerArn=arn)
                lb_attrs[arn] = {kv["Key"]: kv["Value"] for kv in (aresp.get("Attributes") or [])}
            except ClientError:
                lb_attrs[arn] = {}
            except Exception:
                lb_attrs[arn] = {}

        # ---------- 4) batch CloudWatch metrics ----------
        batch = cw.CloudWatchBatcher(region, client=cloudwatch)

        for lb in load_balancers:
            arn = lb["LoadBalancerArn"]
            lb_id = arn.split("/", 1)[-1]  # CW dimension value
            lb_type = (lb.get("Type") or "").lower()  # 'application' | 'network' | 'gateway'

            if lb_type not in ("application", "network"):
                continue  # skip GWLB here

            namespace = "AWS/ApplicationELB" if lb_type == "application" else "AWS/NetworkELB"

            # Total processed bytes for idle heuristics & magnitude
            dims_lb = [{"Name": "LoadBalancer", "Value": lb_id}]
            batch.add_q(id_hint=f"lb_bytes__{lb_id}", namespace=namespace, metric="ProcessedBytes",
                        dims=dims_lb, stat="Sum", period=PERIOD)

            # Requests (ALB only) — harmless to skip for NLB
            if lb_type == "application":
                batch.add_q(id_hint=f"alb_req__{lb_id}", namespace="AWS/ApplicationELB",
                            metric="RequestCount", dims=dims_lb, stat="Sum", period=PERIOD)

            # Per-AZ ProcessedBytes for skew & cross-zone analysis
            az_list = [az.get("ZoneName") for az in (lb.get("AvailabilityZones") or []) if az.get("ZoneName")]
            for az in az_list:
                dims_az = [{"Name": "LoadBalancer", "Value": lb_id}, {"Name": "AvailabilityZone", "Value": az}]
                batch.add_q(id_hint=f"lb_bytes_az__{lb_id}__{az}", namespace=namespace,
                            metric="ProcessedBytes", dims=dims_az, stat="Sum", period=PERIOD)

        try:
            series = batch.execute(start, now, scan_by="TimestampDescending")
        except Exception as e:
            logging.exception(f"[ELB] CloudWatch batch execute failed in {region}: {e}")
            series = {}

        # ---------- 5) pricing (optional, only for cross-AZ potential) ----------
        try:
            inter_az_price = get_price("NETWORK", "INTER_AZ_GB", region)
        except Exception:
            inter_az_price = None
        if inter_az_price is None:
            try:
                inter_az_price = get_price("NETWORK", "INTER_REGION_GB", region)
            except Exception:
                inter_az_price = 0.0

        # ---------- 6) emit rows ----------
        for lb in load_balancers:
            try:
                arn = lb["LoadBalancerArn"]
                lb_id = arn.split("/", 1)[-1]
                lb_name = lb.get("LoadBalancerName", lb_id)
                lb_type = (lb.get("Type") or "").lower()
                if lb_type not in ("application", "network"):
                    continue

                namespace = "AWS/ApplicationELB" if lb_type == "application" else "AWS/NetworkELB"
                state = (lb.get("State") or {}).get("Code", "")
                created = lb.get("CreatedTime") or now
                if hasattr(created, "tzinfo") and created.tzinfo is None:
                    created = created.replace(tzinfo=timezone.utc)
                created_iso = created.astimezone(timezone.utc).isoformat()

                tags = arn_to_tags.get(arn, {})
                name = tags.get("Name", lb_name)

                # Aggregate totals
                total_bytes = float(sum(v for _, v in series.get(f"lb_bytes__{lb_id}", [])))
                total_gb = total_bytes / (1024.0 ** 3)

                req_sum = 0.0
                if lb_type == "application":
                    req_sum = float(sum(v for _, v in series.get(f"alb_req__{lb_id}", [])))

                # Flags & signals
                flags: List[str] = []
                missing = [k for k in REQUIRED_TAG_KEYS if not tags.get(k)]
                if missing:
                    flags.append(f"MissingRequiredTags={','.join(missing)}")

                # Extremely conservative idle indicator (no thresholds from config -> zero-traffic only)
                is_idle = (total_bytes == 0.0) and ((req_sum == 0.0) if lb_type == "application" else True) and state.lower() == "active"
                if is_idle:
                    flags += ["idle_load_balancer_candidate", "confidence=100"]
                    confidence = 100
                    potential_saving = None  # we do not assert LB pricing here
                else:
                    confidence = None
                    potential_saving = None

                # Cross-zone analysis
                attrs = lb_attrs.get(arn, {})
                cross_zone = (
                    str(attrs.get("load_balancing.cross_zone.enabled", "false")).lower() == "true"
                    or str(attrs.get("routing.cross-zone.enabled", "false")).lower() == "true"
                )

                az_list = [az.get("ZoneName") for az in (lb.get("AvailabilityZones") or []) if az.get("ZoneName")]
                az_bytes = []
                for az in az_list:
                    sid = f"lb_bytes_az__{lb_id}__{az}"
                    az_sum = float(sum(v for _, v in series.get(sid, [])))
                    az_bytes.append((az, az_sum))

                worst = float(max((b for _, b in az_bytes), default=0.0))
                skew = (worst / total_bytes) if total_bytes > 0 else 0.0

                if cross_zone and total_bytes > 0 and skew >= 0.70:
                    flags.append("cross_az_transfer_high")
                    flags.append("disable_cross_zone_candidate")
                    # Potential saving (conservative): (skew-0.5) fraction of bytes as avoidable cross-AZ
                    avoidable_gb = max(0.0, (skew - 0.5)) * total_gb
                    potential_xaz = round(avoidable_gb * float(inter_az_price), 2) if inter_az_price > 0 else None
                    if potential_xaz:
                        potential_saving = (potential_saving or 0.0) + potential_xaz
                        potential_saving = round(potential_saving, 2)

                # Signals (compact)
                signals = {
                    "Region": region,
                    "Type": lb_type,
                    "CrossZone": str(cross_zone).lower(),
                    "AZSkew": f"{skew:.3f}",
                    f"BytesGB{lookback_days}d": f"{total_gb:.3f}",
                }
                if lb_type == "application":
                    signals[f"Requests{lookback_days}d"] = f"{int(req_sum)}"

                # Estimated cost left unchanged here to avoid regression; keep as blank string
                write_resource_to_csv(
                    writer=writer,
                    resource_id=arn,
                    name=name,
                    resource_type="ALB" if lb_type == "application" else "NLB",
                    owner_id=ACCOUNT_ID,
                    state=state,
                    creation_date=created_iso,
                    storage_gb="",                 # n/a
                    estimated_cost="",             # avoid pricing regression
                    app_id=tags.get("ApplicationID", "NULL"),
                    app=tags.get("Application", "NULL"),
                    env=tags.get("Environment", "NULL"),
                    referenced_in="",
                    flags=flags,
                    object_count="",               # n/a
                    potential_saving=potential_saving,
                    confidence=confidence,
                    signals=signals,
                )

            except Exception as e:
                logging.exception(f"[ELB] emit failed for {lb.get('LoadBalancerName','?')} in {region}: {e}")

    except Exception as e:
        logging.exception(f"[ELB] check_idle_load_balancers_refactored failed: {e}")
        return

#endregion


#region LAMBDA SECTION

# ---------- Flags ----------
class LambdaFlag(str, Enum):
    NO_INVOCATIONS = "NoInvocations90d"
    LOW_TRAFFIC = "LowTraffic"
    HIGH_ERROR_RATE = "HighErrorRate"
    LARGE_PACKAGE = "LargePackage"
    LOW_CONCURRENCY = "LowConcurrencyUsage"
    UNDERUTILIZED_PROV_CONC = "UnderutilizedProvisionedConcurrency"
    TMP_USAGE = "TmpUsageHeuristic"
    OVERPROVISIONED_MEMORY = "OverProvisionedMemory"
    POTENTIAL_SAVING = "PotentialSaving"
    STALE_LAYER = "StaleLayer"
    VERSION_SPRAWL = "VersionSprawl"


@dataclass
class LambdaMetadata:
    arn: str
    name: str
    runtime: str
    memory_mb: int
    ephemeral_mb: int
    code_size: int
    creation_date: str
    total_invocations: int
    total_errors: int
    avg_duration_ms: float
    p95_duration_ms: float
    avg_concurrency: float
    max_concurrency: float
    avg_prov_util: float
    estimated_cost: float
    flags: set[str] = field(default_factory=set)


# ---------- Heuristic checks ----------
def check_low_traffic(fn: LambdaMetadata) -> list[str]:
    if fn.total_invocations == 0:
        return [LambdaFlag.NO_INVOCATIONS.value]
    est_month_inv = round(fn.total_invocations * (30 / max(1, LAMBDA_LOOKBACK_DAYS)))
    if est_month_inv < LAMBDA_LOW_TRAFFIC_THRESHOLD:
        return [f"{LambdaFlag.LOW_TRAFFIC.value}={est_month_inv}/mo"]
    return []


def check_high_error_rate(fn: LambdaMetadata) -> list[str]:
    if fn.total_invocations > 0 and (fn.total_errors / fn.total_invocations) > LAMBDA_ERROR_RATE_THRESHOLD:
        return [LambdaFlag.HIGH_ERROR_RATE.value]
    return []


def check_large_package(fn: LambdaMetadata) -> list[str]:
    if fn.code_size >= LAMBDA_LARGE_PACKAGE_MB * 1024 * 1024:
        return [f"{LambdaFlag.LARGE_PACKAGE.value}≈{round(fn.code_size/1024/1024,1)}MB"]
    return []


def check_low_concurrency(fn: LambdaMetadata) -> list[str]:
    if fn.avg_concurrency < LAMBDA_LOW_CONCURRENCY_THRESHOLD:
        return [LambdaFlag.LOW_CONCURRENCY.value]
    return []


def check_underutilized_prov_conc(fn: LambdaMetadata) -> list[str]:
    if fn.avg_prov_util < LAMBDA_LOW_PROVISIONED_UTILIZATION:
        return [LambdaFlag.UNDERUTILIZED_PROV_CONC.value]
    return []


def check_tmp_usage(fn: LambdaMetadata) -> list[str]:
    if fn.ephemeral_mb > 512 and fn.p95_duration_ms > 2000:
        return [f"{LambdaFlag.TMP_USAGE.value}(ephemeral={fn.ephemeral_mb}MB,p95Dur≈{int(fn.p95_duration_ms)}ms)"]
    return []


def check_memory_rightsizing(fn: LambdaMetadata) -> list[str]:
    if fn.memory_mb >= 1024 and fn.p95_duration_ms <= 500 and fn.total_invocations > 0:
        suggested = max(128, fn.memory_mb // 2 // 128 * 128)
        if suggested < fn.memory_mb:
            new_mem_gb = suggested / 1024.0
            avg_duration_sec = fn.avg_duration_ms / 1000.0
            potential_saving = (fn.memory_mb/1024.0 - new_mem_gb) * fn.total_invocations * avg_duration_sec * get_price("LAMBDA", "GB_SECOND")
            return [
                f"{LambdaFlag.OVERPROVISIONED_MEMORY.value}(cur={fn.memory_mb}MB,->~{suggested}MB)",
                f"{LambdaFlag.POTENTIAL_SAVING.value}={round(potential_saving,2)}$"
            ]
    return []


def check_layers(fn: LambdaMetadata, lambda_client=None) -> list[str]:
    flags = []
    if not lambda_client:
        return flags
    try:
        config = lambda_client.get_function_configuration(FunctionName=fn.name)
        for layer in config.get("Layers", []):
            arn = layer.get("Arn", "")
            if arn and ":1" in arn:
                flags.append(f"{LambdaFlag.STALE_LAYER.value}={arn.split(':')[-2:]}")
    except Exception as e:
        logging.warning(f"[Lambda:{fn.name}] Layer check failed: {e}")
    return flags


def check_version_sprawl(fn: LambdaMetadata, lambda_client=None) -> list[str]:
    flags = []
    if not lambda_client:
        return flags
    try:
        versions = lambda_client.list_versions_by_function(FunctionName=fn.name).get("Versions", [])
        if len(versions) > LAMBDA_VERSION_SPRAWL_THRESHOLD:
            flags.append(f"{LambdaFlag.VERSION_SPRAWL.value}={len(versions)}")
    except Exception as e:
        logging.warning(f"[Lambda:{fn.name}] Version sprawl check failed: {e}")
    return flags


# ---------- Check registry ----------
LAMBDA_CHECKS: list[Callable[[LambdaMetadata], list[str]]] = [
    check_low_traffic,
    check_high_error_rate,
    check_large_package,
    check_low_concurrency,
    check_underutilized_prov_conc,
    check_tmp_usage,
    check_memory_rightsizing,
]


# ---------- Cost estimation ----------
def estimate_lambda_cost(fn: LambdaMetadata) -> float:
    avg_duration_sec = fn.avg_duration_ms / 1000.0
    memory_gb = fn.memory_mb / 1024.0
    gb_seconds = fn.total_invocations * avg_duration_sec * memory_gb
    return round(
        gb_seconds * get_price("LAMBDA", "GB_SECOND")
        + (fn.total_invocations / 1_000_000.0 * get_price("LAMBDA", "REQUESTS_PER_MILLION")),
        4,
    )


def check_lambda_efficiency(writer: csv.writer, lambda_client, cloudwatch) -> None:
    """
    Analyze AWS Lambda functions for cost efficiency and rightsizing opportunities.

    This check:
      • Enumerates all Lambda functions in the region (via list_functions).
      • Pulls CloudWatch metrics over the last LAMBDA_LOOKBACK_DAYS:
          - Invocations (Sum)
          - Errors (Sum)
          - Duration (Average, Maximum)
          - ConcurrentExecutions (Average, Maximum)
          - ProvisionedConcurrencyUtilization (Average)
      • Derives per-function statistics:
          - Total invocations & errors
          - Average duration (ms) and p95 duration (ms)
          - Average & max concurrency
          - Average provisioned concurrency utilization
      • Estimates monthly Lambda cost using GB-seconds + request count.
      • Applies heuristic flags:
          - NoInvocations90d / LowTraffic
          - HighErrorRate
          - LargePackage
          - LowConcurrencyUsage
          - UnderutilizedProvisionedConcurrency
          - TmpUsageHeuristic
          - OverProvisionedMemory (with PotentialSaving=$)
          - StaleLayer
          - VersionSprawl

    Output:
        Writes one CSV row per function that has flags or non-zero estimated cost:
            - Function ARN, name, creation date
            - Estimated monthly cost (USD)
            - List of optimization / compliance flags

    Args:
        writer (csv.writer): Active CSV writer instance for appending findings.
        lambda_client: boto3 Lambda client (regional).
        cloudwatch: boto3 CloudWatch client (regional).

    Error handling:
        • API calls are wrapped with retry_with_backoff to mitigate throttling.
        • Individual function errors are logged and skipped (processing continues).
    """

    try:
        region = (
            getattr(getattr(cloudwatch, "meta", None), "region_name", "")
            or getattr(getattr(lambda_client, "meta", None), "region_name", "")
            or ""
        )

        now = datetime.now(timezone.utc)
        lookback_days = max(1, LAMBDA_LOOKBACK_DAYS)
        start = now - timedelta(days=lookback_days)
        PERIOD = 300  # 5m buckets — good balance for Duration averages

        # 1) List functions (paginated)
        funcs = []
        token = None
        while True:
            try:
                kwargs = {"Marker": token} if token else {}
                resp = lambda_client.list_functions(**kwargs)
            except ClientError as e:
                logging.error(f"[Lambda] list_functions failed in {region}: {e}")
                break
            funcs.extend(resp.get("Functions", []))
            token = resp.get("NextMarker")
            if not token:
                break

        if not funcs:
            return

        # 2) Pre-fetch tags (best effort) and (optionally) version counts
        def _tags(arn: str) -> Dict[str, str]:
            try:
                t = lambda_client.list_tags(Resource=arn).get("Tags", {})
                # Tags API returns dict already
                return {str(k): str(v) for k, v in t.items()}
            except ClientError:
                return {}
            except Exception:
                return {}

        # 3) Batch CloudWatch metrics for all functions
        batch = cw.CloudWatchBatcher(region, client=cloudwatch)
        for f in funcs:
            fname = f.get("FunctionName", "")
            dims = [{"Name": "FunctionName", "Value": fname}]
            batch.add_q(id_hint=f"lam_inv__{fname}", namespace="AWS/Lambda", metric="Invocations", dims=dims, stat="Sum",     period=PERIOD)
            batch.add_q(id_hint=f"lam_err__{fname}", namespace="AWS/Lambda", metric="Errors",      dims=dims, stat="Sum",     period=PERIOD)
            batch.add_q(id_hint=f"lam_thr__{fname}", namespace="AWS/Lambda", metric="Throttles",   dims=dims, stat="Sum",     period=PERIOD)
            batch.add_q(id_hint=f"lam_dur__{fname}", namespace="AWS/Lambda", metric="Duration",    dims=dims, stat="Average", period=PERIOD)


        try:
            series = batch.execute(start, now, scan_by="TimestampDescending")
        except Exception as e:
            logging.exception(f"[Lambda] CloudWatch batch execute failed in {region}: {e}")
            series = {}

        # 4) Pricing constants
        try:
            req_per_million = get_price("LAMBDA", "REQUESTS_PER_MILLION")
        except Exception:
            req_per_million = 0.20
        try:
            gb_second = get_price("LAMBDA", "GB_SECOND")
        except Exception:
            gb_second = 0.0000166667

        # 5) Emit rows
        for f in funcs:
            try:
                arn = f.get("FunctionArn", "")
                fname = f.get("FunctionName", arn or "lambda")
                runtime = f.get("Runtime", "")
                memory_mb = int(f.get("MemorySize", 0) or 0)
                timeout_s = int(f.get("Timeout", 0) or 0)
                archs = f.get("Architectures", []) or []
                arch = archs[0] if archs else "x86_64"
                code_size = int(f.get("CodeSize", 0) or 0)
                pkg_type = f.get("PackageType", "Zip")
                created = f.get("LastModified", "")  # often '2023-05-22T12:34:56.000+0000'
                try:
                    if created:
                        created_dt = datetime.fromisoformat(created.replace("Z", "+00:00")) if "T" in created else now
                    else:
                        created_dt = now
                except Exception:
                    created_dt = now
                if created_dt.tzinfo is None:
                    created_dt = created_dt.replace(tzinfo=timezone.utc)
                created_iso = created_dt.astimezone(timezone.utc).isoformat()

                tags = _tags(arn)
                name = tags.get("Name", fname)

                # Metrics
                fname = f.get("FunctionName", "")

                inv_sum  = sum(v for _, v in series.get(f"lam_inv__{fname}", []))
                err_sum  = sum(v for _, v in series.get(f"lam_err__{fname}", []))
                thr_sum  = sum(v for _, v in series.get(f"lam_thr__{fname}", []))
                dur_vals = [v for _, v in series.get(f"lam_dur__{fname}", [])]
                avg_ms   = (sum(dur_vals) / len(dur_vals)) if dur_vals else 0.0

                try:
                    large_pkg_flag = check_large_package(code_size_bytes=code_size, layers=f.get("Layers", []), threshold_mb=LAMBDA_LARGE_PACKAGE_MB)
                except Exception:
                    large_pkg_flag = False

                # Low traffic?
                try:
                    low_traffic_flag = check_low_traffic(total_invocations=inv_sum, threshold=LAMBDA_LOW_TRAFFIC_THRESHOLD)
                except Exception:
                    low_traffic_flag = (inv_sum <= LAMBDA_LOW_TRAFFIC_THRESHOLD)

                # Error rate?
                try:
                    err_rate, high_error_flag = check_high_error_rate(invocations=inv_sum, errors=err_sum, threshold=LAMBDA_ERROR_RATE_THRESHOLD)
                except Exception:
                    err_rate = (err_sum / inv_sum) if inv_sum > 0 else 0.0
                    high_error_flag = (err_rate >= LAMBDA_ERROR_RATE_THRESHOLD)

                # Low concurrency (heuristic via throttles == 0 and low invocations)
                try:
                    low_conc_flag = check_low_concurrency(invocations=inv_sum, throttles=thr_sum, threshold=LAMBDA_LOW_CONCURRENCY_THRESHOLD)
                except Exception:
                    low_conc_flag = (inv_sum <= (LAMBDA_LOW_CONCURRENCY_THRESHOLD * lookback_days * 60 * 60))  # fallback, harmless

                # Version sprawl (optional)
                try:
                    sprawl_flag = check_version_sprawl(lambda_client, function_name=fname, threshold=LAMBDA_VERSION_SPRAWL_THRESHOLD)
                except Exception:
                    sprawl_flag = False

                # ARM64 candidate (helper, if you have it)
                arm64_flag = (arch == "x86_64" and isinstance(runtime, str) and runtime.startswith(("python", "nodejs", "java", "dotnet")))

                # --- Cost estimation (requests + GB-seconds) ---
                #   GB-seconds = invocations * (avg_ms/1000) * (memory_mb/1024)
                gb_seconds = inv_sum * (avg_ms / 1000.0) * max(0.0, float(memory_mb) / 1024.0)
                compute_cost = gb_seconds * gb_second
                request_cost = (inv_sum / 1_000_000.0) * req_per_million
                est_monthly = round(compute_cost + request_cost, 2)

                # Flags & confidence
                flags: List[str] = []
                missing = [k for k in REQUIRED_TAG_KEYS if not tags.get(k)]
                if missing:
                    flags.append(f"MissingRequiredTags={','.join(missing)}")
                if large_pkg_flag:
                    flags.append("lambda_large_package")
                if low_traffic_flag:
                    flags.append("lambda_low_traffic")
                if high_error_flag:
                    flags.append("lambda_high_error_rate")
                if low_conc_flag:
                    flags.append("lambda_low_concurrency")
                if sprawl_flag:
                    flags.append("lambda_version_sprawl")
                if arm64_flag:
                    flags.append("lambda_arm64_candidate")

                # Potential saving: optional; left None unless you have a dedicated estimator
                potential = None

                signals = {
                    "Region": region,
                    "Runtime": runtime,
                    "Arch": arch,
                    "MemoryMB": str(memory_mb),
                    "TimeoutSec": str(timeout_s),
                    f"Invocations{lookback_days}d": str(int(inv_sum)),
                    f"Errors{lookback_days}d": str(int(err_sum)),
                    f"Throttles{lookback_days}d": str(int(thr_sum)),
                    "AvgDurationMs": f"{avg_ms:.2f}",
                    "ErrorRate": f"{err_rate:.4f}",
                    "LookbackDays": str(lookback_days),
                }

                write_resource_to_csv(
                    writer=writer,
                    resource_id=arn,
                    name=name,
                    resource_type="LambdaFunction",
                    owner_id=ACCOUNT_ID,
                    state="",
                    creation_date=created_iso,
                    estimated_cost=est_monthly,  # requests + GB-seconds
                    app_id=tags.get("ApplicationID", "NULL"),
                    app=tags.get("Application", "NULL"),
                    env=tags.get("Environment", "NULL"),
                    flags=flags,
                    potential_saving=potential,
                    signals=signals,
                )
            except Exception as e:
                logging.exception(f"[Lambda] emit failed for {f.get('FunctionName','?')} in {region}: {e}")

    except Exception as e:
        logging.exception(f"[Lambda] check_lambda_functions_refactored failed: {e}")
        return

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


#region FSX SECTION

@dataclass
class FSxBackupMetadata:
    id: str
    fs_id: str
    creation_date: str
    lifecycle: str
    size_gb: int
    tags: Dict[str, str] = field(default_factory=dict)


def estimate_fsx_backup_cost(size_gb: int) -> float:
    """Compute monthly storage cost for FSx backups."""
    price_per_gb = get_price("FSX", "BACKUP_GB_MONTH") or get_price("EBS", "SNAPSHOT_GB_MONTH")
    return round(size_gb * price_per_gb, 2) if price_per_gb else 0.0


def build_fsx_backup_metadata(backup: dict) -> FSxBackupMetadata:
    """Extracts metadata for an FSx backup."""
    backup_id = backup.get("BackupId", "")
    fs_id = backup.get("FileSystemId", "")
    creation_time = backup.get("CreationTime")
    lifecycle = backup.get("Lifecycle", "")
    size_gb = int(backup.get("VolumeCapacity", 0) or 0)
    tags = {t.get("Key", ""): t.get("Value", "") for t in backup.get("Tags", [])}

    return FSxBackupMetadata(
        id=backup_id,
        fs_id=fs_id,
        creation_date=creation_time.isoformat() if hasattr(creation_time, "isoformat") else str(creation_time),
        lifecycle=lifecycle,
        size_gb=size_gb,
        tags=tags,
    )

@retry_with_backoff(exceptions=(ClientError,))
def check_orphaned_fsx_backups(writer: csv.writer, fsx):
    """
    Check for FSx backups that are not associated with any existing FSx file system.
    Logs and writes orphaned backups to the CSV.
    """
    try:
        # Collect existing FSx file systems (with pagination)
        existing_fs_ids: set[str] = set()
        paginator_fs = fsx.get_paginator("describe_file_systems")
        for page in paginator_fs.paginate():
            for fs in page.get("FileSystems", []):
                existing_fs_ids.add(fs.get("FileSystemId", ""))

        # Iterate through backups (with pagination)
        paginator_bk = fsx.get_paginator("describe_backups")
        for page in paginator_bk.paginate():
            for raw_backup in page.get("Backups", []):
                metadata = build_fsx_backup_metadata(raw_backup)

                if metadata.fs_id not in existing_fs_ids:
                    estimated_cost = estimate_fsx_backup_cost(metadata.size_gb)

                    logging.info(
                        f"[FSx] Orphaned backup: {metadata.id}, size={metadata.size_gb}GB, "
                        f"lifecycle={metadata.lifecycle}, estCost≈{estimated_cost}$"
                    )

                    write_resource_to_csv(
                        writer=writer,
                        resource_id=metadata.id,
                        name=metadata.tags.get("Name", ""),
                        owner_id=ACCOUNT_ID,
                        resource_type="FSxBackup",
                        creation_date=metadata.creation_date,
                        storage_gb=metadata.size_gb,
                        estimated_cost=estimated_cost,
                        app_id=metadata.tags.get("ApplicationID", "NULL"),
                        app=metadata.tags.get("Application", "NULL"),
                        env=metadata.tags.get("Environment", "NULL"),
                        flags=[f"OrphanedFSxBackup(lifecycle={metadata.lifecycle})"],
                        confidence=100
                    )

    except ClientError as e:
        logging.error(f"[check_orphaned_fsx_backups] AWS API error: {e.response['Error'].get('Code')}")
    except Exception as e:
        logging.error(f"[check_orphaned_fsx_backups] fatal error: {e}")

#endregion


#region LogGroups SECTION

@dataclass
class LogGroupMetadata:
    name: str
    stored_bytes: int
    size_gb: float
    estimated_cost: float
    flags: list[str] = field(default_factory=list)
    creation_date: str = ""


def build_log_group_metadata(log_group: dict) -> LogGroupMetadata:
    """Construct metadata for a single CloudWatch log group."""
    name = log_group.get("logGroupName", "")
    stored_bytes = int(log_group.get("storedBytes", 0) or 0)
    size_gb = round(stored_bytes / (1024 ** 3), 2)
    estimated_cost = round(size_gb * get_price("CLOUDWATCH", "LOG_GB_MONTH"), 2)

    creation_ms = log_group.get("creationTime")
    creation_date_str = ""
    if isinstance(creation_ms, int):
        creation_date_str = datetime.fromtimestamp(creation_ms / 1000, tz=timezone.utc).isoformat()

    flags = []
    if log_group.get("retentionInDays") is None:
        flags.append("InfiniteRetention")
        # Heuristic: assume ~70% potential saving if retention reduced to 90 days
        if estimated_cost > 0:
            potential_saving = round(estimated_cost * 0.7, 2)
            flags.append(f"PotentialSaving={potential_saving}$")

    return LogGroupMetadata(
        name=name,
        stored_bytes=stored_bytes,
        size_gb=size_gb,
        estimated_cost=estimated_cost,
        flags=flags,
        creation_date=creation_date_str
    )


@retry_with_backoff(exceptions=(ClientError,))
def check_log_groups_with_infinite_retention(writer: csv.writer, logs) -> None:
    """
    Identify CloudWatch Log Groups with infinite retention.

    - Flags groups without a retention policy.
    - Estimates monthly storage cost.
    - Estimates potential savings (~70%) if retention were reduced to 90 days.
    - Writes results to CSV.

    Args:
        writer (csv.writer): CSV writer instance.
        logs: boto3 CloudWatch Logs client.

    CloudWatch Logs Pricing:
        $0.03 per GB-month for log storage (PRICING['CLOUDWATCH']['LOG_GB_MONTH'])
    """
    try:
        paginator = logs.get_paginator("describe_log_groups")
        for page in paginator.paginate():
            for lg in page.get("logGroups", []):
                metadata = build_log_group_metadata(lg)
                if metadata.flags:
                    write_resource_to_csv(
                        writer=writer,
                        resource_id="",
                        name=metadata.name,
                        owner_id=ACCOUNT_ID,
                        resource_type="CloudWatchLogGroup",
                        creation_date=metadata.creation_date,
                        storage_gb=metadata.size_gb,
                        estimated_cost=metadata.estimated_cost,
                        flags=metadata.flags
                    )
                    logging.info(
                        f"[check_log_groups_with_infinite_retention] "
                        f"{metadata.name} size={metadata.size_gb}GB cost≈{metadata.estimated_cost}$ flags={metadata.flags}"
                    )
    except ClientError as e:
        logging.error(f"[check_log_groups_with_infinite_retention] AWS error: {e}")
    except Exception as e:
        logging.error(f"[check_log_groups_with_infinite_retention] Unexpected error: {e}")

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

#region WAFV2 SECTION

@dataclass
class WAFV2WebACLMetadata:
    name: str
    arn: str
    acl_id: str
    scope: str
    monthly_cost: float
    flags: Set[str] = field(default_factory=set)


def estimate_wafv2_web_acl_cost() -> float:
    """Return the base monthly cost for a Web ACL."""
    return get_price("WAFV2", "WEBACL_MONTH")


def check_unassociated_waf_acl(acl: WAFV2WebACLMetadata, wafv2) -> List[str]:
    """Flag Web ACLs with no associated resources."""
    assoc = safe_aws_call(
        lambda: wafv2.list_resources_for_web_acl(WebACLArn=acl.arn),
        fallback={"ResourceArns": []},
        context=f"WAFv2:{acl.name}:ListResources"
    )
    resources = assoc.get("ResourceArns", [])
    if not resources:
        flags = [f"UnassociatedWebACL(scope={acl.scope})"]
        if acl.monthly_cost > 0:
            flags.append(f"PotentialSaving={acl.monthly_cost}$")
        return flags
    return []


@retry_with_backoff(exceptions=(ClientError,))
def check_wafv2_unassociated_acls(writer: csv.writer, wafv2, region_name: str) -> None:
    """
    Identify unassociated WAFv2 Web ACLs and write potential savings to CSV.
    Handles REGIONAL and CLOUDFRONT scopes (CLOUDFRONT only in us-east-1).
    """
    try:
        scopes = ["REGIONAL"]
        if region_name == "us-east-1":
            scopes.append("CLOUDFRONT")

        for scope in scopes:
            next_marker = None
            while True:
                params = {"Scope": scope, "Limit": 100}
                if next_marker:
                    params["NextMarker"] = next_marker

                resp = safe_aws_call(
                    lambda: wafv2.list_web_acls(**params),
                    fallback={"WebACLs": []},
                    context=f"WAFv2:{scope}:ListWebACLs"
                )

                for acl in resp.get("WebACLs", []):
                    metadata = WAFV2WebACLMetadata(
                        name=acl.get("Name", ""),
                        arn=acl.get("ARN", ""),
                        acl_id=acl.get("Id", ""),
                        scope=scope,
                        monthly_cost=estimate_wafv2_web_acl_cost(),
                    )

                    metadata.flags.update(check_unassociated_waf_acl(metadata, wafv2))

                    sig_region = "global" if scope == "CLOUDFRONT" else region_name

                    if metadata.flags:
                        write_resource_to_csv(
                            writer=writer,
                            resource_id=metadata.acl_id,
                            name=metadata.name,
                            resource_type="WAFv2WebACL",
                            owner_id=ACCOUNT_ID,
                            state=metadata.scope,
                            estimated_cost=metadata.monthly_cost,
                            flags=list(metadata.flags),
                            confidence=100,
                            signals={"Region": sig_region, "Scope": scope}
                        )
                        logging.info(f"[WAF:{metadata.name}] flags={metadata.flags} estCost≈${metadata.monthly_cost}")

                next_marker = resp.get("NextMarker")
                if not next_marker:
                    break

    except ClientError as e:
        logging.error(f"[check_wafv2_unassociated_acls] AWS error: {e}")


#endregion


#region RDS SNAPSHOT SECTION

@dataclass
class RDSSnapshotMetadata:
    snapshot_id: str
    db_instance_id: str
    snapshot_type: str
    creation_date: str
    allocated_gb: int
    age_days: int
    monthly_cost: float
    flags: Set[str] = field(default_factory=set)


def estimate_rds_snapshot_cost(allocated_gb: int) -> float:
    """Estimate monthly storage cost of a snapshot based on GB allocated."""
    price_per_gb = get_price("RDS", "BACKUP_GB_MONTH") or 0.0
    return round(allocated_gb * price_per_gb, 2)


def build_rds_snapshot_metadata(s: Dict[str, Any]) -> RDSSnapshotMetadata:
    sid = s.get("DBSnapshotIdentifier", "")
    dbid = s.get("DBInstanceIdentifier", "")
    stype = s.get("SnapshotType", "unknown")
    ctime = s.get("SnapshotCreateTime")
    alloc_gb = int(s.get("AllocatedStorage", 0) or 0)

    age_days = None
    if isinstance(ctime, datetime):
        age_days = (datetime.now(timezone.utc) - ctime).days
    created_str = ctime.isoformat() if hasattr(ctime, "isoformat") else str(ctime or "")

    monthly_cost = estimate_rds_snapshot_cost(alloc_gb)

    return RDSSnapshotMetadata(
        snapshot_id=sid,
        db_instance_id=dbid,
        snapshot_type=stype,
        creation_date=created_str,
        allocated_gb=alloc_gb,
        age_days=age_days or 0,
        monthly_cost=monthly_cost,
    )


# === Checks ===

def check_rds_snapshot_old(snapshot: RDSSnapshotMetadata, cutoff_days: int = 90) -> List[str]:
    if snapshot.snapshot_type == "manual" and snapshot.age_days > cutoff_days:
        return [f"OldManualSnapshot>{snapshot.age_days}d"]
    return []


def check_rds_snapshot_orphaned(snapshot: RDSSnapshotMetadata, active_instances: Set[str]) -> List[str]:
    if snapshot.db_instance_id and snapshot.db_instance_id not in active_instances:
        return [f"Orphaned{snapshot.snapshot_type.capitalize()}Snapshot"]
    return []


def check_rds_snapshot_idle_auto(snapshot: RDSSnapshotMetadata, cutoff_days: int = 30) -> List[str]:
    """
    Automated snapshots:
      - flag if instance gone (already caught by orphan check)
      - OR if age > cutoff (unexpected accumulation).
    """
    if snapshot.snapshot_type == "automated" and snapshot.age_days > cutoff_days:
        return [f"OldAutomatedSnapshot>{snapshot.age_days}d"]
    return []


# registry of checks (context-dependent ones handled in driver)
RDS_SNAPSHOT_CHECKS: List[Callable[..., List[str]]] = [
    check_rds_snapshot_old,
    check_rds_snapshot_idle_auto,
]


@retry_with_backoff(exceptions=(ClientError,))
def check_rds_snapshots(writer: csv.writer, rds) -> None:
    """
    Flags RDS snapshots that are:
      - old manual (>90d)
      - old automated (>30d, unusual accumulation)
      - orphaned from any DB instance

    Writes flagged snapshots with estimated storage cost.
    """
    try:
        # collect all instance IDs for orphaned check
        instances: Set[str] = set()
        for page in rds.get_paginator("describe_db_instances").paginate():
            for db in page.get("DBInstances", []):
                instances.add(db.get("DBInstanceIdentifier", ""))

        # fetch both manual & automated snapshots
        snap_paginator = rds.get_paginator("describe_db_snapshots")
        for page in snap_paginator.paginate():
            for s in page.get("DBSnapshots", []):
                snapshot = build_rds_snapshot_metadata(s)

                # run checks from registry
                for check in RDS_SNAPSHOT_CHECKS:
                    snapshot.flags.update(check(snapshot))
                # orphaned check (needs context)
                snapshot.flags.update(check_rds_snapshot_orphaned(snapshot, instances))

                if snapshot.flags:
                    if snapshot.monthly_cost > 0:
                        snapshot.flags.add(f"PotentialSaving≈{snapshot.monthly_cost}$")

                    write_resource_to_csv(
                        writer=writer,
                        resource_id=snapshot.snapshot_id,
                        name="",
                        owner_id=ACCOUNT_ID,
                        resource_type=f"RDSSnapshot({snapshot.snapshot_type})",
                        state="",
                        creation_date=snapshot.creation_date,
                        storage_gb=snapshot.allocated_gb,
                        estimated_cost=snapshot.monthly_cost,
                        flags=list(snapshot.flags),
                    )
                    logging.info(
                        f"[RDS:{snapshot.snapshot_id}] type={snapshot.snapshot_type} "
                        f"flags={snapshot.flags} estCost≈${snapshot.monthly_cost}"
                    )

    except ClientError as e:
        logging.error(f"[check_rds_snapshots] AWS error: {e.response['Error'].get('Code')}")
    except Exception as e:
        logging.error(f"[check_rds_snapshots] Unexpected error: {e}")

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


#region AMI SECTION
@retry_with_backoff(exceptions=(ClientError,))
def get_tags(resource_id: str, ec2) -> dict[str, str]:
    """
    Retrieve tags for a given AWS resource.
    Args:
        resource_id (str): The ID of the AWS resource.
    Returns:
        dict: Dictionary of tag key-value pairs.
    """
    try:
        tags = ec2.describe_tags(Filters=[{"Name": "resource-id", "Values": [resource_id]}])["Tags"]
        return {tag["Key"]: tag["Value"] for tag in tags}
    except ClientError as e:
        logging.warning(f"Error retrieving tags for {resource_id}: {e}")
        return {}

def is_referenced_in_cfn(ami_id, cached_templates):
    """
    Check if the AMI ID is referenced in any cached CloudFormation templates.

    Args:
        ami_id (str): The AMI ID to search for.
        cached_templates (list): List of (stack_name, template_str) tuples.

    Returns:
        str: Description of reference or "No".
    """
    try:
        for stack_name, template_str in cached_templates:
            if ami_id in template_str:
                return f"Yes (in CloudFormation stack {stack_name})"
    except Exception as e:
        logging.warning(f"Error searching AMI ID {ami_id} in cached templates: {e}")
    return "No"


@retry_with_backoff(exceptions=(ClientError,))
def get_ami_ids(ec2):
    """
    Retrieve a list of AMI IDs owned by the current AWS account.
    Returns:
        list: A list of AMI IDs.
    """
    try:
        response = ec2.describe_images(Owners=["self"])
        return [img["ImageId"] for img in response["Images"]]
    except ClientError as e:
        logging.error(f"Error retrieving AMIs: {e}")
        return []


def is_referenced_in_templates(ami_id):
    """
    Check if the AMI ID is referenced in local template files (YAML, YML, JSON).
    Args:
        ami_id (str): The AMI ID to search for.
    Returns:
        str: Description of reference or "No".
    """
    for ext in ("yaml", "yml", "json"):
        for root, _, files in os.walk("."):
            for file in files:
                if file.endswith(ext):
                    try:
                        with open(os.path.join(root, file), "r", encoding="utf-8", errors="ignore") as f:
                            if ami_id in f.read():
                                return f"Yes (in {file})"
                    except Exception as e:
                        logging.warning(f"Error reading file {file}: {e}")
                        return "Error"
    return "No"

@retry_with_backoff(exceptions=(ClientError,))
def is_referenced_in_ec2(ami_id, ec2):
    """
    Check if the AMI ID is used by any EC2 instances.
    Args:
        ami_id (str): The AMI ID to check.
    Returns:
        str: Description of reference or "No".
    """
    try:
        paginator = ec2.get_paginator("describe_instances")
        for page in paginator.paginate():
            for reservation in page.get("Reservations", []):
                for instance in reservation.get("Instances", []):
                    if instance.get("ImageId") == ami_id:
                        return f"Yes (in EC2 instance {instance.get('InstanceId')})"
    except ClientError as e:
        logging.warning(f"Error checking EC2 references for {ami_id}: {e}")
    return "No"


@retry_with_backoff(exceptions=(ClientError,))
def is_referenced_in_launch_templates(ami_id, ec2):
    """
    Check if the AMI ID is used in any EC2 launch templates.
    Args:
        ami_id (str): The AMI ID to check.
    Returns:
        str: Description of reference or "No".
    """
    try:
        templates = ec2.describe_launch_templates()["LaunchTemplates"]
        for tpl in templates:
            versions = ec2.describe_launch_template_versions(LaunchTemplateId=tpl["LaunchTemplateId"])["LaunchTemplateVersions"]
            for ver in versions:
                if ver["LaunchTemplateData"].get("ImageId") == ami_id:
                    return f"Yes (in Launch Template {tpl['LaunchTemplateId']})"
    except ClientError as e:
        logging.warning(f"Error checking launch templates for {ami_id}: {e}")
    return "No"


@retry_with_backoff(exceptions=(ClientError,))
def is_referenced_in_asg(ami_id, autoscaling):
    """
    Check if the AMI ID is used in any Auto Scaling Groups.
    Args:
        ami_id (str): The AMI ID to check.
    Returns:
        str: Description of reference or "No".
    """
    try:
        groups = autoscaling.describe_auto_scaling_groups()["AutoScalingGroups"]
        for group in groups:
            lc_name = group.get("LaunchConfigurationName")
            if lc_name:
                lcs = autoscaling.describe_launch_configurations(LaunchConfigurationNames=[lc_name])["LaunchConfigurations"]
                if lcs and lcs[0]["ImageId"] == ami_id:
                    return f"Yes (in Auto Scaling Group {group['AutoScalingGroupName']})"
    except ClientError as e:
        logging.warning(f"Error checking ASG references for {ami_id}: {e}")
    return "No"


def load_existing_ami_ids():
    """
    Load existing AMI IDs from the output CSV file to avoid duplication.
    Returns:
        set: Set of existing AMI IDs.
    """
    if not os.path.exists(OUTPUT_FILE):
        return set()
    with open(OUTPUT_FILE, "r", newline="") as f:
        reader = csv.reader(f)
        next(reader, None)
        return {row[0] for row in reader if row}


@retry_with_backoff(exceptions=(ClientError,))
def get_launch_permissions(ami_id, ec2):
    """
    Check if the AMI is shared with other AWS accounts or is public.
    Returns "Yes" if shared, "No" if private, "Unknown" on error.
    """
    try:
        attr = ec2.describe_image_attribute(ImageId=ami_id, Attribute='launchPermission')
        permissions = attr.get('LaunchPermissions', [])
        return "Yes" if permissions else "No"
    except ClientError as e:
        logging.warning(f"Error checking launch permissions for {ami_id}: {e}")
        return "Unknown"


def cache_all_cfn_templates(cfn):
    """
    Retrieve and cache all CloudFormation templates in the region.
    Returns:
        list of tuples: Each tuple contains (stack_name, template_str)
    """
    templates = []
    try:
        paginator = cfn.get_paginator("describe_stacks")
        for page in paginator.paginate():
            for stack in page.get("Stacks", []):
                try:
                    template = cfn.get_template(StackName=stack["StackName"]).get("TemplateBody", "")
                    if isinstance(template, dict):
                        template_str = json.dumps(template)
                    else:
                        template_str = template
                    templates.append((stack["StackName"], template_str))
                except Exception as e:
                    logging.warning(f"Error retrieving template for stack {stack['StackName']}: {e}")
    except Exception as e:
        logging.warning(f"Error describing CloudFormation stacks: {e}")
    return templates


# In-memory caches
tag_cache = {}
permission_cache = {}
reference_cache = {}

def get_cached_tags(resource_id: str, ec2) -> dict:
    if resource_id in tag_cache:
        return tag_cache[resource_id]
    tags = get_tags(resource_id, ec2)
    tag_cache[resource_id] = tags
    return tags

def get_cached_permissions(ami_id: str, ec2) -> str:
    if ami_id in permission_cache:
        return permission_cache[ami_id]
    perm = get_launch_permissions(ami_id, ec2)
    permission_cache[ami_id] = perm
    return perm


def get_cached_reference(ami_id: str, cached_templates, ec2, autoscaling) -> str:
    if ami_id in reference_cache:
        return reference_cache[ami_id]
    ref_template = is_referenced_in_templates(ami_id)
    ref_ec2 = is_referenced_in_ec2(ami_id, ec2)
    ref_lt = is_referenced_in_launch_templates(ami_id, ec2)
    ref_asg = is_referenced_in_asg(ami_id, autoscaling)
    ref_cfn = is_referenced_in_cfn(ami_id, cached_templates)
    referenced = next((r for r in [ref_template, ref_ec2, ref_lt, ref_asg, ref_cfn] if r != "No"), "No")
    reference_cache[ami_id] = referenced
    return referenced


@retry_with_backoff(exceptions=(ClientError,))
def get_snapshot_storage(snapshot_ids: List[str], ec2) -> float:
    """
    Calculate the total storage size in GB for a list of snapshot IDs.
    Args:
        snapshot_ids (List[str]): List of snapshot IDs.
    Returns:
        float: Total storage size in GB.
    """
    total_gb = 0.0
    for i in range(0, len(snapshot_ids), BATCH_SIZE):
        batch = snapshot_ids[i:i+BATCH_SIZE]
        try:
            snapshots = ec2.describe_snapshots(SnapshotIds=batch)["Snapshots"]
            for snap in snapshots:
                size_gb = snap.get("StorageSize", snap.get("VolumeSize", 0))
                
                if size_gb is None:
                    logging.warning(f"[get_snapshot_storage] Snapshot {snap.get('SnapshotId')} has no size info.")
                    continue 

                total_gb += size_gb
        except ClientError as e:
            logging.warning(f"Error retrieving snapshot batch: {e}")
    return total_gb


def process_ami(image, cached_templates, existing_ids, ec2, autoscaling):
    ami_id = image["ImageId"]
    if ami_id in existing_ids:
        logging.info(f"{ami_id} already in CSV, skipping.")
        return None

    try:
        creation_date = image.get("CreationDate", "")
        name = image.get("Name", "")
        description = image.get("Description", "")
        owner_id = ACCOUNT_ID
        state = image.get("State", "")

        if "This image is created by the AWS Backup" in description:
            return None

        snapshot_ids = [
            bdm["Ebs"]["SnapshotId"]
            for bdm in image.get("BlockDeviceMappings", [])
            if "Ebs" in bdm and "SnapshotId" in bdm["Ebs"]
        ]

        total_storage_gb = get_snapshot_storage(snapshot_ids, ec2)
        cost_usd = round(total_storage_gb * get_price("EBS", "SNAPSHOT_GB_MONTH"), 2)

        tags = get_cached_tags(ami_id, ec2)
        app_id = tags.get("ApplicationID", "")
        app = tags.get("Application", "")
        env = tags.get("Environment", "")

        referenced = get_cached_reference(ami_id, cached_templates, ec2, autoscaling)
        shared = get_cached_permissions(ami_id, ec2)

        flagger = AMIFlagger(
            tags={"ApplicationID": app_id, "Application": app, "Environment": env},
            creation_date=creation_date,
            referenced=referenced,
            shared=shared
        )
        flagger.apply_rules()
        flags = flagger.get_flags()

        logging.info(f"{ami_id} analysis complete.")

        # Return a structured payload for main-thread CSV writing
        return {
            "resource_id": ami_id,
            "name": name,
            "resource_type": "AMI",
            "owner_id": owner_id,
            "state": state,
            "creation_date": creation_date,
            "storage_gb": total_storage_gb,
            "estimated_cost": cost_usd,
            "app_id": app_id or "Not Found",
            "app": app or "Not Found",
            "env": env or "Not Found",
            "referenced_in": referenced,
            "flags": flags,
        }

    except Exception as e:
        logging.error(f"Error processing AMI {ami_id}: {e}")
        return None


def check_amis(writer, cached_templates, ec2, autoscaling, cfn):
    existing_ids = load_existing_ami_ids()
    ami_ids = get_ami_ids(ec2)
    if not ami_ids:
        logging.info("No AMIs found or error retrieving AMIs.")
        return

    for i in range(0, len(ami_ids), BATCH_SIZE):
        batch_ids = ami_ids[i:i + BATCH_SIZE]
        try:
            images = ec2.describe_images(ImageIds=batch_ids)["Images"]
        except Exception as e:
            logging.warning(f"Error fetching AMI batch: {e}")
            continue

        results = []
        with ThreadPoolExecutor(max_workers=5) as executor:
            futures = [executor.submit(process_ami, image, cached_templates, existing_ids, ec2, autoscaling)
                       for image in images]
            for f in futures:
                payload = f.result()
                if payload:
                    results.append(payload)

        # Write on the main thread via the unified helper (correct columns)
        for p in results:
            write_resource_to_csv(
                writer=writer,
                resource_id=p["resource_id"],
                name=p["name"],
                resource_type=p["resource_type"],
                owner_id=p["owner_id"],
                state=p["state"],
                creation_date=p["creation_date"],
                storage_gb=p["storage_gb"],
                estimated_cost=p["estimated_cost"],
                app_id=p["app_id"],
                app=p["app"],
                env=p["env"],
                referenced_in=p["referenced_in"],
                flags=p["flags"],
            )

#endregion

#region EC2 SECTION

def _ec2_hourly_price(instance_type: str, region: str) -> float:
    """Best-effort on-demand hourly price for an EC2 instance type in a region."""
    try:
        return float(get_price("EC2", instance_type, region=region))
    except Exception:
        return 0.0


def check_idle_ec2_instances(writer, ec2, cloudwatch,) -> None:
    """
    Identify EC2 instances that appear **idle** and estimate potential monthly savings
    if they are stopped/terminated.

    Method:
      • Enumerate running EC2 instances (DescribeInstances paginator).
      • Build a single CloudWatch GetMetricData request per page to fetch:
          - CPUUtilization (Average)
          - NetworkIn, NetworkOut (Sum)
          - DiskReadOps, DiskWriteOps (Sum)
          - StatusCheckFailed (Maximum)
        using 1-day periods over the last EC2_LOOKBACK_DAYS.
      • Compute per-instance indicators:
          - avg_cpu_pct
          - total_net_gb over window
          - total_disk_ops over window
          - max_status_check_failed (0 means healthy)
      • Flag as IdleInstance if:
          avg_cpu_pct < EC2_IDLE_CPU_PCT AND
          total_net_gb < EC2_IDLE_NET_GB AND
          total_disk_ops < EC2_IDLE_DISK_OPS AND
          max_status_check_failed == 0
      • Estimate potential monthly saving as on-demand hourly price × 24 × 30.

    Output (CSV):
      - ResourceType="EC2Instance", State (instance state), PotentialSaving in flags
        so your writer populates Potential_Saving_USD automatically.

    Error handling:
      • All AWS calls are wrapped with retry/backoff.
      • Missing metrics default to safe values (treated as 0 traffic/CPU).
      • Processing continues on per-page or per-instance errors, logged at INFO/ERROR.
    """

    try:
        region = (
            getattr(getattr(cloudwatch, "meta", None), "region_name", "")
            or getattr(getattr(ec2, "meta", None), "region_name", "")
            or ""
        )

        now = datetime.now(timezone.utc)
        lookback_days = max(1, EC2_LOOKBACK_DAYS)
        start = now - timedelta(days=lookback_days)
        period = EC2_CW_PERIOD  # e.g., 86400

        # 1) List instances in this region
        instances = []
        token = None
        while True:
            try:
                resp = ec2.describe_instances(NextToken=token) if token else ec2.describe_instances()
            except ClientError as e:
                logging.error(f"[EC2] describe_instances failed in {region}: {e}")
                break

            for r in resp.get("Reservations", []):
                instances.extend(r.get("Instances", []))
            token = resp.get("NextToken")
            if not token:
                break

        if not instances:
            return

        def tags_dict(aws_tags):
            if not aws_tags:
                return {}
            return {t.get("Key", ""): t.get("Value", "") for t in aws_tags}

        # 2) Batch CloudWatch metrics for all instances (passed CW client)
        batch = cw.CloudWatchBatcher(region, client=cloudwatch)
        for it in instances:
            iid = it["InstanceId"]
            dims = [{"Name": "InstanceId", "Value": iid}]
            batch.add_q(id_hint=f"ec2_cpu__{iid}",  namespace="AWS/EC2", metric="CPUUtilization", dims=dims, stat="Average", period=period)
            batch.add_q(id_hint=f"ec2_nin__{iid}",  namespace="AWS/EC2", metric="NetworkIn",      dims=dims, stat="Sum",     period=period)
            batch.add_q(id_hint=f"ec2_nout__{iid}", namespace="AWS/EC2", metric="NetworkOut",     dims=dims, stat="Sum",     period=period)
            batch.add_q(id_hint=f"ec2_drd__{iid}",  namespace="AWS/EC2", metric="DiskReadOps",    dims=dims, stat="Sum",     period=period)
            batch.add_q(id_hint=f"ec2_dwr__{iid}",  namespace="AWS/EC2", metric="DiskWriteOps",   dims=dims, stat="Sum",     period=period)

        try:
            series = batch.execute(start, now, scan_by="TimestampDescending")
        except Exception as e:
            logging.exception(f"[EC2] CloudWatch batch execute failed in {region}: {e}")
            series = {}

        # 3) Emit rows
        for it in instances:
            try:
                iid = it["InstanceId"]
                itype = it.get("InstanceType", "")
                state = (it.get("State", {}) or {}).get("Name", "")
                launch_time = it.get("LaunchTime")
                if isinstance(launch_time, datetime) and launch_time.tzinfo is None:
                    launch_time = launch_time.replace(tzinfo=timezone.utc)
                created_iso = (launch_time or now).astimezone(timezone.utc).isoformat()

                tdict = tags_dict(it.get("Tags", []))
                name = tdict.get("Name", iid)

                # Extract metrics
                cpu_vals = [v for _, v in series.get(f"ec2_cpu__{iid}", [])]
                nin_sum  = sum(v for _, v in series.get(f"ec2_nin__{iid}", []))
                nout_sum = sum(v for _, v in series.get(f"ec2_nout__{iid}", []))
                drd_sum  = sum(v for _, v in series.get(f"ec2_drd__{iid}", []))
                dwr_sum  = sum(v for _, v in series.get(f"ec2_dwr__{iid}", []))

                avg_cpu  = (sum(cpu_vals) / len(cpu_vals)) if cpu_vals else 0.0
                net_gb   = float(nin_sum + nout_sum) / (1024.0 ** 3)
                disk_ops = float(drd_sum + dwr_sum)

                # Thresholds from config
                idle_cpu  = avg_cpu  <= EC2_IDLE_CPU_PCT
                idle_net  = net_gb   <= EC2_IDLE_NET_GB
                idle_disk = disk_ops <= EC2_IDLE_DISK_OPS
                is_idle   = idle_cpu and idle_net and idle_disk and state == "running"

                # Estimated monthly compute using your helper & math
                try:
                    hourly = _ec2_hourly_price(itype, region)
                except Exception:
                    hourly = 0.0
                monthly_compute = round(hourly * 24 * 30, 2) if hourly > 0 else 0.0

                # Flags, confidence, potential
                flags = []
                missing = [k for k in REQUIRED_TAG_KEYS if not tdict.get(k)]
                if missing:
                    flags.append(f"MissingRequiredTags={','.join(missing)}")
                if is_idle:
                    flags.append("idle_ec2_candidate")

                confidence = 100 if is_idle else None
                potential  = monthly_compute if is_idle else None

                signals = {
                    "Region": region,
                    "InstanceType": itype,
                    "State": state,
                    "AvgCPUPercent": f"{avg_cpu:.2f}",
                    f"NetGB{lookback_days}d": f"{net_gb:.3f}",
                    f"DiskOps{lookback_days}d": str(int(disk_ops)),
                    "LookbackDays": str(lookback_days),
                }

                write_resource_to_csv(
                    writer=writer,
                    resource_id=iid,
                    name=name,
                    resource_type="EC2Instance",
                    owner_id=ACCOUNT_ID,
                    state=str(state),
                    creation_date=created_iso,
                    estimated_cost=monthly_compute,  # <= your original monthly compute estimate
                    app_id=tdict.get("ApplicationID", "NULL"),
                    app=tdict.get("Application", "NULL"),
                    env=tdict.get("Environment", "NULL"),
                    referenced_in="",
                    flags=flags,
                    object_count="",
                    potential_saving=potential,
                    confidence=confidence,
                    signals=signals,
                )
            except Exception as e:
                logging.exception(f"[EC2] emit failed for {it.get('InstanceId','?')} in {region}: {e}")

    except Exception as e:
        logging.exception(f"[EC2] check_ec2_idle_instances_refactored failed: {e}")
        return

#endregion

#region ACM SECTION
@retry_with_backoff(exceptions=(ClientError,))
def check_acm_private_certificates(writer: csv.writer, cloudfront) -> None:
    """
    Find ACM private certificates that are not in use (InUseBy == []) and flag them.

    Why it matters:
    - Private certs are usually issued from AWS Private CA. While the per-certificate
      fee is assessed at issuance (not monthly), keeping unused certs around can still
      drive operational risk and OCSP response handling charges; and they’re often a
      smell that a Private CA continues to run without real consumers.  # Pricing refs:
      - AWS Private CA: $400/mo per CA (general-purpose) or $50/mo (short-lived).  # noqa
      - CUR dimensions include PrivateCertificatesIssued & OCSP* items.           # noqa
    Signals include Status, NotAfter, and InUseBy count to help reviewers decide.

    Notes:
    - ACM is regional: we iterate REGIONS.
    - The function uses boto3.client('acm') internally and guards API calls via safe_aws_call.
      In your unit tests, safe_aws_call is patched to return fallbacks without raising.
    """
    try:
        total_unused = 0
        for region in REGIONS:
            try:
                acm = boto3.client("acm", region_name=region, config=SDK_CONFIG)  # type: ignore
            except ClientError as e:
                logging.warning(f"[ACM] Init client failed for {region}: {e}")
                continue

            # list_certificates is cheap; we filter Type=PRIVATE
            cert_summaries = safe_aws_call(
                lambda: acm.list_certificates().get("CertificateSummaryList", []),
                fallback=[], context=f"ACM:{region}:ListCertificates",
            )

            # Quick filter on 'Type' where available; otherwise describe per item
            for s in cert_summaries:
                arn = s.get("CertificateArn", "")
                # We still need details for InUseBy & NotAfter
                desc = safe_aws_call(
                    lambda: acm.describe_certificate(CertificateArn=arn).get("Certificate", {}),
                    fallback={}, context=f"ACM:{region}:DescribeCertificate",
                )
                if not desc:
                    continue

                ctype = desc.get("Type") or s.get("Type") or ""
                if str(ctype).upper() != "PRIVATE":
                    continue

                in_use_by = desc.get("InUseBy", []) or []
                status = desc.get("Status", "")
                not_after = desc.get("NotAfter")
                not_after_str = not_after.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ") if hasattr(not_after, "astimezone") else ""

                if len(in_use_by) == 0:
                    # We do not assert a high dollar saving per cert (per-cert fee is one-time on issuance),
                    # but we still emit a review row with clear signals.
                    flags = ["PrivateCertNotInUse", "ConsiderRevokeOrDelete"]
                    # Optional: tag hygiene
                    tags = {}
                    try:
                        t = acm.list_tags_for_certificate(CertificateArn=arn).get("Tags", [])
                        tags = {kv.get("Key",""): kv.get("Value","") for kv in t if kv.get("Key")}
                    except Exception:
                        pass

                    signals = {
                        "Region": region,
                        "Status": status,
                        "InUseBy": len(in_use_by),
                        "NotAfter": not_after_str,
                        "LookbackDays": "",  # N/A for ACM directly
                    }
                    # Confidence: simple—if 'InUseBy' is empty we have strong evidence
                    confidence = score_confidence({"inuse_zero": 1.0}, evidence_ok=True)

                    write_resource_to_csv(
                        writer=writer,
                        resource_id=arn,
                        name=s.get("DomainName", ""),
                        resource_type="ACMPrivateCertificate",
                        owner_id=ACCOUNT_ID,
                        state=status,
                        creation_date="",     # not exposed directly in describe_certificate
                        estimated_cost=0,     # per-cert issuance is one-time; OCSP may exist but small/variable
                        app_id=tags.get("ApplicationID", "NULL"),
                        app=tags.get("Application", "NULL"),
                        env=tags.get("Environment", "NULL"),
                        flags=flags,
                        confidence=confidence,
                        signals=signals,
                    )
                    total_unused += 1

        logging.info(f"[ACM] Unused private certificates flagged: {total_unused}")
    except Exception as e:
        logging.error(f"[check_acm_private_certificates] Unexpected error: {e}")

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

            run_check(
                profiler=profiler,
                check_name="check_acm_private_certificates",
                region="GLOBAL",
                fn=check_acm_private_certificates,
                writer=writer,
                cloudfront=cloudfront_global
            )

            # -------- Per-region steps
            for region in REGIONS:
                logging.info(f"Running cleanup for region: {region}")
                try:
                    clients = init_clients(region)
                except Exception as e:
                    logging.error(f"[main] init_clients({region}) failed: {e}")
                    continue

                # Cache CFN templates (this is used by check_amis)
                cached_templates = run_step(
                    profiler,
                    step_name="cache_all_cfn_templates",
                    region=region,
                    fn=cache_all_cfn_templates,
                    cfn=clients['cfn']
                )

                #correlator WIP
                #regions = REGIONS
                #graph = build_certificate_graph(regions=regions, account_id=ACCOUNT_ID)
                #cert_summary = summarize_cert_usage(graph)

                run_check(
                    profiler, check_name="check_unused_elastic_ips",
                    region=region, fn=eip, writer=writer, ec2=clients["ec2"],
                )

                run_check(profiler, check_name="check_idle_load_balancers", region=region,
                          fn=check_idle_load_balancers, writer=writer,
                          elbv2=clients['elbv2'], cloudwatch=clients['cloudwatch'])

                run_check(
                    profiler, check_name="eni",
                    region=region, fn=eni, writer=writer, ec2=clients["ec2"],
                )

                run_check(profiler, check_name="check_unused_efs_filesystems", region=region,
                          fn=check_unused_efs_filesystems, writer=writer,
                          efs=clients['efs'], cloudwatch=clients['cloudwatch'])

                run_check(profiler, check_name="check_log_groups_with_infinite_retention", region=region,
                          fn=check_log_groups_with_infinite_retention,
                          writer=writer, logs=clients['logs'])

                run_check(profiler, "check_backup_plans_without_selections", 
                          region, backup_checks.check_backup_plans_without_selections, writer=writer, 
                          backup=clients["backup"])
                run_check(profiler, "check_backup_rules_no_lifecycle",      
                          region, backup_checks.check_backup_rules_no_lifecycle, writer=writer, 
                          backup=clients["backup"])
                run_check(profiler, "check_backup_stale_recovery_points",   
                          region, backup_checks.check_backup_stale_recovery_points, writer=writer, 
                          backup=clients["backup"])

                run_check(profiler, check_name="check_orphaned_fsx_backups", region=region,
                          fn=check_orphaned_fsx_backups, writer=writer, fsx=clients['fsx'])

                # Route 53 is global, ELB is regional; leave as-is but profile per region invocation
                run_check(profiler, check_name="check_redundant_route53_records", region=region,
                          fn=check_redundant_route53_records, writer=writer,
                          route53=clients['route53'], elbv2=clients['elbv2'], s3=clients['s3'])

                run_check(profiler, check_name="check_lambda_efficiency", region=region,
                          fn=check_lambda_efficiency, writer=writer,
                          lambda_client=clients['lambda'], cloudwatch=clients['cloudwatch'])

                run_check(profiler, check_name="check_amis", region=region,
                          fn=check_amis, writer=writer,
                          cached_templates=cached_templates, ec2=clients['ec2'],
                          autoscaling=clients['autoscaling'], cfn=clients['cfn'])

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

                run_check(profiler, check_name="check_rds_snapshots", region=region,
                          fn=check_rds_snapshots, writer=writer, rds=clients['rds'])

                run_check(profiler, check_name="check_wafv2_unassociated_acls", region=region,
                          fn=check_wafv2_unassociated_acls, writer=writer,
                          wafv2=clients['wafv2'], region_name=region)

                run_check(profiler, check_name="check_idle_ec2_instances", region=region,
                          fn=check_idle_ec2_instances, writer=writer,
                          ec2=clients['ec2'], cloudwatch=clients['cloudwatch'])

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


        profiler.dump_csv()
        profiler.log_summary(top_n=30)
        logging.info(f"CSV export complete: {OUTPUT_FILE}")
        logging.info(f"Profile export complete: {PROFILE_FILE}")

    except Exception as e:
        logging.error(f"[main] Fatal error: {e}")

if __name__ == "__main__":
    main()
