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
import time
import logging
from typing import *  # noqa: F403
from datetime import datetime, timezone, timedelta
import json
import random
from functools import wraps
from botocore.exceptions import ClientError, EndpointConnectionError, NoCredentialsError # type: ignore
from concurrent.futures import ThreadPoolExecutor, as_completed
from botocore.config import Config # type: ignore
from dataclasses import dataclass, field
from statistics import fmean
from enum import Enum
import string
import re
from statistics import median
from contextlib import contextmanager
from time import perf_counter
import threading
#from correlator import build_certificate_graph, summarize_cert_usage

from finops_toolset.config import (
    SDK_CONFIG,
    REGIONS, OUTPUT_FILE, LOG_FILE, BATCH_SIZE, REQUIRED_TAG_KEYS,
    _S3_MPU_BUCKET_WORKERS, _S3_MPU_PART_WORKERS, _S3_MPU_PAGE_SIZE,
    _S3_MPU_GLOBAL_FINDINGS_CAP, _S3_MPU_PARTS_MODE,
    DDB_LOOKBACK_DAYS, DDB_CW_PERIOD, DDB_BACKUP_AGE_DAYS,
    EFS_LOOKBACK_DAYS, EFS_IA_LARGE_THRESHOLD_GB, EFS_IA_READS_HIGH_GB_PER_DAY,
    EFS_IDLE_THRESHOLD_GB_PER_DAY, EFS_STANDARD_THRESHOLD_GB,
    EFS_STANDARD_ARCHIVE_THRESHOLD_GB, EFS_BURST_CREDIT_LOW_WATERMARK, HOURS_PER_MONTH,
    LAMBDA_LOOKBACK_DAYS, LAMBDA_ERROR_RATE_THRESHOLD, LAMBDA_LOW_CONCURRENCY_THRESHOLD,
    LAMBDA_LOW_TRAFFIC_THRESHOLD, LAMBDA_LARGE_PACKAGE_MB,
    LAMBDA_LOW_PROVISIONED_UTILIZATION, LAMBDA_VERSION_SPRAWL_THRESHOLD,
    VPC_LOOKBACK_DAYS, MIN_COST_THRESHOLD,
    NAT_LOOKBACK_DAYS, NAT_IDLE_TRAFFIC_THRESHOLD_GB, NAT_IDLE_CONNECTION_THRESHOLD,
    BIG_BUCKET_THRESHOLD_GB, STALE_DAYS_THRESHOLD, S3_MULTIPART_STALE_DAYS,
    S3_LOOKBACK_DAYS, MAX_KEYS_TO_SCAN, S3_STORAGE_TYPES,
    _DDB_TABLE_WORKERS, _DDB_META_WORKERS, _DDB_GSI_METRICS_LIMIT, _DDB_CW_PERIOD,
    VALID_RETENTION_DAYS, SSM_ADV_STALE_DAYS, MAX_CUSTOM_METRICS_CHECK,
    EC2_LOOKBACK_DAYS, EC2_CW_PERIOD, EC2_IDLE_CPU_PCT, EC2_IDLE_NET_GB, EC2_IDLE_DISK_OPS,
    CLOUDFRONT_LOOKBACK_DAYS, CLOUDFRONT_PERIOD, CLOUDFRONT_IDLE_REQUESTS, CLOUDFRONT_IDLE_BYTES_GB,
    LOAD_BALANCER_LOOKBACK_DAYS,
)

from finops_toolset.pricing import PRICING as PRICING, get_price as get_price, per_month
import core.cloudwatch as cw

#endregion

#region RETRY

def retry_with_backoff(max_retries=3, backoff_factor=1.5, jitter=True, exceptions=(ClientError, EndpointConnectionError, NoCredentialsError)):
    """
    Decorator to retry a function with exponential backoff and optional jitter. -> Used of jitter to avoid thundering herd 
    
    Args:
        max_retries (int): Maximum number of retries.
        backoff_factor (float): Multiplier for delay between retries.
        jitter (bool): Whether to add random jitter to delay.
        exceptions (tuple): Exceptions to catch and retry on.
    """
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            retries = 0
            delay = 1.0
            while retries < max_retries:
                try:
                    return func(*args, **kwargs)
                except exceptions as e:
                    error_code = getattr(e, 'response', {}).get('Error', {}).get('Code', '')
                    if error_code == 'UnauthorizedOperation':
                        logging.error(f"[{func.__name__}] Permission denied: {e}")
                        return None
                    retries += 1
                    sleep_time = delay * (random.uniform(1.5, 2.5) if jitter else 1)
                    logging.warning(f"[{func.__name__}] Retry {retries}/{max_retries} after error: {e}. Retrying in {sleep_time:.2f}s...")
                    time.sleep(sleep_time)
                    delay *= backoff_factor
            logging.error(f"[{func.__name__}] Max retries exceeded.")
            return None
        return wrapper
    return decorator

# Configure logging
logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)

#logger = logging.getLogger("aws-finops")  # base logger for your script
#endregion


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
        "ecr": boto3.client("ecr", region_name=region, config=SDK_CONFIG),
        "eks": boto3.client("eks", region_name=region, config=SDK_CONFIG),
        "rds": boto3.client("rds", region_name=region, config=SDK_CONFIG),
        "kinesis": boto3.client("kinesis", region_name=region, config=SDK_CONFIG),
        "wafv2": boto3.client("wafv2", region_name=region, config=SDK_CONFIG),
        "ssm": boto3.client("ssm", region_name=region, config=SDK_CONFIG),
        "cloudfront": boto3.client("cloudfront", config=SDK_CONFIG),
        "cloudtrail": boto3.client("cloudtrail", config=SDK_CONFIG),
        "kms": boto3.client("kms", region_name=region, config=SDK_CONFIG),
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


#region S3 SECTION

def _cw_last_avg(cloudwatch, namespace: str, metric: str, dimensions: list[dict], start: datetime, end: datetime, period: int = 86400) -> Optional[float]:
    try:
        resp = cloudwatch.get_metric_statistics(
            Namespace=namespace,
            MetricName=metric,
            Dimensions=dimensions,
            StartTime=start,
            EndTime=end,
            Period=period,
            Statistics=["Average"],
        )
        dps = sorted(resp.get("Datapoints", []), key=lambda x: x["Timestamp"])
        if not dps:
            return None
        return float(dps[-1].get("Average", 0.0))
    except ClientError as e:
        logging.warning(f"[S3/_cw_last_avg] {namespace}/{metric} dims={dimensions} failed: {e}")
        return None

def get_bucket_metrics_via_cw(bucket_name: str, cw) -> tuple[Optional[float], Optional[int], Dict[str, float], List[str]]:
    """
    Returns (total_size_gb, number_of_objects, size_breakdown_gb, flags).
    - total_size_gb: sum across common storage types (None if no datapoints).
    - number_of_objects: CW NumberOfObjects for AllStorageTypes (None if no datapoints).
    - size_breakdown_gb: per storage type GB we could retrieve.
    - flags: AccessDenied/MetricsStale/SizeUnknown etc.
    """
    flags: list[str] = []
    end = datetime.now(timezone.utc)
    # Use 3 days to avoid the daily timing hole; S3 storage metrics are updated daily with a delay
    start = end - timedelta(days=3)

    # NumberOfObjects (disambiguates real empty vs “no size datapoints”)
    obj_avg = _cw_last_avg(
        cw,
        "AWS/S3",
        "NumberOfObjects",
        [{"Name": "BucketName", "Value": bucket_name}, {"Name": "StorageType", "Value": "AllStorageTypes"}],
        start,
        end,
    )
    number_of_objects = int(obj_avg) if obj_avg is not None else None

    # Sum sizes across storage classes
    size_breakdown_gb: dict[str, float] = {}
    total_bytes = 0.0
    any_dp = False
    for stype in S3_STORAGE_TYPES:
        avg_bytes = _cw_last_avg(
            cw,
            "AWS/S3",
            "BucketSizeBytes",
            [{"Name": "BucketName", "Value": bucket_name}, {"Name": "StorageType", "Value": stype}],
            start,
            end,
        )
        if avg_bytes is not None:
            any_dp = True
            size_breakdown_gb[stype] = round(avg_bytes / (1024**3), 2)
            total_bytes += avg_bytes

    total_size_gb = round(total_bytes / (1024**3), 2) if any_dp else None

    if not any_dp:
        flags.append("SizeUnknown")
    if number_of_objects is None:
        flags.append("ObjectCountUnknown")

    return total_size_gb, number_of_objects, size_breakdown_gb, flags


@retry_with_backoff()
def get_bucket_last_modified(s3, bucket_name: str) -> Optional[datetime]:
    """
    Return the most recent LastModified (UTC) across all objects in the bucket.

    Defensive behavior to avoid false positives:
      • We only return a timestamp if we have high confidence.
      • If the listing is truncated and we did not complete the scan (hit safety cap),
        we return None (caller will mark LastModifiedUnknown rather than StaleData).
      • Region mismatch is retried once with a regional S3 client.
      • AccessDenied/AllAccessDisabled/NoSuchBucket -> None.

    NOTE: S3 ListObjectsV2 is lexicographically ordered by key, not by LastModified.
          Therefore we must aggregate across the pages we actually scan. For very large
          buckets we cap total keys scanned to bound runtime; if truncated after the cap,
          we return None to avoid stale false positives.

    Args:
        s3: boto3 S3 client (may be global/non-regional).
        bucket_name: target bucket.

    Returns:
        datetime (tz-aware, UTC) of the most recently modified object, or None if unknown.
    """

    PAGE_SIZE = 1000

    def _scan_with_client(client) -> Optional[datetime]:
        latest: Optional[datetime] = None
        scanned = 0
        truncated = False

        paginator = client.get_paginator("list_objects_v2")
        try:
            page_iter = paginator.paginate(
                Bucket=bucket_name,
                PaginationConfig={"PageSize": PAGE_SIZE}
            )
            for page in page_iter:
                contents = page.get("Contents") or []
                if contents:
                    try:
                        page_latest = max(
                            obj["LastModified"] for obj in contents if obj.get("LastModified")
                        )
                        if latest is None or page_latest > latest:
                            latest = page_latest
                    except Exception:
                        pass
                    scanned += len(contents)

                truncated = bool(page.get("IsTruncated"))
                if scanned >= MAX_KEYS_TO_SCAN:
                    break
            if scanned >= MAX_KEYS_TO_SCAN and truncated:
                human_cap = f"{MAX_KEYS_TO_SCAN:,}"
                logging.info(
                    "[get_bucket_last_modified] %s: hit cap (%s keys) with truncated listing; "
                    "returning None to avoid false 'stale' classification.",
                    bucket_name, human_cap
                )
                return None

            # If we scanned zero keys, either empty bucket or no permission -> None
            return latest
        except ClientError as e:
            code = (e.response or {}).get("Error", {}).get("Code", "")
            if code in ("AccessDenied", "AllAccessDisabled", "NoSuchBucket"):
                logging.info("[get_bucket_last_modified] %s: %s", bucket_name, code)
                return None
            raise

        except Exception as e:
            logging.warning(
                "[get_bucket_last_modified] Unexpected error on %s: %s", bucket_name, e
            )
            return None

    # First attempt with provided client
    try:
        return _scan_with_client(s3)
    except ClientError as e:
        # Handle region mismatch (PermanentRedirect / AuthorizationHeaderMalformed / 301 / InvalidRequest)
        if _is_wrong_region_error(e):
            try:
                loc = s3.get_bucket_location(Bucket=bucket_name)
                region = _normalize_bucket_region(loc.get("LocationConstraint"))
                try:
                    regional = boto3.client("s3", region_name=region, config=SDK_CONFIG)
                except Exception as ce:
                    logging.warning(
                        "[get_bucket_last_modified] Failed to init regional S3 client for %s: %s; "
                        "falling back to original client.", region, ce
                    )
                    regional = s3
                return _scan_with_client(regional)
            except Exception as re:
                logging.warning(
                    "[get_bucket_last_modified] Regional retry failed for %s: %s",
                    bucket_name, re
                )
                return None
        else:
            # Other client errors already handled in _scan_with_client, but just in case:
            code = (e.response or {}).get("Error", {}).get("Code", "")
            logging.warning("[get_bucket_last_modified] %s: %s", bucket_name, code or str(e))
            return None


def check_s3_buckets_refactored(
    writer: csv.writer,
    s3,
    regions: Optional[Iterable[str]] = None,
) -> None:
    """
    Audit all S3 buckets in the current AWS account for cost, usage, and compliance

      • Enumerates buckets
      • Caches regional CloudWatch clients to avoid re‑init overhead.
      • Gathers object count and per‑storage‑class size from CloudWatch
        (3‑day look‑back to avoid S3 metrics delay holes).
      • Estimates monthly storage cost using STANDARD and STANDARD_IA rates,
        flags when other storage classes are present.
      • Flags buckets for common FinOps/ops conditions:
          - MissingRequiredTags: one or more REQUIRED_TAG_KEYS absent or empty.
          - RegionUnknown: bucket region could not be resolved.
          - MetricsError / SizeUnknown / ObjectCountUnknown from CloudWatch.
          - EmptyBucket or NotEmptyByObjects mismatches.
          - CostApproximate when partial storage class pricing applied.
          - BigBucket when size exceeds BIG_BUCKET_THRESHOLD_GB.

    Args:
        writer: Active csv.writer instance used to append findings to the
            unified output file.
        s3: boto3 S3 client (global, no region_name) with permissions to
            list buckets, get locations, and read tags.

    Output:
        Writes a row to CSV for every bucket discovered, including:
            - Bucket name, owner account ID, creation date, region
            - Object count, total size (GB), per‑class size breakdown (for cost)
            - Estimated monthly storage cost (or "Unknown")
            - ApplicationID / Application / Environment tags if present
            - List of optimisation / compliance flags

    Notes:
        • CloudWatch S3 metrics are updated once per day; allow for lag
          when interpreting recent changes.
        • Cost estimates exclude classes other than STANDARD and STANDARD_IA
          unless explicitly added to PRICING.
    """
    try:
        # 1) Global list of buckets (+ creation date)
        try:
            all_buckets = s3.list_buckets().get("Buckets", [])
        except ClientError as e:
            logging.error(f"[S3] list_buckets failed: {e}")
            return
        if not all_buckets:
            return

        bucket_created_iso: Dict[str, str] = {}
        for b in all_buckets:
            c = b.get("CreationDate")
            if isinstance(c, datetime) and c.tzinfo is None:
                c = c.replace(tzinfo=timezone.utc)
            bucket_created_iso[b["Name"]] = (c or datetime.now(timezone.utc)).astimezone(timezone.utc).isoformat()

        # 2) Resolve region & tags
        def _normalize_region(loc):
            if not loc:
                return "us-east-1"
            if loc == "EU":
                return "eu-west-1"
            return loc

        def fetch_meta(bucket_entry) -> Dict[str, Any]:
            bname = bucket_entry["Name"]
            created = bucket_created_iso.get(bname, "")
            region, tags = "unknown", {}
            try:
                loc = s3.get_bucket_location(Bucket=bname)
                region = _normalize_region(loc.get("LocationConstraint"))
            except Exception as e:
                logging.info(f"[S3] get_bucket_location({bname}) -> {e}")
            if region != "unknown":
                try:
                    s3r = boto3.client("s3", region_name=region, config=SDK_CONFIG)
                except Exception:
                    s3r = s3
                try:
                    tagset = s3r.get_bucket_tagging(Bucket=bname).get("TagSet", [])
                    tags = {t["Key"]: t.get("Value", "") for t in tagset}
                except ClientError:
                    tags = {}
                except Exception:
                    tags = {}
            return {"Name": bname, "Region": region, "CreatedISO": created, "Tags": tags}

        metas: List[Dict[str, Any]] = []
        with ThreadPoolExecutor(max_workers=8) as ex:
            futs = [ex.submit(fetch_meta, b) for b in all_buckets]
            for f in as_completed(futs):
                try:
                    metas.append(f.result())
                except Exception as e:
                    logging.warning(f"[S3] fetch_meta error: {e}")

        if not metas:
            return

        region_filter = {r.strip() for r in regions} if regions else None

        # 3) Group by region; write minimal rows for unknown region
        now = datetime.now(timezone.utc)
        lookback_days = max(2, min(S3_LOOKBACK_DAYS, 7))
        start = now - timedelta(days=lookback_days)

        region_to_buckets: Dict[str, List[str]] = {}
        bucket_meta: Dict[str, Dict[str, Any]] = {}

        for m in metas:
            bn = m["Name"]
            bucket_meta[bn] = m
            if m["Region"] == "unknown":
                flags = ["RegionUnknown"]
                miss = [k for k in REQUIRED_TAG_KEYS if not m["Tags"].get(k)]
                if miss:
                    flags.append(f"MissingRequiredTags={','.join(miss)}")
                write_resource_to_csv(
                    writer=writer,
                    resource_id=bn,
                    name=bn,
                    resource_type="S3Bucket",
                    owner_id=ACCOUNT_ID or "",
                    state="",
                    creation_date=m["CreatedISO"],
                    storage_gb="",
                    estimated_cost="",
                    app_id=m["Tags"].get("ApplicationID", "NULL"),
                    app=m["Tags"].get("Application", "NULL"),
                    env=m["Tags"].get("Environment", "NULL"),
                    referenced_in="",
                    flags=flags,
                    object_count="",
                    potential_saving=None,
                    confidence=None,
                    signals={"Region": "unknown"},
                )
                continue

            if region_filter and m["Region"] not in region_filter:
                continue
            region_to_buckets.setdefault(m["Region"], []).append(bn)

        # 4) Per-region batch metrics & emit rows

        for region, buckets in region_to_buckets.items():
            if not buckets:
                continue

            try:
                s3r = boto3.client("s3", region_name=region, config=SDK_CONFIG)
            except Exception:
                s3r = s3

            batch = cw.CloudWatchBatcher(region)
            for bn in buckets:
                batch.add(cw.MDQ(
                    id=f"s3_size_std__{bn}",
                    namespace="AWS/S3",
                    metric="BucketSizeBytes",
                    dims=[{"Name": "BucketName", "Value": bn},
                          {"Name": "StorageType", "Value": "StandardStorage"}],
                    stat="Average",
                    period=86400,
                ))
                batch.add(cw.MDQ(
                    id=f"s3_obj__{bn}",
                    namespace="AWS/S3",
                    metric="NumberOfObjects",
                    dims=[{"Name": "BucketName", "Value": bn},
                          {"Name": "StorageType", "Value": "AllStorageTypes"}],
                    stat="Average",
                    period=86400,
                ))

            series = {}
            try:
                series = batch.execute(start, now, scan_by="TimestampDescending")
            except Exception as e:
                logging.exception(f"[S3] CloudWatch batch execute failed in {region}: {e}")

            for bn in buckets:
                try:
                    m = bucket_meta[bn]

                    size_bytes = cw.CloudWatchBatcher.latest(series.get(f"s3_size_std__{bn}", []), 0.0)
                    obj_count  = cw.CloudWatchBatcher.latest(series.get(f"s3_obj__{bn}", []), 0.0)

                    size_gb = round(float(size_bytes) / (1024.0 ** 3), 3)
                    objects = int(obj_count)

                    # Last modified via helper (no regression)
                    try:
                        lm_dt = get_bucket_last_modified(s3r, bn)
                    except Exception:
                        lm_dt = None
                    days_since_last = (now - lm_dt).days if lm_dt else None

                    # Guarded deep calls (only for big/stale)
                    has_lifecycle = False
                    versioning_status = ""
                    if (size_gb >= BIG_BUCKET_THRESHOLD_GB) or (days_since_last is not None and days_since_last >= STALE_DAYS_THRESHOLD):
                        try:
                            s3r.get_bucket_lifecycle_configuration(Bucket=bn)
                            has_lifecycle = True
                        except Exception:
                            has_lifecycle = False
                        try:
                            v = s3r.get_bucket_versioning(Bucket=bn) or {}
                            versioning_status = (v.get("Status") or "").upper()
                        except Exception:
                            versioning_status = ""

                    # Flags (keep legacy strings)
                    flags: List[str] = []
                    missing = [k for k in REQUIRED_TAG_KEYS if not m["Tags"].get(k)]
                    if missing:
                        flags.append(f"MissingRequiredTags={','.join(missing)}")

                    if size_gb == 0.0 and objects == 0:
                        flags += ["emptybucket", "confidence=100", "safedelete"]

                    if days_since_last is None:
                        flags.append("LastModifiedUnknown")
                    elif days_since_last >= STALE_DAYS_THRESHOLD:
                        flags.append(f"stale_data>{STALE_DAYS_THRESHOLD}d")

                    if not has_lifecycle and size_gb >= BIG_BUCKET_THRESHOLD_GB:
                        flags.append("nolifecycle_for_big_bucket")
                    if not has_lifecycle and (days_since_last or 0) >= 90:
                        flags.append("lifecycle_to_ia_recommended")
                    if versioning_status == "ENABLED" and not has_lifecycle and size_gb >= (BIG_BUCKET_THRESHOLD_GB / 2):
                        flags.append("versioning_wo_noncurrent_expiration")

                    # Pricing (conservative: STANDARD only)
                    s3_std_gb_month = get_price("S3", "STANDARD_GB_MONTH")
                    est_cost = round(size_gb * s3_std_gb_month, 2)

                    potential_saving = None
                    if "lifecycle_to_ia_recommended" in flags:
                        try:
                            s3_ia_gb_month = get_price("S3", "STANDARD_IA_GB_MONTH")
                            delta = max(0.0, s3_std_gb_month - s3_ia_gb_month)
                            potential_saving = round(size_gb * delta * 0.7, 2)  # assume 70% moves to IA
                        except Exception:
                            potential_saving = None

                    signals = {
                        "Region": region,
                        "DaysSinceLastModified": (str(days_since_last) if days_since_last is not None else ""),
                        "Versioning": versioning_status or "",
                        "HasLifecycle": str(bool(has_lifecycle)).lower(),
                    }

                    write_resource_to_csv(
                        writer=writer,
                        resource_id=bn,
                        name=bn,
                        resource_type="S3Bucket",
                        owner_id=ACCOUNT_ID or "",
                        state="",
                        creation_date=m["CreatedISO"],
                        storage_gb=size_gb,
                        estimated_cost=est_cost,
                        app_id=m["Tags"].get("ApplicationID", "NULL"),
                        app=m["Tags"].get("Application", "NULL"),
                        env=m["Tags"].get("Environment", "NULL"),
                        referenced_in="",
                        flags=flags,
                        object_count=objects,
                        potential_saving=potential_saving,
                        confidence=None,
                        signals=signals,
                    )
                except Exception as e:
                    logging.exception(f"[S3] bucket emit failed for {bn} in {region}: {e}")

    except Exception as e:
        logging.exception(f"[S3] check_s3_buckets_refactored failed: {e}")
        return


def _is_wrong_region_error(e: ClientError) -> bool:
    code = (e.response or {}).get("Error", {}).get("Code", "")
    return code in ("PermanentRedirect", "AuthorizationHeaderMalformed", "301", "InvalidRequest")


def _normalize_bucket_region(raw: Optional[str]) -> str:
    # S3 quirks: None => us-east-1, "EU" => eu-west-1
    if not raw:
        return "us-east-1"
    if raw == "EU":
        return "eu-west-1"
    return raw


@retry_with_backoff()
def check_s3_abandoned_multipart_uploads(writer: csv.writer, s3) -> None:
    """
    Fast, global MPU scan:
      • Try global list_multipart_uploads first; only resolve region on 301/redirect.
      • Per-upload, fetch only the FIRST page of parts (MaxParts=1000) by default.
        - Exact if <=1000 parts; otherwise lower bound with 'CostLowerBound' flag.
      • Parallel across buckets, with modest per-bucket concurrency.
      • Keeps CSV schema/flags.
    """
    try:
        cutoff = datetime.now(timezone.utc) - timedelta(days=S3_MULTIPART_STALE_DAYS)
        buckets = s3.list_buckets().get("Buckets", []) or []
        if not buckets:
            return

        findings_count: int = 0
        findings_lock = threading.Lock()

        # Small caches for region-aware retries (used only on redirects)
        s3_client_by_region: Dict[str, Any] = {}

        def get_s3_client_for_region(region: str) -> Any:
            cli = s3_client_by_region.get(region)
            if cli is None:
                try:
                    cli = boto3.client("s3", region_name=region, config=SDK_CONFIG)
                except Exception as e:
                    logging.warning(f"[S3 MPU] init regional client {region} failed: {e}; fallback to global")
                    cli = s3
                s3_client_by_region[region] = cli
            return cli

        def list_stale_uploads_for_bucket(bname: str) -> List[Dict[str, Any]]:
            """
            List stale MPUs for a bucket with the global client first; if we hit a
            region error, resolve region and retry with a regional client.
            """
            stale: List[Dict[str, Any]] = []

            def _list_with(client) -> List[Dict[str, Any]]:
                out: List[Dict[str, Any]] = []
                paginator = client.get_paginator("list_multipart_uploads")
                for page in paginator.paginate(
                    Bucket=bname, PaginationConfig={"PageSize": _S3_MPU_PAGE_SIZE}
                ):
                    uploads = page.get("Uploads", []) or []
                    if not uploads:
                        continue
                    for up in uploads:
                        initiated = up.get("Initiated")
                        if initiated and initiated < cutoff:
                            out.append({
                                "Key": up.get("Key", ""),
                                "UploadId": up.get("UploadId", ""),
                                "Initiated": initiated
                            })
                return out

            try:
                stale = _list_with(s3)
                return stale
            except ClientError as e:
                if _is_wrong_region_error(e):
                    # Resolve region only when necessary
                    try:
                        loc = s3.get_bucket_location(Bucket=bname)
                        region = _normalize_bucket_region(loc.get("LocationConstraint"))
                        s3r = get_s3_client_for_region(region)
                        stale = _list_with(s3r)
                        return stale
                    except Exception as e2:
                        logging.warning(f"[S3 MPU] regional retry failed for {bname}: {e2}")
                        return []
                else:
                    code = e.response.get("Error", {}).get("Code")
                    if code in ("AccessDenied", "AllAccessDisabled", "NoSuchBucket"):
                        logging.info(f"[S3 MPU] Skipping {bname}: {code}")
                        return []
                    logging.warning(f"[S3 MPU] list_multipart_uploads failed for {bname}: {e}")
                    return []
            except Exception as e:
                logging.warning(f"[S3 MPU] {bname} unexpected list_multipart_uploads error: {e}")
                return []

        def parts_first_page_size(s3_client, bname: str, key: str, upload_id: str) -> Tuple[float, bool]:
            """
            Return (bytes_sum_first_page, is_truncated) using a single call.
            """
            try:
                resp = s3_client.list_parts(Bucket=bname, Key=key, UploadId=upload_id, MaxParts=1000)
                parts = resp.get("Parts", []) or []
                total_bytes = float(sum(int(p.get("Size", 0) or 0) for p in parts))
                is_trunc = bool(resp.get("IsTruncated"))
                return total_bytes, is_trunc
            except ClientError as e:
                logging.warning(f"[S3 MPU] list_parts first page failed for {bname}/{key}#{upload_id}: {e}")
                return 0.0, False
            except Exception as e:
                logging.warning(f"[S3 MPU] list_parts first page unexpected for {bname}/{key}#{upload_id}: {e}")
                return 0.0, False

        def process_bucket(bucket_entry: Dict[str, Any]) -> List[Dict[str, Any]]:
            """
            Process one bucket: get stale uploads, then estimate bytes with one
            list_parts call per upload (first page). Returns rows to write.
            """
            nonlocal findings_count
            bname = bucket_entry.get("Name", "")
            if not bname:
                return []

            with findings_lock:
                if findings_count >= _S3_MPU_GLOBAL_FINDINGS_CAP:
                    return []

            # 1) List stale uploads
            stale_uploads = list_stale_uploads_for_bucket(bname)
            if not stale_uploads:
                return []

            # If we had to switch to regional client, re-use it for parts; else use global
            s3_for_parts = s3
            # Try to detect the client we used: if global worked, keep using it.
            # If we need a regional client, list_stale_uploads_for_bucket already fetched region once.

            # 2) Fetch a single parts page per upload (fast path)
            rows_local: List[Dict[str, Any]] = []

            def do_one(upd: Dict[str, Any]) -> Optional[Dict[str, Any]]:
                key = upd.get("Key") or ""
                upload_id = upd.get("UploadId") or ""
                initiated = upd.get("Initiated")
                if not key or not upload_id:
                    return None

                # Try global first; on region error, find region once for parts
                client_used = s3_for_parts
                bytes_first = 0.0
                is_trunc = False
                try:
                    bytes_first, is_trunc = parts_first_page_size(client_used, bname, key, upload_id)
                except Exception:
                    pass  # handled in helper

                if bytes_first == 0.0 and _S3_MPU_PARTS_MODE == "first_page":
                    # Maybe region needed — resolve and retry once
                    try:
                        loc = s3.get_bucket_location(Bucket=bname)
                        region = _normalize_bucket_region(loc.get("LocationConstraint"))
                        client_used = get_s3_client_for_region(region)
                        bytes_first, is_trunc = parts_first_page_size(client_used, bname, key, upload_id)
                    except Exception as e:
                        logging.debug(f"[S3 MPU] parts region retry skipped for {bname}/{key}: {e}")

                # If someone prefers exact sizes at the cost of time:
                if _S3_MPU_PARTS_MODE == "full" and is_trunc:
                    # Fallback to full pagination ONLY when requested
                    try:
                        total = bytes_first
                        paginator = client_used.get_paginator("list_parts")
                        for ppage in paginator.paginate(Bucket=bname, Key=key, UploadId=upload_id,
                                                        PaginationConfig={"PageSize": 1000}):
                            if "Parts" in ppage:
                                total = float(sum(int(p.get("Size", 0) or 0) for p in ppage["Parts"]))
                        bytes_first = total
                        is_trunc = False
                    except Exception as e:
                        logging.warning(f"[S3 MPU] full parts scan failed for {bname}/{key}: {e}")

                gb = round(bytes_first / (1024.0 ** 3), 2)
                est_cost = round(gb * get_price("S3", "STANDARD_GB_MONTH"), 2)

                flags: List[str] = [
                    "AbandonedMultipart>{}d".format(S3_MULTIPART_STALE_DAYS),
                    "Key={}".format(key),
                    "ConsiderAbortMultipartUploads",
                ]
                if _S3_MPU_PARTS_MODE == "first_page" and is_trunc:
                    flags.append("CostLowerBound")  # We saw only first 1000 parts

                # Keep numeric column populated; mark lower-bound if applicable
                if est_cost > 0:
                    flags.append("PotentialSaving={}$".format(est_cost))
                else:
                    flags.append("PotentialSaving≈Low")

                return {
                    "resource_id": "{}/{}#{}".format(bname, key, upload_id),
                    "name": bname,
                    "resource_type": "S3MultipartUpload",
                    "creation_date": initiated.isoformat() if hasattr(initiated, "isoformat") else "",
                    "storage_gb": gb,
                    "estimated_cost": est_cost,
                    "flags": flags
                }

            with ThreadPoolExecutor(max_workers=_S3_MPU_PART_WORKERS) as pool:
                futs = [pool.submit(do_one, u) for u in stale_uploads]
                for f in as_completed(futs):
                    row = f.result()
                    if row:
                        rows_local.append(row)

            # Apply global cap
            with findings_lock:
                if findings_count >= _S3_MPU_GLOBAL_FINDINGS_CAP:
                    return []
                allowed = _S3_MPU_GLOBAL_FINDINGS_CAP - findings_count
                if allowed <= 0:
                    return []
                if len(rows_local) > allowed:
                    rows_local = rows_local[:allowed]
                findings_count += len(rows_local)

            return rows_local

        all_rows: List[Dict[str, Any]] = []
        with ThreadPoolExecutor(max_workers=_S3_MPU_BUCKET_WORKERS) as pool:
            futs = [pool.submit(process_bucket, b) for b in buckets]
            for f in as_completed(futs):
                rows = f.result()
                if rows:
                    all_rows.extend(rows)
                with findings_lock:
                    if findings_count >= _S3_MPU_GLOBAL_FINDINGS_CAP:
                        break

        for r in all_rows:
            write_resource_to_csv(
                writer=writer,
                resource_id=r["resource_id"],
                name=r["name"],
                owner_id=ACCOUNT_ID,
                resource_type=r["resource_type"],
                creation_date=r["creation_date"],
                storage_gb=r["storage_gb"],
                estimated_cost=r["estimated_cost"],
                flags=r["flags"],
            )

    except ClientError as e:
        logging.error(f"[check_s3_abandoned_multipart_uploads] {e}")
    except Exception as e:
        logging.error(f"[check_s3_abandoned_multipart_uploads] fatal: {e}")

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


#region EIP SECTION

@retry_with_backoff()
def check_unused_elastic_ips(writer: csv.writer, ec2):
    try:
        resp = ec2.describe_addresses()
        for addr in resp.get("Addresses", []):
            resource_id_ip = addr.get("AllocationId", addr.get("PublicIp"))
            flags: List[str] = []
            if "InstanceId" not in addr and "NetworkInterfaceId" not in addr:
                flags.append("UnusedElasticIP")
                write_resource_to_csv(
                    writer=writer,
                    resource_id=resource_id_ip,
                    name="",
                    owner_id=ACCOUNT_ID,
                    resource_type="ElasticIP",
                    estimated_cost=get_price("EIP", "UNASSIGNED_MONTH"),
                    flags=flags,
                    confidence=100
                )

            logging.info(f"[check_unused_elastic_ips] Processed IP : {resource_id_ip}")
    except ClientError as e:
        logging.error(f"Error checking Elastic IPs: {e}")

#endregion


#region ENI SECTION

@retry_with_backoff()
def check_detached_network_interfaces(writer: csv.writer, ec2):
    try:
        enis = ec2.describe_network_interfaces().get("NetworkInterfaces", [])
        for eni in enis:
            if eni.get("Status") == "available":
                tags = {tag["Key"]: tag["Value"] for tag in eni.get("TagSet", [])}
                flags = ["DetachedENI"]
                write_resource_to_csv(
                    writer=writer,
                    resource_id=eni["NetworkInterfaceId"],
                    name=tags.get("Name", ""),
                    owner_id=ACCOUNT_ID,
                    resource_type="ENI",
                    state=eni.get("Status", ""),
                    creation_date="",  # Not available in ENI metadata
                    estimated_cost=0.0,
                    flags=flags,
                    confidence=100
                )
    except ClientError as e:
        logging.error(f"Error checking network interfaces: {e}")

#endregion


#region EFS CHECK SECTION

def check_unused_efs_filesystems(
    writer,
    efs, 
    cloudwatch,
) -> None:
    """
    EFS audit using CloudWatch batcher
    - Batches StorageBytes(Standard/IA) + DataReadIOBytes/DataWriteIOBytes + BurstCreditBalance.
    - Cost estimate: STANDARD_GB_MONTH + IA_GB_MONTH (+ Provisioned throughput if present).
    - Writes rows via write_resource_to_csv; returns nothing.
    """
    try:
        region = (
            getattr(getattr(cloudwatch, "meta", None), "region_name", "")
            or getattr(getattr(efs, "meta", None), "region_name", "")
            or ""
        )

        now = datetime.now(timezone.utc)
        lookback_days = max(1, EFS_LOOKBACK_DAYS)
        start = now - timedelta(days=lookback_days)

        # ---------- helpers ----------

        def _tdict(aws_tags):
            if not aws_tags:
                return {}
            return {t.get("Key", ""): t.get("Value", "") for t in aws_tags}

        # ---------- 1) list file systems ----------
        filesystems = []
        marker = None
        while True:
            try:
                args = {"Marker": marker} if marker else {}
                resp = efs.describe_file_systems(**args)
            except ClientError as e:
                logging.error(f"[EFS] describe_file_systems failed in {region}: {e}")
                break
            filesystems.extend(resp.get("FileSystems", []) or [])
            marker = resp.get("NextMarker")
            if not marker:
                break

        if not filesystems:
            return

        # ---------- 2) per-FS metadata (tags + lifecycle config) ----------
        metas = []
        for fs in filesystems:
            try:
                fsid = fs.get("FileSystemId", "")
                arn  = fs.get("FileSystemArn", fsid)
                created = fs.get("CreationTime")
                if isinstance(created, datetime) and created.tzinfo is None:
                    created = created.replace(tzinfo=timezone.utc)

                # tags
                try:
                    tags = _tdict(efs.describe_tags(FileSystemId=fsid).get("Tags", []))
                except ClientError:
                    tags = {}
                except Exception:
                    tags = {}

                # lifecycle policies (to IA/Archive)
                lifecycle = []
                try:
                    lc = efs.describe_lifecycle_configuration(FileSystemId=fsid)
                    lifecycle = lc.get("LifecyclePolicies", []) or []
                except ClientError:
                    lifecycle = []
                except Exception:
                    lifecycle = []

                # throughput mode/provisioned throughput
                tput_mode = (fs.get("ThroughputMode") or "").lower()  # bursting | provisioned | elastic
                prov_mibps = float(fs.get("ProvisionedThroughputInMibps") or 0.0)

                metas.append({
                    "fsid": fsid,
                    "arn": arn,
                    "created": created,
                    "tags": tags,
                    "name": tags.get("Name", fsid),
                    "performance_mode": fs.get("PerformanceMode", ""),
                    "tput_mode": tput_mode,
                    "prov_mibps": prov_mibps,
                    "lifecycle": lifecycle,   # [{'TransitionToIA': 'AFTER_30_DAYS'}, {'TransitionToArchive': 'AFTER_90_DAYS'}, ...]
                })
            except Exception as e:
                logging.warning(f"[EFS] meta failed for {fs.get('FileSystemId','?')} in {region}: {e}")

        if not metas:
            return

        # ---------- 3) batch CW metrics (use passed CW client) ----------
        PERIOD_STORAGE = 86400  # daily for StorageBytes
        PERIOD_IO      = 3600   # hourly for IO/BurstCredit (sum across window)
        batch = cw.CloudWatchBatcher(region, client=cloudwatch)

        for m in metas:
            fsid = m["fsid"]

            dims_std = [{"Name": "FileSystemId", "Value": fsid}, {"Name": "StorageClass", "Value": "Standard"}]
            dims_ia  = [{"Name": "FileSystemId", "Value": fsid}, {"Name": "StorageClass", "Value": "InfrequentAccess"}]
            dims_fs  = [{"Name": "FileSystemId", "Value": fsid}]

            # Storage
            batch.add(cw.MDQ(id=f"efs_std_bytes__{fsid}", namespace="AWS/EFS", metric="StorageBytes", dims=dims_std, stat="Average", period=PERIOD_STORAGE))
            batch.add(cw.MDQ(id=f"efs_ia_bytes__{fsid}",  namespace="AWS/EFS", metric="StorageBytes", dims=dims_ia,  stat="Average", period=PERIOD_STORAGE))

            # IO bytes (sum over lookback)
            batch.add(cw.MDQ(id=f"efs_read__{fsid}",  namespace="AWS/EFS", metric="DataReadIOBytes",  dims=dims_fs, stat="Sum", period=PERIOD_IO))
            batch.add(cw.MDQ(id=f"efs_write__{fsid}", namespace="AWS/EFS", metric="DataWriteIOBytes", dims=dims_fs, stat="Sum", period=PERIOD_IO))

            # Burst credits (latest)
            batch.add(cw.MDQ(id=f"efs_burst__{fsid}", namespace="AWS/EFS", metric="BurstCreditBalance", dims=dims_fs, stat="Average", period=PERIOD_IO))

        try:
            series = batch.execute(start, now, scan_by="TimestampDescending")
        except Exception as e:
            logging.exception(f"[EFS] CloudWatch batch execute failed in {region}: {e}")
            series = {}

        # ---------- 4) pricing ----------
        try:
            p_std = get_price("EFS", "STANDARD_GB_MONTH")
        except Exception:
            p_std = 0.25
        try:
            p_ia = get_price("EFS", "IA_GB_MONTH")
        except Exception:
            p_ia = 0.025
        try:
            p_prov = get_price("EFS", "PROV_TPUT_MIBPS_MONTH")
        except Exception:
            p_prov = 6.0
        # IO/Arch/MT prices exist in your pricebook but are not used here to avoid regressions

        # ---------- 5) emit rows ----------
        for m in metas:
            try:
                fsid = m["fsid"]

                created = m["created"] or now
                if created.tzinfo is None:
                    created = created.replace(tzinfo=timezone.utc)
                created_iso = created.astimezone(timezone.utc).isoformat()

                # latest storage (GB)
                std_bytes = cw.CloudWatchBatcher.latest(series.get(f"efs_std_bytes__{fsid}", []), 0.0)
                ia_bytes  = cw.CloudWatchBatcher.latest(series.get(f"efs_ia_bytes__{fsid}",  []), 0.0)
                std_gb = round(float(std_bytes) / (1024.0 ** 3), 3)
                ia_gb  = round(float(ia_bytes)  / (1024.0 ** 3), 3)

                # IO sums over window (GB/day)
                read_sum  = float(sum(v for _, v in series.get(f"efs_read__{fsid}", [])))
                write_sum = float(sum(v for _, v in series.get(f"efs_write__{fsid}", [])))
                total_io_gb = (read_sum + write_sum) / (1024.0 ** 3)
                avg_io_gb_per_day = total_io_gb / float(lookback_days) if lookback_days > 0 else 0.0

                # Burst credits (latest)
                burst_latest = cw.CloudWatchBatcher.latest(series.get(f"efs_burst__{fsid}", []), 0.0)

                # cost estimate (storage + provisioned throughput if any)
                est_monthly = round(std_gb * p_std + ia_gb * p_ia, 2)
                if m["tput_mode"] == "provisioned" and m["prov_mibps"] > 0:
                    est_monthly = round(est_monthly + (m["prov_mibps"] * p_prov), 2)

                # flags (conservative, no destructive claims)
                flags: List[str] = []
                missing = [k for k in REQUIRED_TAG_KEYS if not m["tags"].get(k)]
                if missing:
                    flags.append(f"MissingRequiredTags={','.join(missing)}")

                # Lifecycle recommendation to IA when large & low daily reads
                has_ia_policy = any("TransitionToIA" in d for d in (m["lifecycle"] or []))
                if std_gb >= EFS_IA_LARGE_THRESHOLD_GB and avg_io_gb_per_day <= EFS_IA_READS_HIGH_GB_PER_DAY and not has_ia_policy:
                    flags.append("efs_lifecycle_to_ia_recommended")

                # Idle-ish FS (very low IO/day)
                if avg_io_gb_per_day <= EFS_IDLE_THRESHOLD_GB_PER_DAY:
                    flags.append("efs_low_io")

                # Low burst credits
                try:
                    if burst_latest > 0 and burst_latest <= float(EFS_BURST_CREDIT_LOW_WATERMARK):
                        flags.append("efs_burst_credits_low")
                except Exception:
                    pass

                # potential saving (heuristic similar to S3: move 70% of std to IA)
                potential = None
                if "efs_lifecycle_to_ia_recommended" in flags:
                    delta = max(0.0, p_std - p_ia)
                    potential = round(std_gb * 0.7 * delta, 2)

                # signals
                signals = {
                    "Region": region,
                    "PerfMode": m.get("performance_mode", ""),
                    "ThroughputMode": m["tput_mode"],
                    "ProvisionedMiBps": f"{m['prov_mibps']:.2f}",
                    "LifecyclePolicies": ",".join(sorted({list(p.keys())[0] for p in (m['lifecycle'] or [])})) if m["lifecycle"] else "",
                    "StorageStandardGB": f"{std_gb:.3f}",
                    "StorageIAGB": f"{ia_gb:.3f}",
                    f"AvgIOGBPerDay{lookback_days}d": f"{avg_io_gb_per_day:.4f}",
                    "BurstCreditBalance": f"{burst_latest:.0f}",
                    "LookbackDays": str(lookback_days),
                }

                # owner/account
                try:
                    owner_id = str(ACCOUNT_ID)
                except NameError:
                    owner_id = ""

                write_resource_to_csv(
                    writer=writer,
                    resource_id=m["arn"] or fsid,
                    name=m["name"],
                    resource_type="EFS",
                    owner_id=owner_id,
                    state="",  # EFS doesn't expose a simple 'state' here
                    creation_date=created_iso,
                    storage_gb=round(std_gb + ia_gb, 3),
                    estimated_cost=est_monthly,
                    app_id=m["tags"].get("ApplicationID", "NULL"),
                    app=m["tags"].get("Application", "NULL"),
                    env=m["tags"].get("Environment", "NULL"),
                    referenced_in="",
                    flags=flags,
                    object_count="",    # n/a
                    potential_saving=potential,
                    confidence=None,    # no auto-delete here
                    signals=signals,
                )
            except Exception as e:
                logging.exception(f"[EFS] emit failed for {m.get('fsid','?')} in {region}: {e}")

    except Exception as e:
        logging.exception(f"[EFS] check_efs_filesystems_refactored failed: {e}")
        return


#endregion --- END EFS SECTION ----------------------------------------------------------


#region LB SECTION

def safe_aws_call(fn: Callable[[], Any], fallback: Any, context: str = "") -> Any:
    """Safely invoke AWS API call, returning fallback on error."""
    try:
        return fn()
    except ClientError as e:
        code = e.response["Error"].get("Code")
        logging.warning(f"[{context}] AWS call failed: {code} {e}")
        return fallback


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
            inter_az_price = get_price("NETWORK", "INTER_AZ_GB", region, None)
        except Exception:
            inter_az_price = None
        if inter_az_price is None:
            try:
                inter_az_price = get_price("NETWORK", "INTER_REGION_GB", region, 0.0)
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


#region BACKUP SECTION

@dataclass
class BackupRuleMetadata:
    plan_id: str
    plan_name: str
    rule_name: str
    schedule: str
    retention_days: Optional[int]
    flags: Set[str] = field(default_factory=set)


def build_backup_rule_metadata(plan: Dict[str, Any], rule: Dict[str, Any]) -> BackupRuleMetadata:
    return BackupRuleMetadata(
        plan_id=plan["BackupPlanId"],
        plan_name=plan["BackupPlanName"],
        rule_name=rule.get("RuleName", ""),
        schedule=rule.get("ScheduleExpression", ""),
        retention_days=rule.get("Lifecycle", {}).get("DeleteAfterDays"),
    )


def check_backup_retention(rule: BackupRuleMetadata) -> List[str]:
    """
    Flag daily backup rules with invalid retention (not in VALID_RETENTION_DAYS).
    """
    if "rate(1 day)" in rule.schedule and rule.retention_days not in VALID_RETENTION_DAYS:
        return [f"MisconfiguredRetention({rule.retention_days})"]
    return []


def check_missing_retention(rule: BackupRuleMetadata) -> List[str]:
    """
    Flag backup rules that have no retention set (keeps backups forever).
    """
    if rule.retention_days is None:
        return ["NoRetentionConfigured"]
    return []


BACKUP_RULE_CHECKS: List[Callable[[BackupRuleMetadata], List[str]]] = [
    check_backup_retention,
    check_missing_retention,
]


@retry_with_backoff()
def check_backup_retention_misconfigurations(writer: csv.writer, backup) -> None:
    """
    Check AWS Backup plans for misconfigured rules:
      - Daily schedule with invalid retention
      - Missing retention (keeps backups forever)

    Logs and writes issues to CSV.
    """
    try:
        plans = safe_aws_call(
            lambda: backup.list_backup_plans().get("BackupPlansList", []),
            [],
            context="Backup:ListPlans",
        )

        for plan in plans:
            details = safe_aws_call(
                lambda: backup.get_backup_plan(BackupPlanId=plan["BackupPlanId"]),
                {},
                context=f"Backup:GetPlan:{plan['BackupPlanName']}",
            )
            rules = details.get("BackupPlan", {}).get("Rules", [])

            for raw_rule in rules:
                rule = build_backup_rule_metadata(plan, raw_rule)

                for check in BACKUP_RULE_CHECKS:
                    rule.flags.update(check(rule))

                if rule.flags:
                    logging.info(
                        f"[Backup:{rule.plan_name}] Rule '{rule.rule_name}' retention={rule.retention_days} flags={rule.flags}"
                    )
                    write_resource_to_csv(
                        writer=writer,
                        resource_id=rule.plan_id,
                        name=rule.rule_name,
                        owner_id=ACCOUNT_ID,
                        resource_type="BackupRule",
                        state="",  # no explicit state field in BackupRule
                        creation_date="",  # Backup rules don’t have a creation timestamp
                        estimated_cost=0,  # retention misconfig doesn’t affect cost directly
                        flags=list(rule.flags),
                    )

    except ClientError as e:
        logging.error(f"[check_backup_retention] AWS error: {e.response['Error'].get('Code')}")
    except Exception as e:
        logging.error(f"[check_backup_retention] Unexpected error: {e}")

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


#region NAT Gateways SECTION


def check_nat_replacement_opps(writer, ec2, cloudwatch):
    region = (getattr(getattr(cloudwatch,"meta",None),"region_name","") or
              getattr(getattr(ec2,"meta",None),"region_name","") or "")
    now = datetime.now(timezone.utc); start = now - timedelta(days=NAT_LOOKBACK_DAYS)
    PERIOD = 300
    # 1) list NATs
    ngws = ec2.describe_nat_gateways().get("NatGateways", [])
    if not ngws: return
    # 2) batch metrics
    batch = cw.CloudWatchBatcher(region, client=cloudwatch)
    for g in ngws:
        gid = g.get("NatGatewayId")
        dims = [{"Name":"NatGatewayId","Value":gid}]
        batch.add_q(id_hint=f"nat_bin_src__{gid}",  namespace="AWS/NATGateway", metric="BytesInFromSource",  dims=dims, stat="Sum", period=PERIOD)
        batch.add_q(id_hint=f"nat_bout_dst__{gid}", namespace="AWS/NATGateway", metric="BytesOutToDestination",dims=dims, stat="Sum", period=PERIOD)
        batch.add_q(id_hint=f"nat_conn__{gid}",     namespace="AWS/NATGateway", metric="ActiveConnectionCount",dims=dims, stat="Average", period=PERIOD)
    series = batch.execute(start, now, scan_by="TimestampDescending")

    # 3) prices
    nat_hr  = get_price("NAT","HOUR",region)
    nat_gb  = get_price("NAT","GB_PROCESSED",region)
    base_mo = nat_hr * HOURS_PER_MONTH

    for g in ngws:
        gid = g["NatGatewayId"]
        bin_sum  = sum(v for _,v in series.get(f"nat_bin_src__{gid}", []))
        bout_sum = sum(v for _,v in series.get(f"nat_bout_dst__{gid}", []))
        bytes_gb = (bin_sum + bout_sum) / (1024**3)
        nat_month = round(base_mo + (bytes_gb * nat_gb), 2)
        confidence=0
        # Heuristic: if most egress is S3/DynamoDB (TODO: Flow Logs),
        # we mark gateway endpoint replacement as a 100% confidence candidate.
        flags = []
        # Optional: if you track per-service NAT shares in Signals elsewhere, use that. Here: simple bytes threshold.
        if bytes_gb >= NAT_IDLE_TRAFFIC_THRESHOLD_GB:  # actively used NAT
            flags.append("nat_replace_with_gateway_endpoints")
            confidence=100

        write_resource_to_csv(
            writer, resource_id=gid, name=gid, resource_type="NAT",
            owner_id=str(ACCOUNT_ID), state=g.get("State",""),
            creation_date=(g.get("CreateTime") or now).astimezone(timezone.utc).isoformat(),
            storage_gb="", estimated_cost=nat_month,
            app_id="NULL", app="NULL", env="NULL", referenced_in="",
            flags=flags, object_count="", potential_saving=nat_month if confidence==100 else None,
            confidence=confidence,
            signals={"Region":region, f"TrafficGB{NAT_LOOKBACK_DAYS}d":f"{bytes_gb:.2f}"},
        )


def check_unused_nat_gateways(
    writer: csv.writer,
    ec2,
    cloudwatch,
) -> None:
    """
    NAT Gateway audit using CloudWatch batcher
    """
    try:
        region = (
            getattr(getattr(cloudwatch, "meta", None), "region_name", "")
            or getattr(getattr(ec2, "meta", None), "region_name", "")
            or ""
        )

        lookback_days = max(1, NAT_LOOKBACK_DAYS)
        now = datetime.now(timezone.utc)
        start = now - timedelta(days=lookback_days)

        # 1) List NATs in this region
        nats = []
        token = None
        while True:
            try:
                if token:
                    resp = ec2.describe_nat_gateways(
                        Filters=[{"Name": "state", "Values": ["available", "pending"]}],
                        NextToken=token
                    )
                else:
                    resp = ec2.describe_nat_gateways(
                        Filters=[{"Name": "state", "Values": ["available", "pending"]}]
                    )
            except ClientError as e:
                logging.error(f"[NAT] describe_nat_gateways failed in {region}: {e}")
                break
            nats.extend(resp.get("NatGateways", []))
            token = resp.get("NextToken")
            if not token:
                break

        if not nats:
            return

        def tags_dict(aws_tags):
            if not aws_tags:
                return {}
            return {t.get("Key", ""): t.get("Value", "") for t in aws_tags}

        # 2) Batch CW metrics for all NATs in this region (use passed CW client)
        batch = cw.CloudWatchBatcher(region, client=cloudwatch)
        for nat in nats:
            nat_id = nat["NatGatewayId"]

            dims = [{"Name": "NatGatewayId", "Value": nat_id}]
            # bytes (sum) — convert to GB later
            batch.add(cw.MDQ(id=f"nat_bin_src__{nat_id}",  namespace="AWS/NATGateway",
                             metric="BytesInFromSource",      dims=dims, stat="Sum", period=3600))
            batch.add(cw.MDQ(id=f"nat_bout_dst__{nat_id}", namespace="AWS/NATGateway",
                             metric="BytesOutToDestination",  dims=dims, stat="Sum", period=3600))
            batch.add(cw.MDQ(id=f"nat_bin_dst__{nat_id}",  namespace="AWS/NATGateway",
                             metric="BytesInFromDestination", dims=dims, stat="Sum", period=3600))
            batch.add(cw.MDQ(id=f"nat_bout_src__{nat_id}", namespace="AWS/NATGateway",
                             metric="BytesOutToSource",       dims=dims, stat="Sum", period=3600))
            # connections (sum)
            batch.add(cw.MDQ(id=f"nat_conn__{nat_id}",     namespace="AWS/NATGateway",
                             metric="ActiveConnectionCount", dims=dims, stat="Sum", period=3600))

        try:
            series = batch.execute(start, now, scan_by="TimestampDescending")
        except Exception as e:
            logging.exception(f"[NAT] CloudWatch batch execute failed in {region}: {e}")
            series = {}

        # 3) Emit rows
        for nat in nats:
            try:
                nat_id = nat["NatGatewayId"]
                state = nat.get("State", "")
                create_time = nat.get("CreateTime")
                if isinstance(create_time, datetime) and create_time.tzinfo is None:
                    create_time = create_time.replace(tzinfo=timezone.utc)
                created_iso = (create_time or now).astimezone(timezone.utc).isoformat()

                tdict = tags_dict(nat.get("Tags", []))
                name = tdict.get("Name", nat_id)

                # Sum bytes across the 4 metrics → GB
                b_sum = 0.0
                for key in (f"nat_bin_src__{nat_id}",
                            f"nat_bout_dst__{nat_id}",
                            f"nat_bin_dst__{nat_id}",
                            f"nat_bout_src__{nat_id}"):
                    b_sum += sum(v for _, v in series.get(key, []))
                gb_processed = float(b_sum) / (1024.0 ** 3)

                # Connections sum
                conn_sum = sum(v for _, v in series.get(f"nat_conn__{nat_id}", []))

                # Region-aware pricing
                try:
                    nat_hour = get_price("NAT", "HOUR", region, default=0.0)
                except Exception:
                    nat_hour = 0.0
                try:
                    nat_gb = get_price("NAT", "GB_PROCESSED", region, default=0.0)
                except Exception:
                    nat_gb = 0.0

                est_monthly = round(nat_hour * HOURS_PER_MONTH + gb_processed * nat_gb, 2)

                # Flags (idle candidate)
                flags = []
                missing = [k for k in REQUIRED_TAG_KEYS if not tdict.get(k)]
                if missing:
                    flags.append(f"MissingRequiredTags={','.join(missing)}")
                if (gb_processed <= NAT_IDLE_TRAFFIC_THRESHOLD_GB) and (conn_sum <= NAT_IDLE_CONNECTION_THRESHOLD):
                    flags.append("idle_nat_candidate")

                # Potential saving & confidence
                potential = round(est_monthly, 2) if "idle_nat_candidate" in flags else None
                confidence = 100 if "idle_nat_candidate" in flags else None

                # Signals (used by policies later)
                signals = {
                    "Region": region,
                    f"DataProcessedGB{lookback_days}d": f"{gb_processed:.3f}",
                    "ActiveConnectionSum": str(int(conn_sum)),
                    "LookbackDays": str(lookback_days),
                }

                write_resource_to_csv(
                    writer=writer,
                    resource_id=nat_id,
                    name=name,
                    resource_type="NATGateway",
                    owner_id=ACCOUNT_ID,
                    state=str(state),
                    creation_date=created_iso,
                    estimated_cost=est_monthly,
                    app_id=tdict.get("ApplicationID", "NULL"),
                    app=tdict.get("Application", "NULL"),
                    env=tdict.get("Environment", "NULL"),
                    referenced_in="",
                    flags=flags,
                    potential_saving=potential,
                    confidence=confidence,
                    signals=signals,
                )
            except Exception as e:
                logging.exception(f"[NAT] emit failed for {nat.get('NatGatewayId','?')} in {region}: {e}")

    except Exception as e:
        logging.exception(f"[NAT] check_nat_gateways_refactored failed: {e}")
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


@retry_with_backoff()
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

@retry_with_backoff()
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


@retry_with_backoff()
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


#region ECR SECTION

@dataclass
class ECRRepositoryMetadata:
    name: str
    arn: str
    total_bytes: int
    size_gb: float
    estimated_cost: float
    stale_images: int = 0
    large_images: int = 0
    flags: list[str] = field(default_factory=list)

# Keep the stale/large thresholds consistent
_ECR_STALE_DAYS = 180
# Use a large page size to reduce API calls (service will cap if higher than allowed)
_ECR_PAGE_SIZE = 1000

def _sum_image_stats_from_page(page, cutoff_dt):
    """Local helper to aggregate a describe_images page."""
    total_bytes = 0
    stale = 0
    large = 0
    for img in page.get("imageDetails", []) or []:
        size = int(img.get("imageSizeInBytes", 0) or 0)
        total_bytes += size
        if size >= 1_000 * 1024 * 1024:  # >= 1 GB
            large += 1
        pushed = img.get("imagePushedAt")
        if pushed and pushed < cutoff_dt:
            stale += 1
    return total_bytes, stale, large

@retry_with_backoff()
def _repo_has_lifecycle_policy(ecr, repo_name: str) -> bool:
    """Return True if the repo has a lifecycle policy, False if not."""
    try:
        ecr.get_lifecycle_policy(repositoryName=repo_name)
        return True
    except getattr(ecr, "exceptions", object()).LifecyclePolicyNotFoundException:  # type: ignore[attr-defined]
        return False
    except ClientError as e:
        # Treat “AccessDenied” or transient issues as unknown; do not block the scan
        logging.warning(f"[ECR] lifecycle policy check for {repo_name} failed: {e}")
        return True  # assume True to avoid noisy "NoLifecyclePolicy" in case of perms issues

@retry_with_backoff()
def _describe_images_iter(ecr, repo_name: str):
    """Yield pages from describe_images with large page size and tagStatus=ANY."""
    paginator = ecr.get_paginator("describe_images")
    # NOTE: boto3 PaginationConfig 'PageSize' maps to service 'maxResults'
    for page in paginator.paginate(
        repositoryName=repo_name,
        filter={"tagStatus": "ANY"},
        PaginationConfig={"PageSize": _ECR_PAGE_SIZE},
    ):
        yield page

@retry_with_backoff()
def build_ecr_repo_metadata_fast(ecr, repo_info: dict) -> Optional[ECRRepositoryMetadata]:
    """
    Faster per-repository aggregation:
      - Single pass over describe_images pages with large page size
      - Optional lifecycle-policy check (fast path)
    """
    repo_name = repo_info.get("repositoryName", "")
    arn = repo_info.get("repositoryArn", "")

    total_bytes = 0
    stale_images = 0
    large_images = 0
    flags: list[str] = []

    cutoff_dt = datetime.now(timezone.utc) - timedelta(days=_ECR_STALE_DAYS)

    # Lifecycle policy (used as a hygiene signal, not a blocker)
    has_lifecycle = _repo_has_lifecycle_policy(ecr, repo_name)
    if not has_lifecycle:
        flags.append("NoLifecyclePolicy")

    # Aggregate images
    try:
        for page in _describe_images_iter(ecr, repo_name):
            t, s, l = _sum_image_stats_from_page(page, cutoff_dt)
            total_bytes += t
            stale_images += s
            large_images += l
    except ClientError as e:
        logging.warning(f"[ECR] describe_images failed for {repo_name}: {e}")
        # If we completely fail to list images, still emit a review row so user investigates
        flags.append("DescribeImagesFailed")
        total_bytes = 0
        stale_images = 0
        large_images = 0

    size_gb = round(total_bytes / (1024 ** 3), 2)
    estimated_cost = round(size_gb * get_price("ECR", "STORAGE_GB_MONTH"), 2)

    if stale_images > 0:
        flags.append(f"StaleImages>={stale_images}@{_ECR_STALE_DAYS}d")
    if large_images > 0:
        flags.append(f"LargeImages>={large_images}")
    if not flags and estimated_cost == 0:
        flags.append("Review")

    return ECRRepositoryMetadata(
        name=repo_name,
        arn=arn,
        total_bytes=total_bytes,
        size_gb=size_gb,
        estimated_cost=estimated_cost,
        stale_images=stale_images,
        large_images=large_images,
        flags=flags,
    )

@retry_with_backoff()
def check_ecr_storage_and_staleness(writer: csv.writer, ecr) -> None:
    """
    Refactored ECR checker:
      - Paginates through repositories
      - Processes repos in parallel (ThreadPoolExecutor)
      - Writes CSV rows on the main thread
    """
    try:
        repos: list[dict] = []
        paginator = ecr.get_paginator("describe_repositories")
        for page in paginator.paginate(PaginationConfig={"PageSize": 1000}):
            repos.extend(page.get("repositories", []) or [])

        if not repos:
            return

        # Choose a sensible level of parallelism without overwhelming API (tune if needed)
        max_workers = min(16, max(4, len(repos)))
        results: list[ECRRepositoryMetadata] = []

        with ThreadPoolExecutor(max_workers=max_workers) as pool:
            futures = {
                pool.submit(build_ecr_repo_metadata_fast, ecr, r): r.get("repositoryName", "?")
                for r in repos
            }
            for fut in as_completed(futures):
                repo_name = futures[fut]
                try:
                    meta = fut.result()
                except Exception as e:
                    logging.error(f"[ECR] repo {repo_name} failed in worker: {e}")
                    meta = None
                if meta and (meta.flags or meta.estimated_cost > 0):
                    results.append(meta)

        # CSV writes in main thread to avoid race conditions on file handle
        for m in results:
            write_resource_to_csv(
                writer=writer,
                resource_id=m.arn,
                name=m.name,
                owner_id=ACCOUNT_ID,
                resource_type="ECRRepository",
                storage_gb=m.size_gb,
                estimated_cost=m.estimated_cost,
                flags=m.flags,
            )
            logging.info(
                f"[ECR] {m.name} size={m.size_gb}GB cost≈{m.estimated_cost}$ flags={m.flags}"
            )

    except ClientError as e:
        logging.error(f"[check_ecr_storage_and_staleness] Failed to describe repositories: {e}")
    except Exception as e:
        logging.error(f"[check_ecr_storage_and_staleness] Unexpected error: {e}")

#endregion


#region VPC/TGW SECTION

@retry_with_backoff()
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


#region EBS SNAPSHOT SECTION

@dataclass
class EBSSnapshotMetadata:
    snapshot_id: str
    volume_size: int
    start_time: Optional[datetime]
    description: str
    tags: Dict[str, str]
    estimated_cost: float = 0.0
    flags: Set[str] = field(default_factory=set)

def estimate_ebs_snapshot_cost(snapshot: EBSSnapshotMetadata) -> float:
    """Estimate monthly cost of an EBS snapshot."""
    return round(snapshot.volume_size * get_price("EBS", "SNAPSHOT_GB_MONTH"), 2)

def check_snapshot_replication(snapshot: EBSSnapshotMetadata, source_snapshot_ids: Set[str]) -> List[str]:
    """
    Flag snapshot if it's replicated:
      - If it's a source of a copy
      - If Description indicates it was copied
    """
    desc = snapshot.description or ""
    if snapshot.snapshot_id in source_snapshot_ids or \
       "Copied from snapshot" in desc or \
       "Copied for DestinationAmi" in desc:
        return ["SnapshotReplicated"]
    return []

@retry_with_backoff()
def check_ebs_snapshot_replication(writer: csv.writer, ec2) -> None:
    """
    Identify EBS snapshots that are replicated to other regions.
    Writes flagged snapshots with estimated monthly storage cost to CSV.
    """
    try:
        snapshots = safe_aws_call(
            lambda: ec2.describe_snapshots(OwnerIds=["self"]).get("Snapshots", []),
            fallback=[],
            context="DescribeSnapshots"
        )

        # First pass: identify snapshots used as source for copies
        source_snapshot_ids: Set[str] = set()
        for snap in snapshots:
            desc = snap.get("Description", "") or ""
            if "Copied for DestinationAmi" in desc and "SourceSnapshot" in desc:
                parts = desc.split("SourceSnapshot")
                if len(parts) > 1:
                    source_id = parts[1].strip().split()[0]
                    source_snapshot_ids.add(source_id)

        # Second pass: build metadata and run checks
        for snap in snapshots:
            snapshot_id = snap.get("SnapshotId", "")
            volume_size = int(snap.get("VolumeSize", 0) or 0)
            start_time = snap.get("StartTime")
            description = snap.get("Description", "") or ""
            tags = {t["Key"]: t["Value"] for t in snap.get("Tags", [])} if snap.get("Tags") else {}

            snapshot = EBSSnapshotMetadata(
                snapshot_id=snapshot_id,
                volume_size=volume_size,
                start_time=start_time if isinstance(start_time, datetime) else None,
                description=description,
                tags=tags
            )
            snapshot.estimated_cost = estimate_ebs_snapshot_cost(snapshot)
            snapshot.flags.update(check_snapshot_replication(snapshot, source_snapshot_ids))

            write_resource_to_csv(
                writer=writer,
                resource_id=snapshot.snapshot_id,
                name=snapshot.tags.get("Name", ""),
                owner_id=ACCOUNT_ID,
                resource_type="EBSSnapshot",
                creation_date=snapshot.start_time.isoformat() if snapshot.start_time else "",
                storage_gb=snapshot.volume_size,
                estimated_cost=snapshot.estimated_cost,
                flags=list(snapshot.flags)
            )

    except ClientError as e:
        logging.error(f"[check_ebs_snapshot_replication] Error retrieving snapshots: {e}")

#endregion


#region DYNAMODB SECTION

@dataclass
class DynamoDBGSI:
    name: str
    storage_gb: float
    prov_rcu: int
    prov_wcu: int
    flags: Set[str] = field(default_factory=set)

@dataclass
class DynamoDBTableMetadata:
    name: str
    arn: str
    storage_gb: float
    billing_mode: str
    table_class: str
    creation_date: str
    prov_rcu: int = 0
    prov_wcu: int = 0
    streams_enabled: bool = False
    ttl_enabled: bool = False
    pitr_enabled: bool = False
    stale_backups: bool = False
    throttled_requests: float = 0.0
    gsi_list: List[DynamoDBGSI] = field(default_factory=list)
    current_monthly_cost: float = 0.0
    flags: Set[str] = field(default_factory=set)
    tags: Dict[str, str] = field(default_factory=dict)


def safe_dynamodb_call(fn: Callable[[], Any], fallback: Any, context: str = "") -> Any:
    """Safely call a DynamoDB API, returning fallback on error."""
    try:
        return fn()
    except ClientError as e:
        code = e.response["Error"].get("Code")
        logging.warning(f"[{context}] DynamoDB API failed: {code} {e}")
        return fallback


def estimate_table_cost(table: DynamoDBTableMetadata, sum_rcu: float, sum_wcu: float, p95_rcu: float, p95_wcu: float) -> float:
    """Estimate current monthly cost based on storage and capacity."""

    storage_cost = 0.0
    if table.table_class == "STANDARD_IA":
        storage_cost = table.storage_gb * get_price("DYNAMODB", "STORAGE_GB_MONTH_STD_IA")
    else:
        storage_cost = table.storage_gb * get_price("DYNAMODB", "STORAGE_GB_MONTH_STD")
    
    # Capacity
    capacity_cost = 0.0
    if table.billing_mode == "PROVISIONED":
        total_rcu = table.prov_rcu + sum(gsi.prov_rcu for gsi in table.gsi_list)
        total_wcu = table.prov_wcu + sum(gsi.prov_wcu for gsi in table.gsi_list)
        capacity_cost = (total_rcu * get_price("DYNAMODB", "RCU_HOUR") + total_wcu * get_price("DYNAMODB", "WCU_HOUR")) * 24 * 30
    else:  # PAY_PER_REQUEST
        capacity_cost = sum_rcu * get_price("DYNAMODB", "OD_RRU") + sum_wcu * get_price("DYNAMODB", "OD_WRU")
    
    return round(storage_cost + capacity_cost, 2)


def flag_table_optimization(table: DynamoDBTableMetadata, sum_rcu: float, sum_wcu: float, p95_rcu: float, p95_wcu: float, DDB_BACKUP_AGE_DAYS: int) -> None:
    """Apply optimization heuristics and add flags & potential savings."""
    flags: Set[str] = set()
    if (sum_rcu + sum_wcu) == 0:
        flags.add("IdleTable")
    if not table.ttl_enabled:
        flags.add("NoTTLConfigured")
    if table.streams_enabled:
        flags.add("StreamsEnabled")
    if table.stale_backups:
        flags.add(f"StaleManualBackups>{DDB_BACKUP_AGE_DAYS}d")
    if table.table_class == "STANDARD" and table.storage_gb >= 10 and (sum_rcu + sum_wcu) < 100_000:
        flags.add("ConsiderStandard-IA")
    if table.pitr_enabled and table.storage_gb >= 50 and (sum_rcu + sum_wcu) < 100_000:
        flags.add("PITREnabledOnColdLargeTable")
    if table.throttled_requests > 0:
        flags.add("SawThrottling")

    # Rightsizing for PROVISIONED tables
    potential_saving = 0.0
    if table.billing_mode == "PROVISIONED":
        def rightsize(current: int, p95_sum: float) -> Tuple[bool, int]:
            if current <= 0:
                return False, current
            threshold = 0.3 * (current * 24)
            if p95_sum < threshold:
                new_per_hour = max(1, int((1.2 * p95_sum) / 24.0))
                return True, new_per_hour
            return False, current

        r_over, new_r = rightsize(table.prov_rcu, p95_rcu)
        w_over, new_w = rightsize(table.prov_wcu, p95_wcu)
        if r_over:
            flags.add(f"OverProvisionedRCU(cur={table.prov_rcu},->~{new_r})")
            potential_saving += (max(0, table.prov_rcu - new_r) * get_price("DYNAMODB", "RCU_HOUR")) * 24 * 30
        if w_over:
            flags.add(f"OverProvisionedWCU(cur={table.prov_wcu},->~{new_w})")
            potential_saving += (max(0, table.prov_wcu - new_w) * get_price("DYNAMODB", "WCU_HOUR")) * 24 * 30
        
        # Candidate for PAY_PER_REQUEST
        total_days = max(1, len([sum_rcu]))
        avg_daily_rcu = sum_rcu / total_days
        avg_daily_wcu = sum_wcu / total_days
        very_low_util = (
            avg_daily_rcu < 0.1 * (table.prov_rcu * 24) and
            avg_daily_wcu < 0.1 * (table.prov_wcu * 24) and
            p95_rcu < 0.4 * (table.prov_rcu * 24) and
            p95_wcu < 0.4 * (table.prov_wcu * 24)
        )
        if very_low_util and (sum_rcu + sum_wcu) > 0:
            flags.add("CandidatePAY_PER_REQUEST")
            current_capacity_cost = (
            (table.prov_rcu + sum(gsi.prov_rcu for gsi in table.gsi_list)) * get_price("DYNAMODB","RCU_HOUR") +
            (table.prov_wcu + sum(gsi.prov_wcu for gsi in table.gsi_list)) * get_price("DYNAMODB","WCU_HOUR")
            ) * 24 * 30
            ondemand_cost = sum_rcu * get_price("DYNAMODB","OD_RRU") + sum_wcu * get_price("DYNAMODB","OD_WRU")
            delta = round(max(0.0, current_capacity_cost - ondemand_cost), 2)
            if delta > 0.01:
                potential_saving += delta
        
    if potential_saving > 0.01:
        flags.add(f"PotentialSaving={round(potential_saving,2)}$")

    table.flags.update(flags)


def check_dynamodb_cost_optimization(
    writer,
    dynamodb,
    cloudwatch,
) -> None:
    """
    Analyze DynamoDB tables/GSIs for FinOps opportunities using a single
    CloudWatch GetMetricData batch per table, then enrich results with
    burstiness, hot‑GSI, and TTL‑effectiveness intelligence.

    Pipeline:
      1) Describe table (size, billing mode, class, provisioned throughput, streams).
      2) Collect TTL, PITR, manual‑backup hygiene, and tags.
      3) Fetch daily SUM series for RCU/WCU/Throttled (+ TTL deletes if available)
         for the table + all GSIs via one GetMetricData batch.
      4) Estimate monthly cost and apply existing rightsizing flags
         via `flag_table_optimization`.
      5) Add smarter signals
      6) Emit the table row (with Confidence/Signals) and optional rows for under‑utilized GSIs.

    CSV:
      - resource_type: 'DynamoDBTable' (tables) or 'DynamoDBGSI' (per‑index insights)
      - estimated_cost: monthly estimate (storage + capacity)
      - confidence/signals: evidence strength & diagnostics
    """

    try:
        region = (
            getattr(getattr(cloudwatch, "meta", None), "region_name", "")
            or getattr(getattr(dynamodb, "meta", None), "region_name", "")
            or ""
        )

        now = datetime.now(timezone.utc)
        lookback_days = max(1, DDB_LOOKBACK_DAYS)
        start = now - timedelta(days=lookback_days)
        PERIOD = max(60, int(globals().get("_DDB_CW_PERIOD", DDB_CW_PERIOD)))
        LOOKBACK_SECONDS = lookback_days * 24 * 3600

        # ---------- helpers ----------

        def _tdict(aws_tags):
            if not aws_tags:
                return {}
            return {t.get("Key", ""): t.get("Value", "") for t in aws_tags}

        # ---------- 1) list tables ----------
        tables = []
        token = None
        while True:
            try:
                resp = dynamodb.list_tables(ExclusiveStartTableName=token) if token else dynamodb.list_tables()
            except ClientError as e:
                logging.error(f"[DDB] list_tables failed in {region}: {e}")
                break
            tables.extend(resp.get("TableNames", []))
            token = resp.get("LastEvaluatedTableName")
            if not token:
                break

        if not tables:
            return

        # ---------- 2) describe tables + tags + TTL + PITR + recent backups ----------
        metas = []

        def _describe_and_meta(tname: str) -> Optional[Dict[str, Any]]:
            try:
                td = dynamodb.describe_table(TableName=tname)["Table"]
            except ClientError as e:
                logging.warning(f"[DDB] describe_table({tname}) failed in {region}: {e}")
                return None

            arn = td.get("TableArn", "")
            # Tags
            tags = {}
            try:
                if arn:
                    tg = dynamodb.list_tags_of_resource(ResourceArn=arn).get("Tags", [])
                    tags = _tdict(tg)
            except ClientError:
                tags = {}
            except Exception:
                tags = {}

            # TTL
            ttl_status = ""
            try:
                ttl = dynamodb.describe_time_to_live(TableName=tname)
                ttl_desc = ttl.get("TimeToLiveDescription") or {}
                ttl_status = str(ttl_desc.get("TimeToLiveStatus") or "")
            except ClientError:
                ttl_status = ""
            except Exception:
                ttl_status = ""

            # PITR
            pitr_status = ""
            try:
                pitr = dynamodb.describe_continuous_backups(TableName=tname)
                cs = (pitr.get("ContinuousBackupsDescription") or {}).get("PointInTimeRecoveryDescription") or {}
                pitr_status = str(cs.get("PointInTimeRecoveryStatus") or "")
            except ClientError:
                pitr_status = ""
            except Exception:
                pitr_status = ""

            # Recent backups (bounded window)
            backup_age_days = None
            try:
                lb = dynamodb.list_backups(
                    TableName=tname,
                    TimeRangeLowerBound=now - timedelta(days=int(DDB_BACKUP_AGE_DAYS)),
                    TimeRangeUpperBound=now,
                )
                backs = lb.get("BackupSummaries", []) or []
                if backs:
                    last_backup_time = max((b.get("BackupCreationDateTime") for b in backs if b.get("BackupCreationDateTime")), default=None)
                    if last_backup_time:
                        if isinstance(last_backup_time, datetime) and last_backup_time.tzinfo is None:
                            last_backup_time = last_backup_time.replace(tzinfo=timezone.utc)
                        backup_age_days = (now - last_backup_time).days
            except ClientError:
                backup_age_days = None
            except Exception:
                backup_age_days = None

            return {
                "name": tname,
                "arn": arn,
                "status": td.get("TableStatus", ""),
                "created": td.get("CreationDateTime"),
                "billing_mode": ((td.get("BillingModeSummary") or {}).get("BillingMode") or "PROVISIONED"),
                "rcu_prov": int(((td.get("ProvisionedThroughput") or {}).get("ReadCapacityUnits") or 0)),
                "wcu_prov": int(((td.get("ProvisionedThroughput") or {}).get("WriteCapacityUnits") or 0)),
                "size_bytes": int(td.get("TableSizeBytes", 0) or 0),
                "item_count": int(td.get("ItemCount", 0) or 0),
                "gsi": [g.get("IndexName") for g in (td.get("GlobalSecondaryIndexes") or [])],
                "tags": tags,
                "ttl_status": ttl_status,
                "pitr_status": pitr_status,
                "backup_age_days": backup_age_days,
            }

        meta_workers = int(globals().get("_DDB_META_WORKERS", 4))
        from concurrent.futures import ThreadPoolExecutor, as_completed
        with ThreadPoolExecutor(max_workers=meta_workers) as ex:
            futs = [ex.submit(_describe_and_meta, t) for t in tables]
            for f in as_completed(futs):
                m = f.result()
                if m:
                    metas.append(m)

        if not metas:
            return

        # ---------- 3) batch CW metrics per table (use passed CW client) ----------
        batch = cw.CloudWatchBatcher(region, client=cloudwatch)
        gsi_limit = globals().get("_DDB_GSI_METRICS_LIMIT", None)

        for m in metas:
            tname = m["name"]

            dims = [{"Name": "TableName", "Value": tname}]
            # Table-level consumption
            batch.add(cw.MDQ(id=f"ddb_rcu__{tname}", namespace="AWS/DynamoDB",
                             metric="ConsumedReadCapacityUnits",  dims=dims, stat="Sum", period=PERIOD))
            batch.add(cw.MDQ(id=f"ddb_wcu__{tname}", namespace="AWS/DynamoDB",
                             metric="ConsumedWriteCapacityUnits", dims=dims, stat="Sum", period=PERIOD))
            batch.add(cw.MDQ(id=f"ddb_thr__{tname}", namespace="AWS/DynamoDB",
                             metric="ThrottledRequests",          dims=dims, stat="Sum", period=PERIOD))

            # Optional GSIs (respect cap)
            gsis = m["gsi"] or []
            if gsi_limit is None:
                selected_gsis = gsis
            else:
                try:
                    lim = int(gsi_limit)
                    selected_gsis = [] if lim <= 0 else gsis[:lim]
                except Exception:
                    selected_gsis = gsis

            for idx_name in selected_gsis:
                idims = [{"Name": "TableName", "Value": tname},
                         {"Name": "GlobalSecondaryIndexName", "Value": idx_name}]
                batch.add(cw.MDQ(id=f"ddb_rcu_gsi__{idx_name}", namespace="AWS/DynamoDB",
                                 metric="ConsumedReadCapacityUnits",  dims=idims, stat="Sum", period=PERIOD))
                batch.add(cw.MDQ(id=f"ddb_wcu_gsi__{idx_name}", namespace="AWS/DynamoDB",
                                 metric="ConsumedWriteCapacityUnits", dims=idims, stat="Sum", period=PERIOD))

        try:
            series = batch.execute(start, now, scan_by="TimestampDescending")
        except Exception as e:
            logging.exception(f"[DDB] CloudWatch batch execute failed in {region}: {e}")
            series = {}

        # ---------- 4) pricing ----------
        try:
            rcu_hr = get_price("DYNAMODB", "RCU_HOUR")
        except Exception:
            rcu_hr = 0.00013
        try:
            wcu_hr = get_price("DYNAMODB", "WCU_HOUR")
        except Exception:
            wcu_hr = 0.00065
        try:
            storage_std = get_price("DYNAMODB", "STORAGE_GB_MONTH_STD")
        except Exception:
            storage_std = 0.25

        # ---------- 5) emit rows ----------
        for m in metas:
            try:
                tname = m["name"]

                created = m["created"] or now
                if isinstance(created, datetime) and created.tzinfo is None:
                    created = created.replace(tzinfo=timezone.utc)
                created_iso = created.astimezone(timezone.utc).isoformat()

                billing = (m["billing_mode"] or "PROVISIONED").upper()
                rcu_p = int(m["rcu_prov"] or 0)
                wcu_p = int(m["wcu_prov"] or 0)
                size_gb = round(float(m["size_bytes"]) / (1024.0 ** 3), 3)
                item_count = int(m["item_count"] or 0)

                # Consumption (table + limited GSI)
                rcu_sum = float(sum(v for _, v in series.get(f"ddb_rcu__{tname}", [])))
                wcu_sum = float(sum(v for _, v in series.get(f"ddb_wcu__{tname}", [])))
                thr_sum = float(sum(v for _, v in series.get(f"ddb_thr__{tname}", [])))

                gsis = m["gsi"] or []
                if gsi_limit is None:
                    selected_gsis = gsis
                else:
                    try:
                        lim = int(gsi_limit)
                        selected_gsis = [] if lim <= 0 else gsis[:lim]
                    except Exception:
                        selected_gsis = gsis
                for idx_name in selected_gsis:
                    rcu_sum += float(sum(v for _, v in series.get(f"ddb_rcu_gsi__{idx_name}", [])))
                    wcu_sum += float(sum(v for _, v in series.get(f"ddb_wcu_gsi__{idx_name}", [])))

                compute_month = 0.0
                if billing == "PROVISIONED":
                    compute_month = round((rcu_hr * rcu_p + wcu_hr * wcu_p) * HOURS_PER_MONTH, 2)
                # OD remains storage-only (conservative)

                est_monthly = round(compute_month + (size_gb * storage_std), 2)

                # Flags (conservative)
                flags: List[str] = []
                missing = [k for k in REQUIRED_TAG_KEYS if not m["tags"].get(k)]
                if missing:
                    flags.append(f"MissingRequiredTags={','.join(missing)}")

                # Low utilization for PROVISIONED (no throttles)
                if billing == "PROVISIONED" and (rcu_p > 0 or wcu_p > 0):
                    denom_read  = max(1.0, rcu_p * LOOKBACK_SECONDS)
                    denom_write = max(1.0, wcu_p * LOOKBACK_SECONDS)
                    util_r = rcu_sum / denom_read
                    util_w = wcu_sum / denom_write
                    util = max(util_r, util_w)
                    if util < 0.2 and thr_sum == 0.0:
                        flags.append("ddb_low_utilization")

                if thr_sum > 0.0:
                    flags.append("ddb_throttled")

                if item_count == 0 and size_gb == 0.0 and billing == "PROVISIONED" and (rcu_p > 0 or wcu_p > 0):
                    flags.append("ddb_empty_provisioned")

                # Confidence & potential (stay conservative)
                confidence = None
                potential = None
                if "ddb_low_utilization" in flags and billing == "PROVISIONED":
                    potential = compute_month
                if "ddb_empty_provisioned" in flags:
                    potential = compute_month

                # Signals (including TTL/PITR/backup info)
                signals = {
                    "Region": region,
                    "BillingMode": billing,
                    "RCU_Prov": str(rcu_p),
                    "WCU_Prov": str(wcu_p),
                    f"RCU_Sum{lookback_days}d": f"{rcu_sum:.0f}",
                    f"WCU_Sum{lookback_days}d": f"{wcu_sum:.0f}",
                    f"Throttled{lookback_days}d": f"{thr_sum:.0f}",
                    "ItemCount": str(item_count),
                    "StorageGB": f"{size_gb:.3f}",
                    "TTL": m.get("ttl_status", ""),
                    "PITR": m.get("pitr_status", ""),
                    "BackupAgeDays": "" if m.get("backup_age_days") is None else str(int(m["backup_age_days"])),
                    "LookbackDays": str(lookback_days),
                }

                # Name
                name = m["tags"].get("Name", tname)

                write_resource_to_csv(
                    writer=writer,
                    resource_id=m["arn"] or tname,
                    name=name,
                    resource_type="DynamoDBTable",
                    owner_id=ACCOUNT_ID,
                    state=m["status"] or "",
                    creation_date=created_iso,
                    storage_gb=size_gb,
                    estimated_cost=est_monthly,
                    app_id=m["tags"].get("ApplicationID", "NULL"),
                    app=m["tags"].get("Application", "NULL"),
                    env=m["tags"].get("Environment", "NULL"),
                    referenced_in="",
                    flags=flags,
                    object_count=item_count,
                    potential_saving=potential,
                    confidence=confidence,
                    signals=signals,
                )
            except Exception as e:
                logging.exception(f"[DDB] emit failed for {m.get('name','?')} in {region}: {e}")

    except Exception as e:
        logging.exception(f"[DDB] check_dynamodb_tables_refactored failed: {e}")
        return


#endregion


#region FSR SECTION

@retry_with_backoff()
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
@retry_with_backoff()
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


#region EBS SECTION

@dataclass
class EBSVolumeMetadata:
    volume_id: str
    name: str
    volume_type: str
    size_gb: int
    iops: int
    throughput: int
    state: str
    tags: Dict[str, str]
    monthly_cost: float = 0.0
    flags: Set[str] = field(default_factory=set)


def estimate_ebs_cost(vol: EBSVolumeMetadata) -> float:
    """Estimate monthly cost for the EBS volume including add-ons (gp3)."""
    if vol.volume_type == "gp2":
        return round(vol.size_gb * get_price("EBS", "GP2_GB_MONTH"), 2)
    elif vol.volume_type == "gp3":
        base = vol.size_gb * get_price("EBS", "GP3_GB_MONTH")
        addl_iops = max(0, vol.iops - 3000)
        addl_tput = max(0, vol.throughput - 125)
        addl_cost = addl_iops * get_price("EBS", "GP3_IOPS_PER_MONTH") + addl_tput * get_price("EBS", "GP3_TPUT_MIBPS_MONTH")
        return round(base + addl_cost, 2)
    else:
        return 0.0


def check_unattached_volume(vol: EBSVolumeMetadata) -> List[str]:
    if vol.state == "available" and vol.size_gb > 0:
        flags = ["UnattachedEBSVolume"]
        if vol.monthly_cost > 0:
            flags.append(f"PotentialSaving={vol.monthly_cost}$")
        return flags
    return []

@retry_with_backoff()
def check_ebs_unattached_and_rightsize(
    writer: csv.writer,
    ec2,
    cloudwatch,
    chunk_size: int = 120,
    max_workers: int = 3,
) -> None:
    """
    Fast EBS analyzer:
      • Scans volumes via DescribeVolumes (paged) with large page size
      • Early-exits & writes unattached volumes (no CloudWatch)
      • Batches CloudWatch GetMetricData per chunk for attached volumes
      • Computes cold-volume, gp3 over-provision, io1/io2 -> consider gp3 in one pass
      • Writes exactly one row per volume with all flags

    Tunables:
      chunk_size  : volumes per CW batch (<= ~120 is safe; 4 metrics/vol → ~480 MDQs)
      max_workers : # of chunk workers; keep low (<=4) to avoid API throttling
    """
    try:
        region = getattr(getattr(cloudwatch, "meta", None), "region_name", "") or ec2.meta.region_name
        end = datetime.now(timezone.utc)
        start = end - timedelta(days=30)
        period = 86400

        # 1) Gather volumes and process in chunks
        paginator = ec2.get_paginator("describe_volumes")
        page_iter = paginator.paginate(PaginationConfig={"PageSize": 500})

        # Storage for pending chunk (attached volumes only)
        pending_chunk: list[dict] = []

        # To write rows after processing (keep CSV writes single-threaded for safety)
        rows_to_write: list[tuple[dict, list[str], float]] = []  # (vol_meta_dict, flags, monthly_cost)

        def process_chunk(chunk: list[dict]) -> list[tuple[dict, list[str], float]]:
            """
            Process a chunk of *attached* volumes:
              - Build one CW batch for bytes and/or ops
              - Apply heuristics
              - Return list of (vol_meta, flags, monthly_cost)
            """
            if not chunk:
                return []

            vol_meta: dict[str, dict] = {}
            need_bytes: set[str] = set()  # for cold-volume check
            need_ops: set[str] = set()    # for gp3/io1/io2 checks

            for v in chunk:
                vid = v["VolumeId"]
                vtype = (v.get("VolumeType") or "").lower()
                size_gb = int(v.get("Size", 0) or 0)
                iops = int(v.get("Iops", 0) or 0)
                throughput = int(v.get("Throughput", 0) or 0)
                state = v.get("State", "")
                tags = {t["Key"]: t["Value"] for t in v.get("Tags", [])} if v.get("Tags") else {}

                meta = {
                    "volume_id": vid,
                    "name": tags.get("Name", ""),
                    "volume_type": vtype,
                    "size_gb": size_gb,
                    "iops": iops,
                    "throughput": throughput,
                    "state": state,
                    "tags": tags,
                }
                vol_meta[vid] = meta

                need_bytes.add(vid)

                # Collect ops for gp3 & io1/io2 only
                if vtype in ("gp3", "io1", "io2"):
                    need_ops.add(vid)

            # 1 batch: build MDQs & fetch
            mdqs, id_index = _ebs_build_mdqs(list(vol_meta.keys()), need_bytes, need_ops, period=period)
            md = _ebs_collect_cw(region, mdqs, start, end)

            # Apply heuristics and build results
            out: list[tuple[dict, list[str], float]] = []
            for vid, meta in vol_meta.items():
                vtype = meta["volume_type"]
                size_gb = meta["size_gb"]
                iops = meta["iops"]
                throughput = meta["throughput"]
                tags = meta["tags"]

                vol = EBSVolumeMetadata(
                    volume_id=vid,
                    name=meta["name"],
                    volume_type=vtype,
                    size_gb=size_gb,
                    iops=iops,
                    throughput=throughput,
                    state=meta["state"],
                    tags=tags,
                )
                monthly_cost = estimate_ebs_cost(vol)

                flags: set[str] = set()

                # ---- Cold volume (attached only) ----
                # Sum 30d bytes
                rb = _sum_values(md.get(id_index.get((vid, "VolumeReadBytes"), ""), []))
                wb = _sum_values(md.get(id_index.get((vid, "VolumeWriteBytes"), ""), []))
                total_bytes = rb + wb
                # Threshold: < 1 GB per 100 GB of volume over 30d (same heuristic)
                threshold_bytes = max(1, size_gb // 100) * (1024 ** 3)
                if total_bytes <= threshold_bytes and size_gb > 0:
                    flags.add(f"ColdVolume30d(io≈{round(total_bytes/(1024**3), 2)}GB)")
                    flags.add("ConsiderSnapshotAndShrinkOrDetach")

                # ---- gp2 -> gp3 savings (no CW) ----
                if vtype == "gp2" and size_gb > 0:
                    gp2 = get_price("EBS", "GP2_GB_MONTH")
                    gp3 = get_price("EBS", "GP3_GB_MONTH")
                    delta = (gp2 - gp3) * size_gb
                    if delta > 0.01:
                        flags.add("ConsiderGP3")
                        flags.add(f"PotentialSaving={round(delta,2)}$")

                # ---- gp3 over-provision (uses ops + bytes) ----
                if vtype == "gp3" and size_gb > 0:
                    ro = _sum_values(md.get(id_index.get((vid, "VolumeReadOps"), ""), []))
                    wo = _sum_values(md.get(id_index.get((vid, "VolumeWriteOps"), ""), []))
                    total_ops = ro + wo
                    seconds = 30 * 24 * 3600
                    avg_ops_sec = total_ops / seconds if total_ops else 0.0
                    avg_mibps = (total_bytes / seconds) / (1024 ** 2)

                    suggested_iops = max(3000, int(avg_ops_sec * 1.5))
                    suggested_tput = max(125, int(avg_mibps * 1.5))
                    reduce_iops = max(0, iops - suggested_iops)
                    reduce_tput = max(0, throughput - suggested_tput)

                    potential = 0.0
                    if reduce_iops > 0:
                        current_addl_iops = max(0, iops - 3000)
                        new_addl_iops = max(0, suggested_iops - 3000)
                        potential += max(0, current_addl_iops - new_addl_iops) * get_price("EBS", "GP3_IOPS_PER_MONTH")
                    if reduce_tput > 0:
                        current_addl_tput = max(0, throughput - 125)
                        new_addl_tput = max(0, suggested_tput - 125)
                        potential += max(0, current_addl_tput - new_addl_tput) * get_price("EBS", "GP3_TPUT_MIBPS_MONTH")

                    if potential > 0.01:
                        flags.add(f"OverProvisionedGP3(curIOPS={iops},->~{suggested_iops}; curTPUT={throughput}MiB/s,->~{suggested_tput}MiB/s)")
                        flags.add(f"PotentialSaving={round(potential,2)}$")

                # ---- io1/io2 -> consider gp3 (uses ops) ----
                if vtype in ("io1", "io2"):
                    ro = _sum_values(md.get(id_index.get((vid, "VolumeReadOps"), ""), []))
                    wo = _sum_values(md.get(id_index.get((vid, "VolumeWriteOps"), ""), []))
                    total_ops = ro + wo
                    seconds = 30 * 24 * 3600
                    avg_ops_sec = total_ops / seconds if total_ops else 0.0
                    if avg_ops_sec < 200:
                        flags.add("ConsiderGP3")

                if flags:
                    out.append((meta, list(flags), monthly_cost))

            return out

        # Optional chunk-level concurrency
        from concurrent.futures import ThreadPoolExecutor, as_completed
        futures = []
        results_accum: list[tuple[dict, list[str], float]] = []

        def flush_chunk():
            nonlocal futures, results_accum, pending_chunk
            if not pending_chunk:
                return
            chunk = pending_chunk
            pending_chunk = []
            if max_workers > 1:
                futures.append(executor.submit(process_chunk, chunk))
            else:
                results_accum.extend(process_chunk(chunk))

        # 2) Iterate pages
        if max_workers > 1:
            executor = ThreadPoolExecutor(max_workers=max_workers)

        try:
            for page in page_iter:
                for v in page.get("Volumes", []) or []:
                    vid = v["VolumeId"]
                    state = v.get("State", "")
                    vtype = (v.get("VolumeType") or "").lower()
                    size_gb = int(v.get("Size", 0) or 0)
                    iops = int(v.get("Iops", 0) or 0)
                    throughput = int(v.get("Throughput", 0) or 0)
                    tags = {t["Key"]: t["Value"] for t in v.get("Tags", [])} if v.get("Tags") else {}
                    name = tags.get("Name", "")

                    # Build light meta for possible early decision
                    vol = EBSVolumeMetadata(
                        volume_id=vid,
                        name=name,
                        volume_type=vtype,
                        size_gb=size_gb,
                        iops=iops,
                        throughput=throughput,
                        state=state,
                        tags=tags,
                    )
                    monthly_cost = estimate_ebs_cost(vol)

                    # (a) Unattached volumes → fast path (write now, skip CW)
                    if state == "available" and size_gb > 0:
                        flags = set(["UnattachedEBSVolume"])
                        if monthly_cost > 0:
                            flags.add(f"PotentialSaving={monthly_cost}$")
                        rows_to_write.append((
                            {
                                "volume_id": vid, "name": name, "volume_type": vtype, "size_gb": size_gb,
                                "state": state, "tags": tags
                            },
                            list(flags),
                            monthly_cost
                        ))
                        continue

                    # (b) Attached → add to CW chunk
                    pending_chunk.append(v)
                    if len(pending_chunk) >= chunk_size:
                        flush_chunk()

            flush_chunk()

            # Collect futures if used
            if futures:
                for f in as_completed(futures):
                    try:
                        results_accum.extend(f.result())
                    except Exception as e:
                        logging.error(f"[EBS] chunk worker failed: {e}")

            # Combine results to write
            for meta, flags, monthly_cost in results_accum:
                rows_to_write.append((meta, flags, monthly_cost))

            for meta, flags, monthly_cost in rows_to_write:
                tags = meta.get("tags", {})
                write_resource_to_csv(
                    writer=writer,
                    resource_id=meta["volume_id"],
                    name=meta.get("name", ""),
                    resource_type="EBSVolume",
                    owner_id=ACCOUNT_ID,
                    state=meta.get("state", ""),
                    storage_gb=meta.get("size_gb", 0),
                    estimated_cost=monthly_cost,
                    app_id=tags.get("ApplicationID", "NULL"),
                    app=tags.get("Application", "NULL"),
                    env=tags.get("Environment", "NULL"),
                    flags=flags
                )

        finally:
            if max_workers > 1:
                executor.shutdown(wait=True)

    except ClientError as e:
        logging.error(f"[check_ebs_unattached_and_rightsize] AWS error: {e}")
    except Exception as e:
        logging.error(f"[check_ebs_unattached_and_rightsize] Unexpected error: {e}")

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


@retry_with_backoff()
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


@retry_with_backoff()
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

@retry_with_backoff()
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
@retry_with_backoff()
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


@retry_with_backoff()
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


@retry_with_backoff()
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

@retry_with_backoff()
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

@retry_with_backoff()
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

@retry_with_backoff()
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


@retry_with_backoff()
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

@retry_with_backoff()
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


@retry_with_backoff()
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


#region KINESIS SECTION

@dataclass
class KinesisStreamMetadata:
    name: str
    arn: str
    shards: int
    status: str
    creation_date: str
    hourly_price: float
    monthly_cost: float
    flags: Set[str] = field(default_factory=set)


def estimate_kinesis_cost(shards: int) -> float:
    price = get_price("KINESIS", "SHARD_HOUR") or 0.0
    return round(shards * price * 24 * 30, 2)


def build_kinesis_metadata(summary: Dict[str, Any]) -> KinesisStreamMetadata:
    name = summary.get("StreamName", "")
    arn = summary.get("StreamARN", "")
    shards = summary.get("OpenShardCount", 0)
    status = summary.get("StreamStatus", "")
    created = summary.get("StreamCreationTimestamp")
    created_str = created.isoformat() if hasattr(created, "isoformat") else str(created or "")

    monthly_cost = estimate_kinesis_cost(shards)
    hourly_price = get_price("KINESIS", "SHARD_HOUR") or 0.0

    return KinesisStreamMetadata(
        name=name,
        arn=arn,
        shards=shards,
        status=status,
        creation_date=created_str,
        hourly_price=hourly_price,
        monthly_cost=monthly_cost,
    )


def check_kinesis_idle(cw, stream: KinesisStreamMetadata, days: int = 30, threshold: int = 10) -> List[str]:
    """Check if stream has negligible activity in last N days."""
    end = datetime.now(timezone.utc)
    start = end - timedelta(days=days)

    def sum_metric(metric: str, stat="Sum") -> float:
        resp = safe_aws_call(
            lambda: cw.get_metric_statistics(
                Namespace="AWS/Kinesis",
                MetricName=metric,
                Dimensions=[{"Name": "StreamName", "Value": stream.name}],
                StartTime=start,
                EndTime=end,
                Period=86400,
                Statistics=[stat],
            ),
            {"Datapoints": []},
            context=f"Kinesis:{stream.name}:{metric}",
        )
        return float(sum(dp.get(stat, 0.0) for dp in resp.get("Datapoints", [])))

    incoming = sum_metric("IncomingRecords")
    outgoing = sum_metric("GetRecords.Records")
    activity = incoming + outgoing

    if activity < threshold:
        return [f"Idle({days}d,activity≈{int(activity)})"]
    return []


# registry of checks
KINESIS_CHECKS: List[Callable[..., List[str]]] = [
    check_kinesis_idle,
]


@retry_with_backoff()
def check_kinesis_streams(writer: csv.writer, kinesis, cw) -> None:
    """
    Identify potentially wasteful Kinesis Streams:
      - Idle (no traffic in last N days)
    Writes flagged streams with estimated shard-hour burn.
    """
    try:
        paginator = kinesis.get_paginator("list_streams")
        for page in paginator.paginate():
            for name in page.get("StreamNames", []):
                summary = safe_aws_call(
                    lambda: kinesis.describe_stream_summary(StreamName=name)["StreamDescriptionSummary"],
                    {},
                    context=f"Kinesis:{name}:DescribeSummary",
                )
                if not summary:
                    continue

                stream = build_kinesis_metadata(summary)

                for check in KINESIS_CHECKS:
                    stream.flags.update(check(cw, stream))

                if any(f.startswith("Idle") for f in stream.flags):
                    stream.flags.add(f"PotentialSaving≈{stream.monthly_cost}$")

                if stream.flags:
                    write_resource_to_csv(
                        writer=writer,
                        resource_id=stream.name,
                        name="",
                        owner_id=ACCOUNT_ID,
                        resource_type="KinesisStream",
                        state=stream.status,
                        creation_date=stream.creation_date,
                        estimated_cost=stream.monthly_cost,
                        flags=list(stream.flags),
                    )
                    logging.info(f"[Kinesis:{stream.name}] flags={stream.flags} estCost≈${stream.monthly_cost}")

    except ClientError as e:
        logging.error(f"[check_kinesis_streams] AWS error: {e.response['Error'].get('Code')}")
    except Exception as e:
        logging.error(f"[check_kinesis_streams] Unexpected error: {e}")

#endregion


#region SSM SECTION

@dataclass
class SSMParameterMetadata:
    name: str
    tier: str
    last_modified: Optional[datetime]
    age_days: Optional[int]
    monthly_cost: float
    flags: Set[str] = field(default_factory=set)


# ---------- Cost estimation ----------
def estimate_ssm_param_cost(param: dict) -> float:
    """Return monthly cost for an Advanced SSM Parameter."""
    if param.get("Tier") == "Advanced":
        return float(get_price("SSM", "ADV_PARAM_MONTH"))
    return 0.0


def build_ssm_metadata(param: dict) -> SSMParameterMetadata:
    """Construct metadata object for an SSM parameter."""
    name = param.get("Name", "")
    tier = param.get("Tier", "Standard")
    last = param.get("LastModifiedDate")

    age_days = None
    if last:
        age_days = (datetime.now(timezone.utc) - last).days

    monthly_cost = estimate_ssm_param_cost(param)

    return SSMParameterMetadata(
        name=name,
        tier=tier,
        last_modified=last,
        age_days=age_days,
        monthly_cost=monthly_cost,
    )

@retry_with_backoff()
def check_ssm_advanced_parameters(writer: csv.writer, ssm):
    """
    Flags Advanced tier parameters, highlighting stale ones (> SSM_ADV_STALE_DAYS).
    """
    try:
        pager = ssm.get_paginator("describe_parameters")
        for page in pager.paginate():
            for raw_param in page.get("Parameters", []):
                meta = build_ssm_metadata(raw_param)

                if meta.tier != "Advanced":
                    continue

                meta.flags.add("AdvancedTierParameter")

                if meta.age_days is not None and meta.age_days > SSM_ADV_STALE_DAYS:
                    meta.flags.add(f"Stale>{meta.age_days}d")
                    meta.flags.add(f"PotentialSaving={round(meta.monthly_cost,2)}$")

                if meta.flags:
                    write_resource_to_csv(
                        writer=writer,
                        resource_id=meta.name,
                        name=meta.name,
                        owner_id=ACCOUNT_ID,
                        resource_type="SSMParameter",
                        estimated_cost=round(meta.monthly_cost, 2),
                        flags=list(meta.flags),
                    )
                    logging.info(f"[SSM:{meta.name}] flags={meta.flags} estCost≈${meta.monthly_cost}")

    except ClientError as e:
        logging.error(f"[check_ssm_advanced_parameters] {e}")

#endregion


#region EC2 SECTION

def _ec2_hourly_price(instance_type: str, region: str) -> float:
    """Best-effort on-demand hourly price for an EC2 instance type in a region."""
    try:
        return float(get_price("EC2", instance_type, region=region, default=0.0))
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

#region ACM & KMS SECTION
@retry_with_backoff()
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
            except Exception as e:
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


@retry_with_backoff()
def check_kms_customer_managed_keys(writer: csv.writer, cloudtrail, kms, lookback_days: int = 90) -> None:
    """
    Analyze KMS Customer Managed Keys (CMKs):
    - Estimate monthly storage cost (~$1/key/month; +$1 for first/second rotation; prorated).
    - Use CloudTrail LookupEvents to infer 'last seen' usage within lookback_days.
    - Flag keys with no recent usage, keys disabled, and rotation hygiene.

    Pricing reference: AWS KMS pricing—$1 per KMS key per month (prorated). Rotations add $1/mo for the first two rotations.
    Also, KMS API requests have per-10K fees (first 20K free/month) which we do not estimate here.  # noqa
    CloudTrail contains KMS usage logs (Encrypt/Decrypt/GenerateDataKey/etc.).  # noqa
    """
    try:
        end = datetime.now(timezone.utc)
        start = end - timedelta(days=lookback_days)

        region = _region_of(kms)

        # List keys (paged)
        keys = []
        paginator = None
        try:
            paginator = kms.get_paginator("list_keys")
        except Exception:
            # old SDKs may not have paginator in unit contexts; fallback single call
            pass

        if paginator:
            for page in safe_aws_call(
                lambda: paginator.paginate(),
                fallback=[], context=f"KMS:{region}:ListKeysPages",
            ):
                keys.extend(page.get("Keys", []) or [])
        else:
            lst = safe_aws_call(lambda: kms.list_keys(), fallback={}, context=f"KMS:{region}:ListKeys")
            keys.extend(lst.get("Keys", []) or [])

        # Iterate keys
        for k in keys:
            kid = k.get("KeyId", "")
            if not kid:
                continue

            meta = safe_aws_call(lambda: kms.describe_key(KeyId=kid).get("KeyMetadata", {}), fallback={}, context=f"KMS:{region}:DescribeKey")
            if not meta:
                continue

            # Only CUSTOMER managed keys (exclude AWS managed / AWS owned)
            if meta.get("KeyManager") != "CUSTOMER":
                continue

            arn     = meta.get("Arn", "")
            state   = meta.get("KeyState", "")
            created = meta.get("CreationDate")
            created_str = created.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ") if hasattr(created, "astimezone") else ""

            # Rotation
            rotation_enabled = bool(safe_aws_call(lambda: kms.get_key_rotation_status(KeyId=kid).get("KeyRotationEnabled", False),
                                                    fallback=False, context=f"KMS:{region}:GetKeyRotationStatus"))

            # Tag enrichment (optional)
            tags = {}
            try:
                # list_resource_tags is regional; limit not huge
                t = kms.list_resource_tags(KeyId=kid).get("Tags", [])
                tags = {kv.get("TagKey", ""): kv.get("TagValue", "") for kv in t if kv.get("TagKey")}
            except Exception:
                pass

            # === Cost estimation (rough, monthly) ===
            # Base key storage: $1 / month (prorated). Add $1/month for first two rotations; we can't know history,
            # so we conservatively assume +$1 only when rotation_enabled is True (still an approximation).
            base_month = get_price("KMS", "KEY_MONTH")
            extra_rotation = get_price("KMS", "KEY_ROTATION_MONTH") if rotation_enabled else 0.0
            est_monthly = 0.0 if state == "PendingDeletion" else round(float(base_month) + float(extra_rotation), 2)

            # === Usage via CloudTrail ===
            # CloudTrail LookupEvents (management events up to 90 days in the console; use trails for longer retention).
            # We scan for kms.amazonaws.com events involving the KeyId (now populated in Resources / responseElements in newer logs).
            last_seen = ""
            try:
                ct = cloudtrail  # NullAWSClient in tests; real client at runtime
                # not all environments provide LookupEvents; guard the call
                def _lookup():
                    # limit events returned per call; if not supported, the stub returns {}
                    return ct.lookup_events(
                        LookupAttributes=[{"AttributeKey": "EventSource", "AttributeValue": "kms.amazonaws.com"}],
                        StartTime=start, EndTime=end, MaxResults=50
                    )

                events_resp = safe_aws_call(_lookup, fallback={}, context=f"CloudTrail:{region}:LookupEvents")
                events = events_resp.get("Events", []) or []
                # Find any event mentioning our key id/arn
                latest = None
                for ev in events:
                    # Quick check in 'Resources' or stringified payloads
                    if kid in json.dumps(ev, default=str) or arn in json.dumps(ev, default=str):
                        et = ev.get("EventTime")
                        if et and (latest is None or et > latest):
                            latest = et
                if latest:
                    last_seen = latest.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
            except Exception:
                pass

            # === Flags & potential saving ===
            flags: List[str] = []
            if state == "Enabled":
                if not last_seen:
                    flags.append(f"NoRecentUse{lookback_days}d")
                    if est_monthly > 0:
                        flags.append(f"PotentialSaving={est_monthly}$")
            elif state in ("Disabled", "PendingDeletion"):
                flags.append(state)

            if not rotation_enabled:
                flags.append("RotationOff")
            if not all(tags.get(k) for k in REQUIRED_TAG_KEYS):
                flags.append("MissingRequiredTags")

            conf = score_confidence({"seen": 1.0 if last_seen else 0.3, "no_recent": 1.0 if f"NoRecentUse{lookback_days}d" in flags else 0.0}, evidence_ok=True)

            signals = {
                "Region": region,
                "State": state,
                "Rotation": "On" if rotation_enabled else "Off",
                "Created": created_str,
                "LastSeen": last_seen,
                "LookbackDays": lookback_days,
                "MonthlyKeyRate": float(base_month),
                "MonthlyRotationRate": float(extra_rotation),
            }

            if flags or est_monthly > 0:
                write_resource_to_csv(
                    writer=writer,
                    resource_id=arn or kid,
                    name=meta.get("Description", "") or meta.get("KeyId", ""),
                    resource_type="KMSKey",
                    owner_id=ACCOUNT_ID,
                    state=state,
                    creation_date=created_str,
                    estimated_cost=est_monthly,
                    app_id=tags.get("ApplicationID", "NULL"),
                    app=tags.get("Application", "NULL"),
                    env=tags.get("Environment", "NULL"),
                    flags=flags,
                    confidence=conf,
                    signals=signals,
                )
        logging.info("[KMS] Completed CMK analysis")
    except Exception as e:
        logging.error(f"[check_kms_customer_managed_keys] Unexpected error: {e}")
#endregion

#region CloudFront SECTION

def check_cloudfront_idle_distributions(
    writer,
    cloudfront,
    cloudwatch,
) -> None:
    """
    Identify CloudFront distributions with near-zero usage and surface any
    recurring monthly charges (e.g., Dedicated IP custom SSL at ~$600/month).

    Method:
      • List all CloudFront distributions (global).
      • Pull CloudWatch metrics (namespace: AWS/CloudFront, Region="Global") using
        a us-east-1 CloudWatch client, batched via GetMetricData:
          - Requests (Sum)
          - BytesDownloaded (Sum)
      • Flag IdleDistribution when both:
            total_requests < CLOUDFRONT_IDLE_REQUESTS
            AND total_bytes_gb < CLOUDFRONT_IDLE_BYTES_GB
      • If the distribution uses Dedicated IP custom SSL (ViewerCertificate.SSLSupportMethod == "vip"),
        add "UsesDedicatedIPCustomSSL" and "PotentialSaving=600$" to flags (AWS charges ~$600/mo).  # See pricing page.
    """
    try:
        region = (
            getattr(getattr(cloudwatch, "meta", None), "region_name", "")
            or getattr(getattr(cloudfront, "meta", None), "region_name", "")
            or ""
        )

        now = datetime.now(timezone.utc)
        lookback_days = max(1, CLOUDFRONT_LOOKBACK_DAYS)
        start = now - timedelta(days=lookback_days)
        PERIOD = max(60, CLOUDFRONT_PERIOD)  # keep your original period setting

        # 1) List distributions (paginated)
        dists = []
        marker = None
        while True:
            try:
                args = {"Marker": marker} if marker else {}
                resp = cloudfront.list_distributions(**args)
            except ClientError as e:
                logging.error(f"[CF] list_distributions failed ({region}): {e}")
                break

            summary_list = ((resp.get("DistributionList") or {}).get("Items") or [])
            dists.extend(summary_list)
            marker = (resp.get("DistributionList") or {}).get("NextMarker")
            if not marker:
                break

        if not dists:
            return

        # 2) Tags (best effort)
        def _tdict(aws_tags):
            if not aws_tags:
                return {}
            items = (aws_tags.get("Items") if isinstance(aws_tags, dict) else None) or []
            return {t.get("Key", ""): t.get("Value", "") for t in items}

        dist_tags: Dict[str, Dict[str, str]] = {}
        for d in dists:
            arn = d.get("ARN") or ""
            t = {}
            if arn:
                try:
                    t = cloudfront.list_tags_for_resource(Resource=arn).get("Tags", {})
                except ClientError:
                    t = {}
                except Exception:
                    t = {}
            dist_tags[arn or d.get("Id", "")] = _tdict(t)

        # 3) Batch CloudWatch metrics (use passed CW client)

        batch = cw.CloudWatchBatcher(region, client=cloudwatch)
        for d in dists:
            did = d.get("Id", "")

            # CloudFront metrics require Region='Global' dimension
            dims = [{"Name": "DistributionId", "Value": did}, {"Name": "Region", "Value": "Global"}]

            batch.add(cw.MDQ(id=f"cf_req__{did}",  namespace="AWS/CloudFront", metric="Requests",       dims=dims, stat="Sum",     period=PERIOD))
            batch.add(cw.MDQ(id=f"cf_bdn__{did}",  namespace="AWS/CloudFront", metric="BytesDownloaded", dims=dims, stat="Sum",     period=PERIOD))
            batch.add(cw.MDQ(id=f"cf_bup__{did}",  namespace="AWS/CloudFront", metric="BytesUploaded",   dims=dims, stat="Sum",     period=PERIOD))
            batch.add(cw.MDQ(id=f"cf_4xx__{did}",  namespace="AWS/CloudFront", metric="4xxErrorRate",    dims=dims, stat="Average", period=PERIOD))
            batch.add(cw.MDQ(id=f"cf_5xx__{did}",  namespace="AWS/CloudFront", metric="5xxErrorRate",    dims=dims, stat="Average", period=PERIOD))

        try:
            series = batch.execute(start, now, scan_by="TimestampDescending")
        except Exception as e:
            logging.exception(f"[CF] CloudWatch batch execute failed ({region}): {e}")
            series = {}

        # 4) Emit rows
        for d in dists:
            try:
                did      = d.get("Id", "")
                arn      = d.get("ARN", did)
                domain   = d.get("DomainName", "")
                status   = d.get("Status", "")
                enabled  = bool(d.get("Enabled", True))
                comment  = d.get("Comment", "")
                last_mod = d.get("LastModifiedTime")

                if isinstance(last_mod, datetime) and last_mod.tzinfo is None:
                    last_mod = last_mod.replace(tzinfo=timezone.utc)
                created_iso = (last_mod or now).astimezone(timezone.utc).isoformat()

                tags = dist_tags.get(arn, {})
                name = tags.get("Name", domain or did)

                # metrics
                req_sum   = float(sum(v for _, v in series.get(f"cf_req__{did}", [])))
                bdn_sum   = float(sum(v for _, v in series.get(f"cf_bdn__{did}", [])))
                bup_sum   = float(sum(v for _, v in series.get(f"cf_bup__{did}", [])))
                e4_vals   = [v for _, v in series.get(f"cf_4xx__{did}", [])]
                e5_vals   = [v for _, v in series.get(f"cf_5xx__{did}", [])]
                e4_avg    = (sum(e4_vals) / len(e4_vals)) if e4_vals else 0.0
                e5_avg    = (sum(e5_vals) / len(e5_vals)) if e5_vals else 0.0

                bytes_gb  = (bdn_sum + bup_sum) / (1024.0 ** 3)

                # ViewerCertificate → detect Dedicated-IP custom SSL (no-regression)
                vc = d.get("ViewerCertificate", {}) or {}
                ssl_method = (vc.get("SSLSupportMethod") or "").lower()  # 'sni-only' | 'vip' | ''
                uses_dedicated_ip = (ssl_method == "vip")

                flags: List[str] = []
                missing = [k for k in REQUIRED_TAG_KEYS if not tags.get(k)]
                if missing:
                    flags.append(f"MissingRequiredTags={','.join(missing)}")

                potential = None
                est_monthly = ""
                # "Idle" heuristic — keep your thresholds from config
                is_idle = (req_sum <= CLOUDFRONT_IDLE_REQUESTS) and (bytes_gb <= CLOUDFRONT_IDLE_BYTES_GB) and enabled and (status.lower() == "deployed")
                if is_idle:
                    flags += ["idle_cloudfront_candidate", "confidence=100"]

                if uses_dedicated_ip:
                    # Dedicated-IP custom SSL carries ~$600/mo even if idle; SNI has $0 base fee.
                    flags.append("UsesDedicatedIPCustomSSL")
                    est_monthly = 600
                    if is_idle:
                        potential = 600

                confidence = 100 if is_idle else None

                signals = {
                    "Region": region,                   
                    "Scope": "Global",
                    "Enabled": str(enabled).lower(),
                    "Status": status,
                    "DomainName": domain,
                    "SSLSupportMethod": ssl_method or "",
                    "CommentLen": str(len(comment or "")),
                    f"Requests{lookback_days}d": f"{int(req_sum)}",
                    f"BytesGB{lookback_days}d": f"{bytes_gb:.3f}",
                    "Avg4xxRate": f"{e4_avg:.4f}",
                    "Avg5xxRate": f"{e5_avg:.4f}",
                    "LookbackDays": str(lookback_days),
                }

                write_resource_to_csv(
                    writer=writer,
                    resource_id=arn or did,
                    name=name,
                    resource_type="CloudFront",
                    owner_id=ACCOUNT_ID,
                    state=status,
                    creation_date=created_iso,
                    estimated_cost=est_monthly,    # left blank to avoid pricing regression
                    app_id=tags.get("ApplicationID", "NULL"),
                    app=tags.get("Application", "NULL"),
                    env=tags.get("Environment", "NULL"),
                    flags=flags,
                    potential_saving=potential,
                    confidence=confidence,
                    signals=signals,
                )
            except Exception as e:
                logging.exception(f"[CF] emit failed for {d.get('Id','?')}: {e}")

    except Exception as e:
        logging.exception(f"[CF] check_cloudfront_distributions_refactored failed: {e}")
        return

#endregion


#region PRIVATE CA SECTION
@retry_with_backoff()
def check_private_certificate_authorities(writer: csv.writer) -> None:
    """
    Flag potentially idle or misconfigured AWS Private CAs and estimate monthly cost.

    What we do per region:
      1) Build a CA->in-use count map from ACM private certificates (Type=PRIVATE) where InUseBy is non-empty.
         If ACM's describe_certificate exposes CertificateAuthorityArn, we attribute explicitly.
      2) Enumerate ACMPCA Certificate Authorities and compute:
         - UsageMode: GENERAL_PURPOSE (~$400/mo) vs SHORT_LIVED_CERTIFICATE (~$50/mo)
         - Status: ACTIVE/DISABLED/...
         - Flags: IdlePrivateCA (no private certs in use mapped to this CA), DisabledCA(StillBilled), Status=<...>
         - PotentialSaving: monthly CA rate when idle.
      3) Emit one CSV row per CA with Signals and Confidence.

    Pricing refs (prorated): $400/mo per CA in general-purpose; $50/mo in short-lived mode.  # noqa
    Disabled CAs still accrue charges until deleted.                                      # noqa
    """
    try:
        # Iterate configured regions (same constant used elsewhere in your toolset)
        for region in REGIONS:
            # --- Init clients lazily, guarded ---
            try:
                acmpca = boto3.client("acmpca", region_name=region, config=SDK_CONFIG)  # type: ignore
            except Exception as e:
                logging.warning(f"[PrivateCA] Init PCA client failed for {region}: {e}")
                continue

            acm = None
            try:
                acm = boto3.client("acm", region_name=region, config=SDK_CONFIG)  # type: ignore
            except Exception as e:
                logging.warning(f"[PrivateCA] Init ACM client failed for {region}: {e}")

            # --- 1) Build 'CA ARN -> count of in-use private certs' map from ACM ---
            ca_inuse: Dict[str, int] = {}
            if acm:
                summaries = safe_aws_call(
                    lambda: acm.list_certificates().get("CertificateSummaryList", []),
                    fallback=[], context=f"ACM:{region}:ListCertificates",
                )
                for s in summaries:
                    c_arn = s.get("CertificateArn", "")
                    if not c_arn:
                        continue
                    desc = safe_aws_call(
                        lambda: acm.describe_certificate(CertificateArn=c_arn).get("Certificate", {}),
                        fallback={}, context=f"ACM:{region}:DescribeCertificate",
                    )
                    if not desc:
                        continue
                    # Only private certificates
                    if str(desc.get("Type", "")).upper() != "PRIVATE":
                        continue
                    # Only those actually in use
                    in_use_by = desc.get("InUseBy", []) or []
                    if not in_use_by:
                        continue
                    # Try to attribute to the issuing Private CA, when present
                    ca_arn = desc.get("CertificateAuthorityArn")
                    if ca_arn:
                        ca_inuse[ca_arn] = ca_inuse.get(ca_arn, 0) + 1

            # --- 2) Enumerate Private CAs (ACMPCA) ---
            # Paginated listing if available
            pages: List[Dict[str, Any]] = []
            try:
                paginator = acmpca.get_paginator("list_certificate_authorities")
                for pg in safe_aws_call(lambda: paginator.paginate(), fallback=[], context=f"ACMPCA:{region}:ListCAsPages"):
                    pages.append(pg)
            except Exception:
                single = safe_aws_call(lambda: acmpca.list_certificate_authorities(), fallback={}, context=f"ACMPCA:{region}:ListCAs")
                if single:
                    pages.append(single)

            for page in pages:
                for ca in page.get("CertificateAuthorities", []) or []:
                    ca_arn = ca.get("Arn", "")
                    status = ca.get("Status", "")
                    usage_mode = ca.get("UsageMode", "GENERAL_PURPOSE")  # GENERAL_PURPOSE | SHORT_LIVED_CERTIFICATE
                    ca_type = ca.get("Type", "SUBORDINATE")              # ROOT | SUBORDINATE
                    created_at = ca.get("CreatedAt")
                    created_str = (
                        created_at.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
                        if hasattr(created_at, "astimezone") else ""
                    )

                    # Tags (optional)
                    tags: Dict[str, str] = {}
                    try:
                        tag_list = safe_aws_call(
                            lambda: acmpca.list_tags(CertificateAuthorityArn=ca_arn).get("Tags", []),
                            fallback=[], context=f"ACMPCA:{region}:ListTags"
                        )
                        tags = {t.get("Key", ""): t.get("Value", "") for t in tag_list if t.get("Key")}
                    except Exception:
                        pass

                    # --- Monthly cost estimate (region-independent public list prices) ---
                    # Keep robust via get_price defaulting.
                    if str(usage_mode).upper() == "SHORT_LIVED_CERTIFICATE":
                        rate = get_price("PRIVATE_CA", "SHORT_LIVED_MONTH", default=50.0)
                    else:
                        rate = get_price("PRIVATE_CA", "GENERAL_PURPOSE_MONTH", default=400.0)
                    est_monthly = round(float(rate), 2)

                    # --- Flags ---
                    inuse_count = int(ca_inuse.get(ca_arn, 0))
                    flags: List[str] = []
                    if status == "ACTIVE" and inuse_count == 0:
                        flags.append("IdlePrivateCA")
                        flags.append(f"PotentialSaving={est_monthly}$")
                    if status == "DISABLED":
                        flags.append("DisabledCA(StillBilled)")  # disabled still billed until deleted
                    if status not in ("ACTIVE", "DISABLED"):
                        flags.append(f"Status={status}")

                    # --- Signals & Confidence ---
                    signals = {
                        "Region": region,
                        "UsageMode": usage_mode,
                        "Type": ca_type,
                        "InUsePrivateCerts": inuse_count,
                        "Created": created_str,
                        "MonthRate": float(rate),
                    }
                    # Confidence is high when we could attribute in-use certs to a CA arn.
                    # If no explicit CA mapping present, still emit but with lower confidence.
                    confidence = score_confidence(
                        {"attributed": 1.0 if ca_arn in ca_inuse else 0.5},
                        evidence_ok=True
                    )

                    write_resource_to_csv(
                        writer=writer,
                        resource_id=ca_arn or "",
                        name=tags.get("Name", ""),
                        resource_type="PrivateCA",
                        owner_id=ACCOUNT_ID,
                        state=status,
                        creation_date=created_str,
                        estimated_cost=est_monthly,
                        app_id=tags.get("ApplicationID", "NULL"),
                        app=tags.get("Application", "NULL"),
                        env=tags.get("Environment", "NULL"),
                        flags=flags,
                        confidence=confidence,
                        signals=signals,
                    )
            logging.info("[PrivateCA] Region %s processed", region)
    except Exception as e:
        logging.warning(f"[check_private_certificate_authorities] non-fatal: {e}")
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

            # -------- Global / cross-region steps first
            try:
                s3_global = boto3.client("s3", config=SDK_CONFIG)
                cloudfront_global = boto3.client("cloudfront", config=SDK_CONFIG)
            except Exception as e:
                logging.error(f"[main] Failed to create global S3 client: {e}")
                s3_global = boto3.client("s3")  # fallback
                cloudfront_global = boto3.client("cloudfront")

            # S3 buckets (global)
            run_check(profiler,
                      check_name="check_s3_buckets_refactored",
                      region="GLOBAL",
                      fn=check_s3_buckets_refactored,
                      writer=writer,
                      s3=s3_global)
              
            run_check(profiler,
                    check_name="check_s3_abandoned_multipart_uploads",
                    region="GLOBAL",
                    fn=check_s3_abandoned_multipart_uploads,
                    writer=writer,
                    s3=s3_global)
            
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

                run_check(profiler, check_name="check_unused_elastic_ips", region=region,
                          fn=check_unused_elastic_ips, writer=writer, ec2=clients['ec2'])

                run_check(profiler, check_name="check_idle_load_balancers", region=region,
                          fn=check_idle_load_balancers, writer=writer,
                          elbv2=clients['elbv2'], cw=clients['cloudwatch'])

                run_check(profiler, check_name="check_detached_network_interfaces", region=region,
                          fn=check_detached_network_interfaces, writer=writer, ec2=clients['ec2'])

                run_check(profiler, check_name="check_unused_efs_filesystems", region=region,
                          fn=check_unused_efs_filesystems, writer=writer,
                          efs=clients['efs'], cloudwatch=clients['cloudwatch'])

                run_check(profiler, check_name="check_unused_nat_gateways", region=region,
                          fn=check_unused_nat_gateways, writer=writer,
                          ec2=clients['ec2'], cloudwatch=clients['cloudwatch'])

                run_check(profiler, check_name="check_log_groups_with_infinite_retention", region=region,
                          fn=check_log_groups_with_infinite_retention, writer=writer, logs=clients['logs'])

                run_check(profiler, check_name="check_backup_retention_misconfigurations", region=region,
                          fn=check_backup_retention_misconfigurations, writer=writer, backup=clients['backup'])

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

                run_check(profiler, check_name="check_ebs_snapshot_replication", region=region,
                          fn=check_ebs_snapshot_replication, writer=writer, ec2=clients['ec2'])

                run_check(profiler, check_name="check_dynamodb_cost_optimization", region=region,
                          fn=check_dynamodb_cost_optimization, writer=writer,
                          dynamodb=clients['dynamodb'], cloudwatch=clients['cloudwatch'])

                run_check(profiler, check_name="check_inter_region_vpc_and_tgw_peerings", region=region,
                          fn=check_inter_region_vpc_and_tgw_peerings, writer=writer,
                          ec2=clients['ec2'], cloudwatch=clients['cloudwatch'])

                run_check(profiler, check_name="check_ecr_storage_and_staleness", region=region,
                          fn=check_ecr_storage_and_staleness, writer=writer, ecr=clients['ecr'])

                run_check(profiler, check_name="check_ebs_fast_snapshot_restore", region=region,
                          fn=check_ebs_fast_snapshot_restore, writer=writer, ec2=clients['ec2'])

                run_check(profiler, check_name="check_eks_empty_clusters", region=region,
                          fn=check_eks_empty_clusters, writer=writer, eks=clients['eks'], ec2=clients['ec2'])

                run_check(profiler, check_name="check_ebs_unattached_and_rightsize", region=region,
                          fn=check_ebs_unattached_and_rightsize, writer=writer,
                          ec2=clients['ec2'], cloudwatch=clients['cloudwatch'])

                run_check(profiler, check_name="check_rds_snapshots", region=region,
                          fn=check_rds_snapshots, writer=writer, rds=clients['rds'])

                run_check(profiler, check_name="check_kinesis_streams", region=region,
                          fn=check_kinesis_streams, writer=writer,
                          kinesis=clients['kinesis'], cw=clients['cloudwatch'])

                run_check(profiler, check_name="check_wafv2_unassociated_acls", region=region,
                          fn=check_wafv2_unassociated_acls, writer=writer,
                          wafv2=clients['wafv2'], region_name=region)

                run_check(profiler, check_name="check_ssm_advanced_parameters", region=region,
                          fn=check_ssm_advanced_parameters, writer=writer, ssm=clients['ssm'])

                run_check(profiler, check_name="check_idle_ec2_instances", region=region,
                          fn=check_idle_ec2_instances, writer=writer,
                          ec2=clients['ec2'], cloudwatch=clients['cloudwatch'])

                # CloudFront is global; no impact to put it in the region loop
                run_check(profiler, check_name="check_cloudfront_idle_distributions", region=region,
                          fn=check_cloudfront_idle_distributions, writer=writer,
                          cloudfront=clients['cloudfront'], cloudwatch=clients['cloudwatch'])

                run_check(profiler, check_name="check_rds_extended_support_mysql", region=region,
                          fn=check_rds_extended_support_mysql, writer=writer, rds=clients['rds'])

                run_check(profiler, "check_private_certificate_authorities", region, 
                check_private_certificate_authorities, writer)

                run_check(profiler=profiler, check_name="check_kms_customer_managed_keys", region=region,
                fn=check_kms_customer_managed_keys, writer=writer, cloudtrail=clients['cloudtrail'], kms=clients['kms'])

                run_check(profiler=profiler, check_name="check_nat_replacement_opps", region=region,
                fn=check_nat_replacement_opps, writer=writer, cloudtrail=clients['ec2'], kms=clients['cloudwatch'])


        profiler.dump_csv()
        profiler.log_summary(top_n=20)
        logging.info(f"CSV export complete: {OUTPUT_FILE}")
        logging.info(f"Profile export complete: {PROFILE_FILE}")

    except Exception as e:
        logging.error(f"[main] Fatal error: {e}")    
        

if __name__ == "__main__":
    main()

