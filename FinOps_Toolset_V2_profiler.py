"""
AWS Cleanup & Cost Optimization Analyzer
========================================

This script performs a comprehensive analysis of AWS resources across multiple services
to identify unused, misconfigured, or cost-inefficient components. It generates a CSV
report with metadata, estimated costs, and optimization flags for review.

Key Features
------------
Described in checkers

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
- Profiler active that enables to check script performance 
"""

#region Imports SECTION

import csv
import os
import logging
from typing import Dict, Optional, List, Union, Callable, Any
from datetime import datetime, timezone, timedelta

import re

from time import perf_counter
import boto3 # type: ignore
#from correlator import build_certificate_graph, summarize_cert_usage

from finops_toolset.config import (
    SDK_CONFIG, REGIONS, OUTPUT_FILE, LOG_FILE,
)

from finops_toolset.pricing import get_price
from aws_checkers.eip import check_unused_elastic_ips as eip
from aws_checkers.network_interfaces import check_detached_network_interfaces as eni
from aws_checkers import config as checkers_config, rds as rds_checks
from aws_checkers.private_ca import check_private_certificate_authorities
from aws_checkers.kms import check_kms_customer_managed_keys
from aws_checkers.efs import check_unused_efs_filesystems
from aws_checkers.cloudfront import check_cloudfront_distributions
from aws_checkers.nat_gateways import check_nat_gateways
from aws_checkers import (
    eks as eks_checks, fsr as fsr_checks, acm as acm_checks,
    wafv2 as waf_checks, lb as lb_checks, route53 as r53_checks,
    fsx as fsx_checks, ec2 as ec2_checks, s3 as s3_checks,
    ami as ami_checks, kinesis as kinesis_checks, ebs as ebs_checks,
    dynamodb as ddb_checks, loggroups as lg_checks, vpc_tgw as vpc_tgw_checks,
    lambda_svc as lambda_checks, rds_snapshots as rds_snaps, backup as backup_checks,
    ecr as ecr_checks, ssm as ssm_checks, sagemaker as sm_checks, apigateway as apigw_checks,
    msk as msk_checks, cloudtrail as ct_checks, stepfunctions as sfn_checks,
    redshift as rs_checks, glue as glue_checks, ecs as ecs_checks,
)

#endregion

# Configure logging
logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)

#region CSV Helpers

def write_resource_to_csv(
    writer: csv.writer,
    resource_id: str,
    name: str,
    resource_type: str,
    owner_id: str = "",
    region: str = "",
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
      - Potential_Saving_USD: numeric, auto-parsed from flags 'PotentialSaving=12.34$'
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
                except Exception: # pylint: disable=broad-except
                    parts.append(f"{k}=<err>")
            signals_str = " | ".join(parts)
        else:
            signals_str = str(signals)

        writer.writerow([
            resource_id, name, resource_type, owner_id, region, state, creation_date,
            storage_gb, object_count if object_count is not None else "",
            estimated_cost, potential_saving if potential_saving is not None else "",
            app_id, app, env, referenced_in, flagged,
            confidence if confidence is not None else "", signals_str
        ])
    except Exception as e: # pylint: disable=broad-except
        logging.error("[write_resource_to_csv] Failed to write row for {%s or %s}: %s", resource_id, name, e)

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
        "sagemaker": boto3.client("sagemaker", region_name=region, config=SDK_CONFIG),
        "kafka": boto3.client("kafka", region_name=region, config=SDK_CONFIG),
        "stepfunctions": boto3.client("stepfunctions", region_name=region, config=SDK_CONFIG),
        "glue": boto3.client("glue", region_name=region, config=SDK_CONFIG),
        "ecs": boto3.client("ecs", region_name=region, config=SDK_CONFIG),
        "apigatewayv2": boto3.client("apigatewayv2", region_name=region, config=SDK_CONFIG),
        "apigateway": boto3.client("apigateway", region_name=region, config=SDK_CONFIG),
        "redshift": boto3.client("redshift", region_name=region, config=SDK_CONFIG),
    }


def get_account_id(sts_client=None) -> str:
    """Retrieves account ID"""
    try:
        c = sts_client or boto3.client("sts", config=SDK_CONFIG)
        return c.get_caller_identity().get("Account", "")
    except Exception: # pylint: disable=broad-except
        return ""

ACCOUNT_ID = get_account_id()

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
        """Counts number of rows in CSV"""
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
        """Retrieves check metrics"""
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
        """dump csv"""
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
        """retrieves statistic at the end of scan"""
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

#region MAIN SECTION

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
                    "Resource_ID", "Name", "ResourceType", "OwnerId", "Region", "State", "Creation_Date",
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
                region="GLOBAL"
            except Exception as e: # pylint: disable=broad-except
                logging.error("[main] Failed to create global S3 client: %s", e)
                s3_global = boto3.client("s3")  # fallback


            run_check(
                profiler, "check_s3_cost_and_compliance",
                region, s3_checks.check_s3_cost_and_compliance,
                writer=writer, client=s3_global, cloudwatch=cloudwatch_global,
                # knobs:
                # lookback_days=7,
                # min_size_gb_for_lifecycle=500.0,
                # assumed_cold_fraction=0.30,
                # min_objects_for_versions=1_000_000,
                # version_fraction=0.25,
                # mpu_older_than_days=7,
                # mpu_check_max_buckets=50,
                # mpu_per_bucket_limit=100,
                # mpu_per_upload_parts_limit=20,
            )

            # -------- Per-region steps
            for region in REGIONS:
                logging.info("Running cleanup for region: %s", region)
                try:
                    clients = init_clients(region)
                except Exception as e: # pylint: disable=broad-except
                    logging.error("[main] init_clients(%s) failed: %s", region, e)
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
                          region, backup_checks.check_backup_plans_without_selections,
                          writer=writer, backup=clients["backup"])
                run_check(profiler, "check_backup_rules_no_lifecycle",
                          region, backup_checks.check_backup_rules_no_lifecycle, writer=writer,
                          backup=clients["backup"])
                run_check(profiler, "check_backup_stale_recovery_points",
                          region, backup_checks.check_backup_stale_recovery_points, writer=writer,
                          backup=clients["backup"])

                run_check(
                    profiler, "check_fsx_low_activity_filesystems",
                    region, fsx_checks.check_fsx_low_activity_filesystems,
                    writer=writer, fsx=clients["fsx"], cloudwatch=clients["cloudwatch"],
                    # knobs: lookback_days=14, io_threshold_bytes=1_000_000_000
                )

                run_check(
                    profiler, "check_fsx_high_free_capacity",
                    region, fsx_checks.check_fsx_high_free_capacity,
                    writer=writer, fsx=clients["fsx"], cloudwatch=clients["cloudwatch"],
                    # knobs: lookback_days=3, free_pct_threshold=0.70
                )

                run_check(
                    profiler, "check_fsx_old_backups",
                    region, fsx_checks.check_fsx_old_backups,
                    writer=writer, fsx=clients["fsx"],
                    cloudwatch=clients["cloudwatch"],
                    # knobs: stale_days=30
                )

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

                # VPC hygiene
                run_check(
                    profiler, "check_vpc_no_flow_logs",
                    region, vpc_tgw_checks.check_vpc_no_flow_logs,
                    writer=writer, ec2=clients["ec2"],
                )

                run_check(
                    profiler, "check_vpc_unused",
                    region, vpc_tgw_checks.check_vpc_unused,
                    writer=writer, ec2=clients["ec2"],
                )

                # TGW hygiene + cost
                run_check(
                    profiler, "check_tgw_no_attachments",
                    region, vpc_tgw_checks.check_tgw_no_attachments,
                    writer=writer, ec2=clients["ec2"],
                )

                run_check(
                    profiler, "check_tgw_attachments_low_traffic",
                    region, vpc_tgw_checks.check_tgw_attachments_low_traffic,
                    writer=writer, ec2=clients["ec2"], cloudwatch=clients["cloudwatch"],
                    # knobs: lookback_days=14, bytes_threshold=50_000_000
                )


                run_check(profiler, "check_ecr_repositories_without_lifecycle_policy", region,
                        ecr_checks.check_ecr_repositories_without_lifecycle_policy,
                        writer=writer, ecr=clients["ecr"])

                run_check(profiler, "check_ecr_empty_repositories", region,
                        ecr_checks.check_ecr_empty_repositories,
                        writer=writer, ecr=clients["ecr"])

                run_check(profiler, "check_ecr_stale_or_untagged_images", region,
                        ecr_checks.check_ecr_stale_or_untagged_images,
                        writer=writer, ecr=clients["ecr"])

                run_check(profiler, "check_ebs_orphan_snapshots",
                          region, ebs_checks.check_ebs_orphan_snapshots, writer=writer,
                          ec2=clients["ec2"], cloudwatch=clients["cloudwatch"])

                run_check(profiler, "check_ebs_snapshot_stale",
                          region, ebs_checks.check_ebs_snapshot_stale, writer=writer,
                          ec2=clients["ec2"], cloudwatch=clients["cloudwatch"])

                run_check(profiler, "check_ebs_snapshots_public_or_shared",
                          region, ebs_checks.check_ebs_snapshots_public_or_shared, writer=writer,
                          ec2=clients["ec2"], cloudwatch=clients["cloudwatch"])

                run_check(profiler, "check_ebs_volumes_low_utilization",
                          region, ebs_checks.check_ebs_volumes_low_utilization, writer=writer,
                          ec2=clients["ec2"], cloudwatch=clients["cloudwatch"])

                run_check(profiler, "check_ebs_unencrypted_volumes", region,
                          ebs_checks.check_ebs_unencrypted_volumes, writer=writer,
                          ec2=clients["ec2"], cloudwatch=clients["cloudwatch"])

                run_check(profiler, "check_ebs_gp2_not_gp3", region,
                          ebs_checks.check_ebs_gp2_not_gp3, writer=writer,
                          ec2=clients["ec2"], cloudwatch=clients["cloudwatch"])

                run_check(profiler, "check_ebs_unattached_volumes", region,
                          ebs_checks.check_ebs_unattached_volumes, writer=writer,
                          ec2=clients["ec2"], cloudwatch=clients["cloudwatch"])

                run_check(
                    profiler, "check_acm_expiring_certificates",
                    region, acm_checks.check_acm_expiring_certificates,
                    writer=writer, acm=clients["acm"],
                    # knobs: days=30
                )

                run_check(
                    profiler, "check_acm_unused_certificates",
                    region, acm_checks.check_acm_unused_certificates,
                    writer=writer, acm=clients["acm"],
                )

                run_check(
                    profiler, "check_acm_validation_issues",
                    region, acm_checks.check_acm_validation_issues,
                    writer=writer, acm=clients["acm"],
                )

                run_check(
                    profiler, "check_acm_renewal_problems",
                    region, acm_checks.check_acm_renewal_problems,
                    writer=writer,
                    acm=clients["acm"],
                )
                #roadmap: ignore slave instances (sap db)
                run_check(
                    profiler, "check_ec2_underutilized_instances",
                    region, ec2_checks.check_ec2_underutilized_instances,
                    writer=writer, ec2=clients["ec2"], cloudwatch=clients["cloudwatch"],
                    # knobs: lookback_days=14, cpu_avg_threshold=5.0, cpu_max_threshold=10.0,
                    #        net_avg_bps_threshold=100_000
                )

                run_check(
                    profiler, "check_ec2_stopped_instances", region,
                    ec2_checks.check_ec2_stopped_instances, writer=writer,
                    ec2=clients["ec2"], cloudwatch=clients["cloudwatch"],
                    # knobs: stale_days=14
                )

                run_check(
                    profiler, "check_ec2_old_generation_instances", region,
                    ec2_checks.check_ec2_old_generation_instances, writer=writer,
                    ec2=clients["ec2"], cloudwatch=clients["cloudwatch"],
                )

                run_check(
                    profiler, "check_ec2_unused_security_groups", region,
                    ec2_checks.check_ec2_unused_security_groups, writer=writer,
                    ec2=clients["ec2"], cloudwatch=clients["cloudwatch"],
                )

                # CloudFront is global; no impact to put it in the region loop
                run_check(profiler, check_name="check_cloudfront_idle_distributions", region=region,
                          fn=check_cloudfront_distributions, writer=writer,
                          cloudfront=clients['cloudfront'], cloudwatch=clients['cloudwatch'])

                run_check(
                    profiler, "check_rds_extended_support_candidates",
                    region, rds_checks.check_rds_engine_extended_support,
                    writer=writer, rds=clients["rds"],
                )

                run_check(
                    profiler, "check_rds_underutilized_instances",
                    region, rds_checks.check_rds_underutilized_instances,
                    writer=writer, cloudwatch=clients["cloudwatch"], rds=clients["rds"],
                    # knobs: lookback_days=30, cpu_threshold_pct=20.0, conn_threshold=5.0
                )

                # Multi-AZ on non-prod → consider single-AZ
                run_check(
                    profiler, "check_rds_multi_az_non_prod",
                    region, rds_checks.check_rds_multi_az_non_prod,
                    writer=writer, rds=clients["rds"],
                )

                # Read replicas with near-zero usage → remove
                run_check(
                    profiler, "check_rds_unused_read_replicas",
                    region, rds_checks.check_rds_unused_read_replicas,
                    writer=writer, cloudwatch=clients["cloudwatch"], rds=clients["rds"],
                    # knobs: lookback_days=30, conn_threshold=1.0, iops_threshold=5.0
                )

                # Provisioned IOPS ≫ observed → reduce
                run_check(
                    profiler, "check_rds_iops_overprovisioned",
                    region, rds_checks.check_rds_iops_overprovisioned,
                    writer=writer, cloudwatch=clients["cloudwatch"], rds=clients["rds"],
                    # knobs: lookback_days=30, headroom_pct=50.0
                )

                # Storage modernization: gp2 → gp3
                run_check(
                    profiler, "check_rds_gp2_to_gp3_candidates",
                    region, rds_checks.check_rds_gp2_to_gp3_candidates,
                    writer=writer, rds=clients["rds"],
                )

                # Aurora clusters with low activity → downsize/pause review
                run_check(
                    profiler, "check_aurora_low_activity_clusters",
                    region, rds_checks.check_aurora_low_activity_clusters,
                    writer=writer, cloudwatch=clients["cloudwatch"], rds=clients["rds"],
                    # knobs: lookback_days=30, cpu_threshold_pct=10.0, conn_threshold=5.0
                )

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

                run_check(profiler, "check_dynamodb_tables_overprovisioned", region,
                          ddb_checks.check_dynamodb_tables_overprovisioned, writer=writer,
                          dynamodb=clients["dynamodb"], cloudwatch=clients["cloudwatch"])
                run_check(profiler, "check_dynamodb_tables_unused", region,
                          ddb_checks.check_dynamodb_tables_unused, writer=writer,
                          dynamodb=clients["dynamodb"], cloudwatch=clients["cloudwatch"])
                run_check(profiler, "check_dynamodb_tables_no_ttl", region,
                          ddb_checks.check_dynamodb_tables_no_ttl, writer=writer,
                          dynamodb=clients["dynamodb"], cloudwatch=clients["cloudwatch"])
                run_check(profiler, "check_dynamodb_tables_no_pitr", region,
                          ddb_checks.check_dynamodb_tables_no_pitr, writer=writer,
                          dynamodb=clients["dynamodb"], cloudwatch=clients["cloudwatch"])

                run_check(
                            profiler, "checks_ami",
                            region, ami_checks.run_check,
                            writer=writer, ec2=clients["ec2"], autoscaling=clients["autoscaling"]
                            # knobs: age_days=180
                        )


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
                    profiler, "check_wafv2_unassociated_web_acls",
                    region, waf_checks.check_wafv2_unassociated_web_acls,
                    writer=writer, wafv2=clients["wafv2"],
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
                    profiler, "check_wafv2_empty_acl_associated",
                    region, waf_checks.check_wafv2_empty_acl_associated,
                    writer=writer, wafv2=clients["wafv2"],
                )

                run_check(
                    profiler, "check_route53_empty_public_zones",
                    region, r53_checks.check_route53_empty_public_zones,
                    writer=writer, route53=clients["route53"],
                )

                run_check(
                    profiler, "check_route53_private_zones_no_vpc_associations",
                    region, r53_checks.check_route53_private_zones_no_vpc_associations,
                    writer=writer, route53=clients["route53"],
                )

                run_check(
                    profiler, "check_route53_unused_health_checks",
                    region, r53_checks.check_route53_unused_health_checks,
                    writer=writer, route53=clients["route53"],
                )

                run_check(
                    profiler, "check_route53_public_zones_dnssec_disabled",
                    region, r53_checks.check_route53_public_zones_dnssec_disabled,
                    writer=writer, route53=clients["route53"],
                )

                run_check(
                    profiler,
                    "check_eks_empty_clusters",
                    region,
                    eks_checks.check_eks_empty_clusters,
                    writer=writer,
                    eks=clients["eks"],
                )

                run_check(
                    profiler,
                    "check_eks_logging_incomplete",
                    region,
                    eks_checks.check_eks_logging_incomplete,
                    writer=writer,
                    eks=clients["eks"],
                )

                run_check(
                    profiler,
                    "check_eks_public_endpoint_open",
                    region,
                    eks_checks.check_eks_public_endpoint_open,
                    writer=writer,
                    eks=clients["eks"],
                )

                run_check(
                    profiler,
                    "check_eks_nodegroups_scaled_to_zero",
                    region,
                    eks_checks.check_eks_nodegroups_scaled_to_zero,
                    writer=writer,
                    eks=clients["eks"],
                    # knobs: stale_days=14
                )

                run_check(
                    profiler,
                    "check_eks_addons_degraded",
                    region,
                    eks_checks.check_eks_addons_degraded,
                    writer=writer,
                    eks=clients["eks"],
                )

                run_check(
                    profiler,
                    "check_eks_old_versions",
                    region,
                    eks_checks.check_eks_old_versions,
                    writer=writer,
                    eks=clients["eks"],
                    # knobs: min_version_mm="1.27"
                )

                run_check(
                    profiler,
                    "check_ebs_fsr_enabled_snapshots",
                    region,
                    fsr_checks.check_ebs_fsr_enabled_snapshots,
                    writer=writer,
                    ec2=clients["ec2"],
                    # knobs: lookback_days=30
                )

                run_check(
                    profiler, "check_sagemaker_idle_notebooks",
                    region, sm_checks.check_sagemaker_idle_notebooks,
                    writer=writer, client=clients["sagemaker"],
                    # knobs: lookback_days=14, idle_grace_hours=12
                )

                run_check(
                    profiler, "check_sagemaker_idle_endpoints",
                    region, sm_checks.check_sagemaker_idle_endpoints,
                    writer=writer, client=clients["sagemaker"], cloudwatch=clients["cloudwatch"],
                    # knobs: lookback_days=14, invocation_threshold=5.0
                )

                run_check(
                    profiler, "check_sagemaker_studio_zombies",
                    region, sm_checks.check_sagemaker_studio_zombies,
                    writer=writer, client=clients["sagemaker"],
                    # knobs: lookback_days=7
                )

                run_check(
                    profiler, "check_apigw_low_cache_hit_ratio",
                    region, apigw_checks.check_apigw_low_cache_hit_ratio,
                    writer=writer, client=clients["apigateway"], cloudwatch=clients["cloudwatch"],
                    # knobs: lookback_days=14, hit_ratio_threshold=0.2, min_requests_sum=100
                )

                run_check(
                    profiler, "check_apigw_idle_rest_apis",
                    region, apigw_checks.check_apigw_idle_rest_apis,
                    writer=writer, client=clients["apigateway"], cloudwatch=clients["cloudwatch"],
                    # knobs: lookback_days=14, requests_threshold=50
                )

                run_check(
                    profiler, "check_apigw_idle_http_apis",
                    region, apigw_checks.check_apigw_idle_http_apis,
                    writer=writer, client=clients["apigatewayv2"], cloudwatch=clients["cloudwatch"],
                    # knobs: lookback_days=14, requests_threshold=50
                )

                run_check(
                    profiler, "check_msk_idle_clusters",
                    region, msk_checks.check_msk_idle_clusters,
                    writer=writer, client=clients["kafka"], cloudwatch=clients["cloudwatch"],
                    # knobs: lookback_days=14, bytes_threshold_gb=1.0, min_brokers_for_saving=1
                )

                run_check(
                    profiler, "check_msk_overprovisioned_brokers",
                    region, msk_checks.check_msk_overprovisioned_brokers,
                    writer=writer, client=clients["kafka"], cloudwatch=clients["cloudwatch"],
                    # knobs: lookback_days=14, low_traffic_gb=10.0,
                    # min_brokers=3, scale_down_factor=0.5
                )

                run_check(
                    profiler, "check_cloudtrail_redundant_trails",
                    region, ct_checks.check_cloudtrail_redundant_trails,
                    writer=writer, client=clients["cloudtrail"],
                )

                run_check(
                    profiler, "check_cloudtrail_s3_cwlogs_duplication",
                    region, ct_checks.check_cloudtrail_s3_cwlogs_duplication,
                    writer=writer, client=clients["cloudtrail"],
                )

                run_check(
                    profiler, "check_sfn_standard_vs_express_mismatch",
                    region, sfn_checks.check_sfn_standard_vs_express_mismatch,
                    writer=writer, client=clients["stepfunctions"],
                    cloudwatch=clients["cloudwatch"],
                    # knobs: lookback_days=14, states_per_execution=5.0,
                    #        assumed_payload_kb=64.0, min_monthly_execs=1000
                )

                run_check(
                    profiler, "check_redshift_idle_clusters",
                    region, rs_checks.check_redshift_idle_clusters,
                    writer=writer, client=clients["redshift"], cloudwatch=clients["cloudwatch"],
                    # knobs: lookback_days=14, min_queries_sum=10, cpu_threshold=5.0
                )

                run_check(
                    profiler, "check_redshift_stale_snapshots",
                    region, rs_checks.check_redshift_stale_snapshots,
                    writer=writer, client=clients["redshift"],
                    # knobs: older_than_days=30
                )
                run_check(
                    profiler, "check_glue_idle_dev_endpoints",
                    region, glue_checks.check_glue_idle_dev_endpoints,
                    writer=writer, client=clients["glue"],
                    # knobs: lookback_days=14
                )

                run_check(
                    profiler, "check_glue_zombie_crawlers",
                    region, glue_checks.check_glue_zombie_crawlers,
                    writer=writer, client=clients["glue"],
                    # knobs: older_than_days=30
                )

                run_check(
                    profiler, "check_ecs_idle_services",
                    region, ecs_checks.check_ecs_idle_services,
                    writer=writer, client=clients["ecs"], cloudwatch=clients["cloudwatch"],
                    # knobs: lookback_days=14, cpu_threshold_pct=1.0, net_total_mb_threshold=5.0
                )

                run_check(
                    profiler, "check_ecs_services_zero_tasks",
                    region, ecs_checks.check_ecs_services_zero_tasks,
                    writer=writer, client=clients["ecs"],
                )

                run_check(
                    profiler, "check_ecs_old_task_definitions",
                    region, ecs_checks.check_ecs_old_task_definitions,
                    writer=writer, client=clients["ecs"],
                    # knobs: older_than_days=90, max_task_defs=200
                )

        profiler.dump_csv()
        profiler.log_summary(top_n=30)
        logging.info("CSV export complete: %s", OUTPUT_FILE)
        logging.info("Profile export complete: %s", PROFILE_FILE)

    except Exception as e: # pylint: disable=broad-except
        logging.exception("[main] Fatal error: %s", e)

if __name__ == "__main__":
    main()

#endregion
