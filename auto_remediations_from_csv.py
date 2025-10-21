#!/usr/bin/env python3
"""Auto-remediate resources from the scanner's CSV output (pylint-compliant).

This script performs **dry-run by default** and applies changes only with
``--execute``. It supports a subset of safe, CSV-driven remediations (ENI, EIP,
CloudWatch Logs retention, unattached EBS volumes, and empty S3 buckets).

Key improvements vs. previous version:
- Lines wrapped to <= 100 chars.
- Removed superfluous parentheses after keywords (``C0325``).
- Replaced broad ``except Exception`` with specific botocore exceptions.
- Added function and class docstrings where missing.
- Removed expression-only ternary (``W0106``) in S3 deletion.
- Kept behavior identical otherwise.
"""
from __future__ import annotations

import argparse
import csv
import logging
import os
import re
import sys
import time
from dataclasses import dataclass
from typing import Dict, List, Optional

import boto3  # type: ignore
from botocore.config import Config  # type: ignore
from botocore.exceptions import BotoCoreError, ClientError  # type: ignore

# Try to reuse repo SDK config if available
try:
    from FinOps_Toolset_V2_profiler import (  # type: ignore
        SDK_CONFIG as _SDK_CONFIG,
    )
except Exception:  # pylint: disable=broad-exception-caught
    _SDK_CONFIG = Config(
        retries={"max_attempts": 10, "mode": "standard"},
        user_agent_extra="finops-auto-remediator/2.0",
    )

# ------------------ CSV helpers ------------------

FLAG_COL_CANDIDATES = ["Flags", "FlaggedForReview", "flagged_for_review"]
SIGNALS_COL_CANDIDATES = ["Signals", "signals"]
RESOURCE_ID_COL = "Resource_ID"
RESOURCE_TYPE_COL = "ResourceType"
NAME_COL = "Name"

ENI_TYPES = {"eni", "networkinterface", "ec2eni", "ec2_network_interface"}
EIP_TYPES = {"eip", "elasticip", "address", "ec2address"}
CWL_TYPES = {"loggroup", "cloudwatchloggroup", "cloudwatch_logs", "cloudwatchlog"}
EBS_TYPES = {"ebs", "ebsvolume", "volume", "ec2volume"}
S3_TYPES = {"s3", "s3bucket", "bucket"}

CONF_TOKENS = {"confidence=100", "confidence=high", "conf=100"}
SAFE_ENI_TOKENS = {
    "orphaneni",
    "orphan_eni",
    "unattached",
    "safedelete",
    "safe_delete",
    "available",
}
DETACH_TOKENS = {"detachable", "force_detach_ok", "safe_detach"}

SAFE_EIP_TOKENS = {"unassociated", "unused", "release_ok", "safe_release"}
CWL_NO_RETENTION_TOKENS = {"noretention", "retention=0", "retention:0", "no_retention"}
EBS_SAFE_TOKENS = {"available", "unattached", "safedelete", "safe_delete"}
S3_EMPTY_TOKENS = {"emptybucket", "empty_bucket", "safedelete", "safe_delete"}

RETENTION_EXTRACT_RE = re.compile(r"(?:setretention|retention)[=: ]?(\d+)", re.IGNORECASE)


def _sniff_delimiter(path: str) -> str:
    """Guess delimiter from a small sample of the CSV file.

    Falls back to ';' (the toolset default) when sniffing fails.
    """
    with open(path, "r", encoding="utf-8") as handle:
        sample = handle.read(4096)
    try:
        dialect = csv.Sniffer().sniff(sample, delimiters=[",", ";", "\t", "|"])
        return dialect.delimiter
    except csv.Error:
        return ";"  # default used in your toolset


def _normalize_flags(raw: str) -> List[str]:
    """Split and normalize pipe/semicolon/comma-separated flag string."""
    if not raw:
        return []
    parts = re.split(r"[|,;]+", str(raw))
    return [p.strip().lower() for p in parts if p.strip()]


def _parse_signals(raw: str) -> Dict[str, str]:
    """Parse the Signals column into a dict of key=value tokens."""
    out: Dict[str, str] = {}
    if not raw:
        return out
    for tok in re.split(r"[|,]+", str(raw)):
        tok = tok.strip()
        if not tok or "=" not in tok:
            continue
        key, val = tok.split("=", 1)
        out[key.strip()] = val.strip()
    return out


def _find_column(row: dict, candidates: List[str]) -> Optional[str]:
    """Find the first present column among candidates (case-insensitive)."""
    lower_map = {k.lower(): k for k in row.keys()}
    for cand in candidates:
        if cand.lower() in lower_map:
            return lower_map[cand.lower()]
    return None


# ------------------ Region helpers ------------------


def _extract_region(signals: Dict[str, str]) -> str:
    """Infer region from Signals (Region= or AZ=) or environment."""
    region = signals.get("Region") or signals.get("region") or ""
    if region:
        return region
    az = signals.get("AZ") or signals.get("AvailabilityZone") or ""
    if az and len(az) >= 2:
        return az[:-1]  # eu-west-1a -> eu-west-1
    return os.getenv("AWS_REGION") or os.getenv("AWS_DEFAULT_REGION") or ""


# ------------------ AWS helpers ------------------


def _sleep_backoff(attempt: int) -> None:
    """Sleep with exponential backoff up to a small cap."""
    time.sleep(min(2**attempt, 8))


def _aws_call(func, *args, **kwargs):
    """Invoke a boto3 call with light retry on throttling/server errors.

    Only botocore errors are retried; other exceptions propagate immediately.
    """
    for attempt in range(4):
        try:
            return func(*args, **kwargs)
        except ClientError as err:
            code = (err.response or {}).get("Error", {}).get("Code", "")
            throttled = code in {
                "Throttling",
                "ThrottlingException",
                "RequestLimitExceeded",
            } or code.startswith("5")
            if throttled and attempt < 3:
                _sleep_backoff(attempt)
                continue
            raise
        except BotoCoreError:
            if attempt < 3:
                _sleep_backoff(attempt)
                continue
            raise


# ------------------ CSV item model ------------------


@dataclass
class CsvItem:
    """One row from the CSV converted to a normalized structure."""

    region: str
    resource_type: str
    resource_id: str
    name: str
    flags: List[str]
    signals: Dict[str, str]
    raw: dict


def _looks_like_type(row: dict, wanted: set[str]) -> bool:
    """Check whether ResourceType matches one of the wanted identifiers."""
    rtype = (row.get(RESOURCE_TYPE_COL) or "").strip().lower()
    return rtype in wanted


def _collect_items(path: str) -> List[CsvItem]:
    """Load CSV rows and map them into :class:`CsvItem` objects."""
    delim = _sniff_delimiter(path)
    items: List[CsvItem] = []
    with open(path, "r", encoding="utf-8") as handle:
        reader = csv.DictReader(handle, delimiter=delim)
        for row in reader:
            try:
                rid = (row.get(RESOURCE_ID_COL) or "").strip()
                if not rid:
                    continue
                flags_col = _find_column(row, FLAG_COL_CANDIDATES)
                sig_col = _find_column(row, SIGNALS_COL_CANDIDATES)
                flags = _normalize_flags(row.get(flags_col or "", ""))
                sigs = _parse_signals(row.get(sig_col or "", ""))
                rtype = (row.get(RESOURCE_TYPE_COL) or "").strip().lower()
                region = _extract_region(sigs)
                items.append(
                    CsvItem(
                        region=region,
                        resource_type=rtype,
                        resource_id=rid,
                        name=(row.get(NAME_COL) or "").strip(),
                        flags=flags,
                        signals=sigs,
                        raw=row,
                    )
                )
            except (KeyError, ValueError, csv.Error):
                # Skip malformed rows, keep processing.
                continue
    return items


# ------------------ Actions ------------------


def _eni_delete(ec2, eni_id: str, execute: bool) -> bool:
    """Delete an unattached ENI, honoring dry-run."""
    _aws_call(
        ec2.delete_network_interface,
        NetworkInterfaceId=eni_id,
        DryRun=not execute,
    )
    return True


def _eni_detach_and_delete(ec2, eni_id: str, execute: bool) -> bool:
    """Detach (if needed) and delete an ENI, with a brief wait loop when executing."""
    resp = _aws_call(ec2.describe_network_interfaces, NetworkInterfaceIds=[eni_id])
    eni = (resp.get("NetworkInterfaces") or [{}])[0]
    attachment = eni.get("Attachment") or {}
    attachment_id = attachment.get("AttachmentId")
    if not attachment_id:
        _aws_call(
            ec2.delete_network_interface, NetworkInterfaceId=eni_id, DryRun=not execute
        )
        return True

    _aws_call(
        ec2.detach_network_interface, AttachmentId=attachment_id, Force=True, DryRun=not execute
    )
    if execute:
        for _ in range(20):
            time.sleep(3)
            try:
                desc = _aws_call(
                    ec2.describe_network_interfaces, NetworkInterfaceIds=[eni_id]
                )
                status = (desc.get("NetworkInterfaces") or [{}])[0].get("Status", "")
                if status == "available":
                    break
            except (ClientError, BotoCoreError):
                break

    _aws_call(ec2.delete_network_interface, NetworkInterfaceId=eni_id, DryRun=not execute)
    return True


def _eip_release(ec2, rid: str, execute: bool, verify: bool) -> bool:
    """Release an unassociated Elastic IP (by allocation id or by public IP)."""
    alloc_id = None
    public_ip = None
    if rid.startswith("eipalloc-"):
        alloc_id = rid
    elif re.match(r"^\d+\.\d+\.\d+\.\d+$", rid):
        public_ip = rid
    elif rid.startswith("arn:aws:ec2"):
        match = re.search(r"eipalloc-[0-9a-f]+", rid)
        if match:
            alloc_id = match.group(0)

    if verify:
        # Ensure it's unassociated
        if alloc_id:
            desc = _aws_call(ec2.describe_addresses, AllocationIds=[alloc_id])
        else:
            desc = _aws_call(ec2.describe_addresses, PublicIps=[public_ip])
        addrs = desc.get("Addresses", [])
        if not addrs:
            return True
        if addrs[0].get("AssociationId"):
            return False

    if alloc_id:
        _aws_call(ec2.release_address, AllocationId=alloc_id, DryRun=not execute)
    else:
        _aws_call(ec2.release_address, PublicIp=public_ip, DryRun=not execute)
    return True


def _cwl_set_retention(logs, group_name: str, days: int, execute: bool) -> bool:
    """Set retention policy (days) on a log group, honoring dry-run."""
    _aws_call(
        logs.put_retention_policy,
        logGroupName=group_name,
        retentionInDays=days,
        DryRun=not execute,
    )
    return True


def _ebs_delete(ec2, vol_id: str, execute: bool, verify: bool) -> bool:
    """Delete an unattached EBS volume, with optional verification."""
    if verify:
        desc = _aws_call(ec2.describe_volumes, VolumeIds=[vol_id])
        volumes = desc.get("Volumes", [])
        if not volumes:
            return True
        volume = volumes[0]
        state = volume.get("State")
        if state != "available" or volume.get("Attachments"):
            return False

    _aws_call(ec2.delete_volume, VolumeId=vol_id, DryRun=not execute)
    return True


def _s3_delete_bucket(s3, bucket: str, execute: bool, verify: bool) -> bool:
    """Delete an empty S3 bucket; when verifying, check both objects and version markers."""
    if verify:
        try:
            _aws_call(s3.head_bucket, Bucket=bucket)
        except ClientError:
            # Ignore missing / wrong region hints here; we check content next.
            pass

        try:
            versions = _aws_call(s3.list_object_versions, Bucket=bucket, MaxKeys=1)
            has_versions = bool(versions.get("Versions") or [])
            has_markers = bool(versions.get("DeleteMarkers") or [])
            if has_versions or has_markers:
                return False
        except ClientError:
            # Maybe versioning never enabled; fall back to list_objects_v2
            pass

        objects = _aws_call(s3.list_objects_v2, Bucket=bucket, MaxKeys=1)
        if (objects or {}).get("KeyCount", 0) != 0:
            return False

    if execute:
        _aws_call(s3.delete_bucket, Bucket=bucket)
    return True


# ------------------ Engine ------------------


@dataclass
class Summary:
    """Simple counters for the per-type summary at the end of the run."""

    deleted: int = 0
    changed: int = 0
    skipped: int = 0
    errors: int = 0


def act_from_csv(
    csv_path: str,
    execute: bool = False,
    verify: bool = True,
    allow_detach: bool = False,
    do_eni: bool = True,
    do_eip: bool = True,
    do_cwl: bool = True,
    do_ebs: bool = True,
    do_s3: bool = True,
    retention_days: int = 30,
) -> Dict[str, Summary]:
    """Perform CSV-driven remediations and return a per-type :class:`Summary` mapping."""
    items = _collect_items(csv_path)
    summaries: Dict[str, Summary] = {
        "ENI": Summary(),
        "EIP": Summary(),
        "CWL": Summary(),
        "EBS": Summary(),
        "S3": Summary(),
    }

    # Group by region to reuse clients
    by_region: Dict[str, List[CsvItem]] = {}
    for item in items:
        by_region.setdefault(item.region or "default", []).append(item)

    for region, rows in by_region.items():
        ec2 = boto3.client("ec2", region_name=(region or None), config=_SDK_CONFIG)
        logs = boto3.client("logs", region_name=(region or None), config=_SDK_CONFIG)
        s3 = boto3.client("s3", config=_SDK_CONFIG)  # S3 is global

        for item in rows:
            flags = set(item.flags)
            conf_ok = bool(CONF_TOKENS & flags)

            # ENI
            if do_eni and item.resource_type in ENI_TYPES and item.resource_id.startswith("eni-"):
                if not conf_ok:
                    summaries["ENI"].skipped += 1
                    continue
                try:
                    is_safe_delete = bool(flags & SAFE_ENI_TOKENS)
                    is_detach_ok = allow_detach and bool(flags & DETACH_TOKENS)
                    if verify:
                        desc = _aws_call(
                            ec2.describe_network_interfaces,
                            NetworkInterfaceIds=[item.resource_id],
                        )
                        eni = (desc.get("NetworkInterfaces") or [{}])[0]
                        status = eni.get("Status", "")
                        attached = bool(eni.get("Attachment"))
                    else:
                        status = "available" if is_safe_delete else "in-use"
                        attached = not is_safe_delete

                    if is_safe_delete and status == "available" and not attached:
                        _eni_delete(ec2, item.resource_id, execute)
                        summaries["ENI"].deleted += 1 if execute else 0
                        summaries["ENI"].skipped += 0 if execute else 1
                        continue

                    if is_detach_ok and attached:
                        _eni_detach_and_delete(ec2, item.resource_id, execute)
                        summaries["ENI"].deleted += 1 if execute else 0
                        summaries["ENI"].skipped += 0 if execute else 1
                        continue

                    summaries["ENI"].skipped += 1
                except (ClientError, BotoCoreError) as err:
                    logging.error("ENI error %s: %s", item.resource_id, err)
                    summaries["ENI"].errors += 1
                continue

            # EIP
            if do_eip and item.resource_type in EIP_TYPES:
                if not conf_ok or not flags & SAFE_EIP_TOKENS:
                    summaries["EIP"].skipped += 1
                    continue
                try:
                    ok = _eip_release(ec2, item.resource_id, execute, verify)
                    if ok:
                        summaries["EIP"].deleted += 1 if execute else 0
                        summaries["EIP"].skipped += 0 if execute else 1
                    else:
                        summaries["EIP"].skipped += 1
                except (ClientError, BotoCoreError) as err:
                    logging.error("EIP error %s: %s", item.resource_id, err)
                    summaries["EIP"].errors += 1
                continue

            # CloudWatch Logs retention
            if do_cwl and item.resource_type in CWL_TYPES:
                if not conf_ok:
                    summaries["CWL"].skipped += 1
                    continue
                days = retention_days
                for flag in flags:
                    match = RETENTION_EXTRACT_RE.search(flag)
                    if match:
                        try:
                            days = int(match.group(1))
                        except ValueError:
                            # Ignore unparsable days; keep default
                            pass
                log_group = (
                    item.resource_id
                    if item.resource_id.startswith("/")
                    else (item.name or item.resource_id)
                )
                try:
                    if verify:
                        try:
                            desc = _aws_call(
                                logs.describe_log_groups, logGroupNamePrefix=log_group
                            )
                            groups = desc.get("logGroups", [])
                            group = next(
                                (g for g in groups if g.get("logGroupName") == log_group),
                                None,
                            )
                            if group and group.get("retentionInDays"):
                                summaries["CWL"].skipped += 1
                                continue
                        except ClientError:
                            pass
                    _cwl_set_retention(logs, log_group, days, execute)
                    summaries["CWL"].changed += 1 if execute else 0
                    summaries["CWL"].skipped += 0 if execute else 1
                except (ClientError, BotoCoreError) as err:
                    logging.error("CWL error %s: %s", log_group, err)
                    summaries["CWL"].errors += 1
                continue

            # EBS volumes
            if do_ebs and item.resource_type in EBS_TYPES and item.resource_id.startswith("vol-"):
                if not conf_ok or not flags & EBS_SAFE_TOKENS:
                    summaries["EBS"].skipped += 1
                    continue
                try:
                    ok = _ebs_delete(ec2, item.resource_id, execute, verify)
                    if ok:
                        summaries["EBS"].deleted += 1 if execute else 0
                        summaries["EBS"].skipped += 0 if execute else 1
                    else:
                        summaries["EBS"].skipped += 1
                except (ClientError, BotoCoreError) as err:
                    logging.error("EBS error %s: %s", item.resource_id, err)
                    summaries["EBS"].errors += 1
                continue

            # S3 buckets
            if do_s3 and item.resource_type in S3_TYPES:
                bucket = (
                    item.resource_id
                    if not item.resource_id.startswith("arn:")
                    else item.name or item.signals.get("Bucket") or ""
                )
                if not bucket:
                    summaries["S3"].skipped += 1
                    continue
                if not conf_ok or not flags & S3_EMPTY_TOKENS:
                    summaries["S3"].skipped += 1
                    continue
                try:
                    ok = _s3_delete_bucket(s3, bucket, execute, verify)
                    if ok:
                        summaries["S3"].deleted += 1 if execute else 0
                        summaries["S3"].skipped += 0 if execute else 1
                    else:
                        summaries["S3"].skipped += 1
                except (ClientError, BotoCoreError) as err:
                    logging.error("S3 error %s: %s", bucket, err)
                    summaries["S3"].errors += 1
                continue

    return summaries


# ------------------ CLI ------------------


def _parse_args(argv: List[str]) -> argparse.Namespace:
    """Parse command-line arguments for the auto-remediator."""
    parser = argparse.ArgumentParser(
        description=(
            "Auto-remediate resources from FinOps scanner CSV (no re-scan). "
            "Dry-run by default."
        )
    )
    parser.add_argument("csv", help="Path to scanner CSV (e.g., cleanup_estimates.csv).")
    parser.add_argument("--execute", action="store_true", help="Perform changes.")
    parser.add_argument(
        "--no-verify",
        action="store_true",
        help="Trust CSV strictly; no Describe/HEAD checks.",
    )
    parser.add_argument(
        "--allow-detach",
        action="store_true",
        help="Allow ENI detach+delete when flagged.",
    )
    parser.add_argument(
        "--do-eni", action="store_true", default=False, help="Enable ENI cleanup from CSV."
    )
    parser.add_argument(
        "--do-eip", action="store_true", default=False, help="Enable EIP release from CSV."
    )
    parser.add_argument(
        "--do-cwl",
        action="store_true",
        default=False,
        help="Enable CloudWatch Logs retention set.",
    )
    parser.add_argument(
        "--do-ebs",
        action="store_true",
        default=False,
        help="Enable EBS unattached volume deletion.",
    )
    parser.add_argument(
        "--do-s3", action="store_true", default=False, help="Enable S3 empty bucket deletion."
    )
    parser.add_argument(
        "--retention-days",
        type=int,
        default=30,
        help="Retention days for CW Logs (default 30).",
    )
    parser.add_argument(
        "--log-level",
        default=os.getenv("LOG_LEVEL", "INFO"),
        choices=["CRITICAL", "ERROR", "WARNING", "INFO", "DEBUG"],
    )
    return parser.parse_args(argv)


def main(argv: Optional[List[str]] = None) -> int:
    """CLI entrypoint. Returns process exit code."""
    args = _parse_args(list(sys.argv[1:] if argv is None else argv))
    logging.basicConfig(level=getattr(logging, args.log_level), format="%(levelname)s %(message)s")
    if not os.path.exists(args.csv):
        logging.error("CSV not found: %s", args.csv)
        return 2

    summaries = act_from_csv(
        csv_path=args.csv,
        execute=args.execute,
        verify=not args.no_verify,
        allow_detach=args.allow_detach,
        do_eni=args.do_eni,
        do_eip=args.do_eip,
        do_cwl=args.do_cwl,
        do_ebs=args.do_ebs,
        do_s3=args.do_s3,
        retention_days=args.retention_days,
    )

    print("\n=== Auto-remediation summary (CSV-driven) ===")
    for key, summ in summaries.items():
        if summ.deleted or summ.changed or summ.skipped or summ.errors:
            print(
                f"{key:>3}: deleted={summ.deleted} changed={summ.changed} "
                f"skipped={summ.skipped} errors={summ.errors}"
            )

    # Non-zero if any errors
    errors = sum(summ.errors for summ in summaries.values())
    return 0 if errors == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
