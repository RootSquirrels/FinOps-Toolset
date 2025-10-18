#!/usr/bin/env python3
"""
auto_remediations_from_csv.py
---------------------------------

Auto-remediate "easy" items using the **scanner's CSV output** as the source
of truth (no full re-scan). Defaults to **dry-run**; add --execute to apply.

Supported (all CSV-driven, confidence=100 required):
  • ENI (NetworkInterface): delete **unattached** ENIs (confidence=100 path).
    - Optional: --allow-detach for rows explicitly flagged as detachable.
  • EIP (Elastic IP): release **unassociated** addresses.
  • CloudWatch Log Groups: set a **retention policy** (e.g., 30 days) when missing.
  • EBS Volumes: delete **unattached** volumes.
  • S3 Buckets: delete **empty** buckets (and versioning has no objects/delete-markers).

Each action can be toggled via CLI flags; verification calls can be disabled with --no-verify
to trust the CSV strictly (fastest).

CSV expectations (robust to naming):
  - `ResourceType`, `Resource_ID`, `Name`, `Flags`/`FlaggedForReview`, `Signals`
  - Region is read from `Signals` (key `Region=`). We fall back to AZ minus letter, or default env region.
  - Required flags must include `confidence=100` and a type-specific token (e.g., `unattached`, `emptybucket`, `noretention`).

Usage:
    python auto_remediations_from_csv.py cleanup_estimates.csv                   # dry-run
    python auto_remediations_from_csv.py cleanup_estimates.csv --execute         # apply all safe actions
    python auto_remediations_from_csv.py cleanup_estimates.csv --execute --allow-detach --do-s3 --do-ebs
    python auto_remediations_from_csv.py cleanup_estimates.csv --do-cwl --retention-days 30

Exit status is non-zero if any errors occurred.
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
from typing import Dict, Iterable, List, Optional, Tuple

import boto3 #type: ignore
from botocore.config import Config #type: ignore
from botocore.exceptions import ClientError #type: ignore

# Try to reuse repo SDK config if available
try:
    from FinOps_Toolset_V2_profiler import SDK_CONFIG as _SDK_CONFIG  # type: ignore
except Exception:
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
S3_TYPES  = {"s3", "s3bucket", "bucket"}

CONF_TOKENS = {"confidence=100", "confidence=high", "conf=100"}
SAFE_ENI_TOKENS = {"orphaneni", "orphan_eni", "unattached", "safedelete", "safe_delete", "available"}
DETACH_TOKENS = {"detachable", "force_detach_ok", "safe_detach"}

SAFE_EIP_TOKENS = {"unassociated", "unused", "release_ok", "safe_release"}
CWL_NO_RETENTION_TOKENS = {"noretention", "retention=0", "retention:0", "no_retention"}
EBS_SAFE_TOKENS = {"available", "unattached", "safedelete", "safe_delete"}
S3_EMPTY_TOKENS = {"emptybucket", "empty_bucket", "safedelete", "safe_delete"}

RETENTION_EXTRACT_RE = re.compile(r"(?:setretention|retention)[=: ]?(\d+)", re.IGNORECASE)

def _sniff_delimiter(path: str) -> str:
    with open(path, "r", encoding="utf-8") as f:
        sample = f.read(4096)
    try:
        dialect = csv.Sniffer().sniff(sample, delimiters=[",", ";", "\t", "|"])
        return dialect.delimiter
    except Exception:
        return ";"  # default used in your toolset

def _normalize_flags(raw: str) -> List[str]:
    if not raw:
        return []
    parts = re.split(r"[|,;]+", str(raw))
    return [p.strip().lower() for p in parts if p.strip()]

def _parse_signals(raw: str) -> Dict[str, str]:
    out: Dict[str, str] = {}
    if not raw:
        return out
    for tok in re.split(r"[|,]+", str(raw)):
        tok = tok.strip()
        if not tok or "=" not in tok:
            continue
        k, v = tok.split("=", 1)
        out[k.strip()] = v.strip()
    return out

def _find_column(row: dict, candidates: List[str]) -> Optional[str]:
    lc = {k.lower(): k for k in row.keys()}
    for c in candidates:
        if c.lower() in lc:
            return lc[c.lower()]
    return None

# ------------------ Region helpers ------------------

def _extract_region(signals: Dict[str, str]) -> str:
    r = signals.get("Region") or signals.get("region") or ""
    if r:
        return r
    az = signals.get("AZ") or signals.get("AvailabilityZone") or ""
    if az and len(az) >= 2:
        return az[:-1]  # eu-west-1a -> eu-west-1
    return os.getenv("AWS_REGION") or os.getenv("AWS_DEFAULT_REGION") or ""

# ------------------ AWS helpers ------------------

def _sleep_backoff(attempt: int) -> None:
    time.sleep(min(2 ** attempt, 8))

def _aws_call(fn, *args, **kwargs):
    for attempt in range(4):
        try:
            return fn(*args, **kwargs)
        except ClientError as e:
            code = (e.response or {}).get("Error", {}).get("Code", "")
            if code in {"Throttling", "ThrottlingException", "RequestLimitExceeded"} or code.startswith("5"):
                if attempt < 3:
                    _sleep_backoff(attempt)
                    continue
            raise
        except Exception:
            if attempt < 3:
                _sleep_backoff(attempt)
                continue
            raise

# ------------------ CSV item model ------------------

@dataclass
class CsvItem:
    region: str
    resource_type: str
    resource_id: str
    name: str
    flags: List[str]
    signals: Dict[str, str]
    raw: dict

def _looks_like_type(row: dict, wanted: set[str]) -> bool:
    rt = (row.get(RESOURCE_TYPE_COL) or "").strip().lower()
    return rt in wanted

def _collect_items(path: str) -> List[CsvItem]:
    delim = _sniff_delimiter(path)
    items: List[CsvItem] = []
    with open(path, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f, delimiter=delim)
        for row in reader:
            try:
                rid = (row.get(RESOURCE_ID_COL) or "").strip()
                if not rid:
                    continue
                flags_col = _find_column(row, FLAG_COL_CANDIDATES)
                sig_col = _find_column(row, SIGNALS_COL_CANDIDATES)
                flags = _normalize_flags(row.get(flags_col or "", ""))
                sigs = _parse_signals(row.get(sig_col or "", ""))
                rt_raw = (row.get(RESOURCE_TYPE_COL) or "").strip().lower()
                rgn = _extract_region(sigs)
                items.append(CsvItem(
                    region=rgn,
                    resource_type=rt_raw,
                    resource_id=rid,
                    name=(row.get(NAME_COL) or "").strip(),
                    flags=flags,
                    signals=sigs,
                    raw=row,
                ))
            except Exception:
                continue
    return items

# ------------------ Actions ------------------

def _eni_delete(ec2, eni_id: str, execute: bool) -> bool:
    _aws_call(ec2.delete_network_interface, NetworkInterfaceId=eni_id, DryRun=(not execute))
    return True

def _eni_detach_and_delete(ec2, eni_id: str, execute: bool) -> bool:
    # best-effort: describe to fetch attachment
    resp = _aws_call(ec2.describe_network_interfaces, NetworkInterfaceIds=[eni_id])
    eni = (resp.get("NetworkInterfaces") or [{}])[0]
    att = eni.get("Attachment") or {}
    att_id = att.get("AttachmentId")
    if not att_id:
        # Fall back to plain delete (maybe already detached)
        _aws_call(ec2.delete_network_interface, NetworkInterfaceId=eni_id, DryRun=(not execute))
        return True
    _aws_call(ec2.detach_network_interface, AttachmentId=att_id, Force=True, DryRun=(not execute))
    if execute:
        # brief wait loop
        for _ in range(20):
            time.sleep(3)
            try:
                e2 = _aws_call(ec2.describe_network_interfaces, NetworkInterfaceIds=[eni_id])
                st = (e2.get("NetworkInterfaces") or [{}])[0].get("Status", "")
                if st == "available":
                    break
            except Exception:
                break
    _aws_call(ec2.delete_network_interface, NetworkInterfaceId=eni_id, DryRun=(not execute))
    return True

def _eip_release(ec2, rid: str, execute: bool, verify: bool) -> bool:
    alloc_id = None
    public_ip = None
    if rid.startswith("eipalloc-"):
        alloc_id = rid
    elif re.match(r"^\d+\.\d+\.\d+\.\d+$", rid):
        public_ip = rid
    elif rid.startswith("arn:aws:ec2"):
        # try to find allocation id at the end
        m = re.search(r"eipalloc-[0-9a-f]+", rid)
        if m:
            alloc_id = m.group(0)
    if verify:
        # ensure it's unassociated
        desc = _aws_call(ec2.describe_addresses, AllocationIds=[alloc_id]) if alloc_id else \
               _aws_call(ec2.describe_addresses, PublicIps=[public_ip])
        addrs = desc.get("Addresses", [])
        if not addrs:
            # nothing to do
            return True
        assoc = addrs[0].get("AssociationId")
        if assoc:
            # still associated -> don't release in verify mode
            return False
    if alloc_id:
        _aws_call(ec2.release_address, AllocationId=alloc_id, DryRun=(not execute))
    else:
        _aws_call(ec2.release_address, PublicIp=public_ip, DryRun=(not execute))
    return True

def _cwl_set_retention(logs, group_name: str, days: int, execute: bool) -> bool:
    _aws_call(logs.put_retention_policy, logGroupName=group_name, retentionInDays=days, DryRun=(not execute))
    return True

def _ebs_delete(ec2, vol_id: str, execute: bool, verify: bool) -> bool:
    if verify:
        d = _aws_call(ec2.describe_volumes, VolumeIds=[vol_id])
        vols = d.get("Volumes", [])
        if not vols:
            return True
        v = vols[0]
        state = v.get("State")
        if state != "available" or v.get("Attachments"):
            return False
    _aws_call(ec2.delete_volume, VolumeId=vol_id, DryRun=(not execute))
    return True

def _s3_delete_bucket(s3, bn: str, execute: bool, verify: bool) -> bool:
    # S3 is global; when verify, confirm truly empty (including versioned markers)
    if verify:
        # find region (HeadBucket redirects with x-amz-bucket-region)
        try:
            _aws_call(s3.head_bucket, Bucket=bn)
        except ClientError as e:
            # try to recover region hint
            pass
        # quick emptiness checks
        try:
            v = _aws_call(s3.list_object_versions, Bucket=bn, MaxKeys=1)
            if (v.get("Versions") or []) or (v.get("DeleteMarkers") or []):
                return False
        except ClientError:
            # maybe no versioning; fall back to list_objects_v2
            pass
        o = _aws_call(s3.list_objects_v2, Bucket=bn, MaxKeys=1)
        if (o or {}).get("KeyCount", 0) != 0:
            return False
    _aws_call(s3.delete_bucket, Bucket=bn) if execute else None
    return True

# ------------------ Engine ------------------

@dataclass
class Summary:
    deleted: int = 0
    changed: int = 0
    skipped: int = 0
    errors:  int = 0

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
    """
    Perform CSV-driven remediations. Returns a per-type Summary dict.
    """
    items = _collect_items(csv_path)
    summaries: Dict[str, Summary] = {
        "ENI": Summary(), "EIP": Summary(), "CWL": Summary(), "EBS": Summary(), "S3": Summary()
    }
    # group by region to reuse clients
    by_region: Dict[str, List[CsvItem]] = {}
    for it in items:
        by_region.setdefault(it.region or "default", []).append(it)

    for region, lst in by_region.items():
        ec2 = boto3.client("ec2", region_name=(region or None), config=_SDK_CONFIG)
        logs = boto3.client("logs", region_name=(region or None), config=_SDK_CONFIG)
        s3   = boto3.client("s3", config=_SDK_CONFIG)  # S3 is global

        for it in lst:
            flags = set(it.flags)
            conf_ok = bool(CONF_TOKENS & flags)

            # ENI
            if do_eni and it.resource_type in ENI_TYPES and it.resource_id.startswith("eni-"):
                if not conf_ok:
                    summaries["ENI"].skipped += 1
                    continue
                try:
                    is_safe_delete = bool(flags & SAFE_ENI_TOKENS)
                    is_detach_ok   = allow_detach and bool(flags & DETACH_TOKENS)
                    if verify:
                        # Check actual state if verifying
                        d = _aws_call(ec2.describe_network_interfaces, NetworkInterfaceIds=[it.resource_id])
                        eni = (d.get("NetworkInterfaces") or [{}])[0]
                        status = eni.get("Status", "")
                        attached = bool(eni.get("Attachment"))
                    else:
                        status = "available" if is_safe_delete else "in-use"
                        attached = not is_safe_delete

                    if is_safe_delete and status == "available" and not attached:
                        _eni_delete(ec2, it.resource_id, execute)
                        summaries["ENI"].deleted += 1 if execute else 0
                        summaries["ENI"].skipped += 0 if execute else 1
                        continue
                    if is_detach_ok and attached:
                        _eni_detach_and_delete(ec2, it.resource_id, execute)
                        summaries["ENI"].deleted += 1 if execute else 0
                        summaries["ENI"].skipped += 0 if execute else 1
                        continue
                    summaries["ENI"].skipped += 1
                except Exception as e:
                    logging.error("ENI error %s: %s", it.resource_id, e)
                    summaries["ENI"].errors += 1
                continue

            # EIP
            if do_eip and it.resource_type in EIP_TYPES:
                if not conf_ok or not (flags & SAFE_EIP_TOKENS):
                    summaries["EIP"].skipped += 1
                    continue
                try:
                    ok = _eip_release(ec2, it.resource_id, execute, verify)
                    if ok:
                        summaries["EIP"].deleted += 1 if execute else 0
                        summaries["EIP"].skipped += 0 if execute else 1
                    else:
                        summaries["EIP"].skipped += 1
                except Exception as e:
                    logging.error("EIP error %s: %s", it.resource_id, e)
                    summaries["EIP"].errors += 1
                continue

            # CloudWatch Logs retention
            if do_cwl and it.resource_type in CWL_TYPES:
                if not conf_ok:
                    summaries["CWL"].skipped += 1
                    continue
                # infer days from flags if provided
                days = retention_days
                for f in flags:
                    m = RETENTION_EXTRACT_RE.search(f)
                    if m:
                        try:
                            days = int(m.group(1))
                        except Exception:
                            pass
                # We need the log group name; most CSVs use Resource_ID or Name for it.
                lg_name = it.resource_id if it.resource_id.startswith("/") else (it.name or it.resource_id)
                try:
                    if verify:
                        # Only set if not already configured or set to 0
                        try:
                            d = _aws_call(logs.describe_log_groups, logGroupNamePrefix=lg_name)
                            groups = d.get("logGroups", [])
                            g = next((g for g in groups if g.get("logGroupName") == lg_name), None)
                            if g and g.get("retentionInDays"):
                                summaries["CWL"].skipped += 1
                                continue
                        except ClientError:
                            pass
                    _cwl_set_retention(logs, lg_name, days, execute)
                    summaries["CWL"].changed += 1 if execute else 0
                    summaries["CWL"].skipped += 0 if execute else 1
                except Exception as e:
                    logging.error("CWL error %s: %s", lg_name, e)
                    summaries["CWL"].errors += 1
                continue

            # EBS volumes
            if do_ebs and it.resource_type in EBS_TYPES and it.resource_id.startswith("vol-"):
                if not conf_ok or not (flags & EBS_SAFE_TOKENS):
                    summaries["EBS"].skipped += 1
                    continue
                try:
                    ok = _ebs_delete(ec2, it.resource_id, execute, verify)
                    if ok:
                        summaries["EBS"].deleted += 1 if execute else 0
                        summaries["EBS"].skipped += 0 if execute else 1
                    else:
                        summaries["EBS"].skipped += 1
                except Exception as e:
                    logging.error("EBS error %s: %s", it.resource_id, e)
                    summaries["EBS"].errors += 1
                continue

            # S3 buckets
            if do_s3 and it.resource_type in S3_TYPES:
                bn = it.resource_id if not it.resource_id.startswith("arn:") else it.name or it.signals.get("Bucket") or ""
                if not bn:
                    summaries["S3"].skipped += 1
                    continue
                if not conf_ok or not (flags & S3_EMPTY_TOKENS):
                    summaries["S3"].skipped += 1
                    continue
                try:
                    ok = _s3_delete_bucket(s3, bn, execute, verify)
                    if ok:
                        summaries["S3"].deleted += 1 if execute else 0
                        summaries["S3"].skipped += 0 if execute else 1
                    else:
                        summaries["S3"].skipped += 1
                except Exception as e:
                    logging.error("S3 error %s: %s", bn, e)
                    summaries["S3"].errors += 1
                continue

    return summaries

# ------------------ CLI ------------------

def _parse_args(argv: List[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Auto-remediate resources from FinOps scanner CSV (no re-scan).")
    p.add_argument("csv", help="Path to scanner CSV (e.g., cleanup_estimates.csv).")
    p.add_argument("--execute", action="store_true", help="Perform changes. Default: dry-run.")
    p.add_argument("--no-verify", action="store_true", help="Trust CSV strictly; no Describe/HEAD checks.")
    p.add_argument("--allow-detach", action="store_true", help="Allow ENI detach+delete when flagged.")
    p.add_argument("--do-eni", action="store_true", default=False, help="Enable ENI cleanup from CSV.")
    p.add_argument("--do-eip", action="store_true", default=False, help="Enable EIP release from CSV.")
    p.add_argument("--do-cwl", action="store_true", default=False, help="Enable CloudWatch Logs retention set.")
    p.add_argument("--do-ebs", action="store_true", default=False, help="Enable EBS unattached volume deletion.")
    p.add_argument("--do-s3", action="store_true", default=False, help="Enable S3 empty bucket deletion.")
    p.add_argument("--retention-days", type=int, default=30, help="Retention days for CW Logs (default 30).")
    p.add_argument("--log-level", default=os.getenv("LOG_LEVEL", "INFO"),
                   choices=["CRITICAL", "ERROR", "WARNING", "INFO", "DEBUG"])
    return p.parse_args(argv)

def main(argv: Optional[List[str]] = None) -> int:
    args = _parse_args(list(sys.argv[1:] if argv is None else argv))
    logging.basicConfig(level=getattr(logging, args.log_level), format="%(levelname)s %(message)s")
    if not os.path.exists(args.csv):
        logging.error("CSV not found: %s", args.csv)
        return 2

    # Require explicit opt-in for each category (safer defaults)
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
    for k, s in summaries.items():
        if s.deleted or s.changed or s.skipped or s.errors:
            print(f"{k:>3}: deleted={s.deleted} changed={s.changed} skipped={s.skipped} errors={s.errors}")

    # Non-zero if any errors
    errors = sum(s.errors for s in summaries.values())
    return 0 if errors == 0 else 1

if __name__ == "__main__":
    sys.exit(main())
