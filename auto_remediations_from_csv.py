#!/usr/bin/env python3
"""
auto_remediations_from_csv.py
---------------------------------

Auto-remediate "easy" items using the **scanner's CSV output** as the source
of truth (no fresh discovery scan). Starts with **ENI cleanup**.

Principles:
- Trust the normalized CSV your FinOps scanner emits.
- Only act on rows explicitly flagged as high confidence (confidence=100).
- Default is DRY-RUN. Use --execute to perform changes.
- Optional lightweight verification (DescribeNetworkInterfaces) can be turned off.

Supported resources (initial):
- ENI (NetworkInterface): delete orphaned/unattached ENIs.
  * Requires flags in CSV indicating both resource type and confidence.
  * Optionally: allow_detach for rows explicitly flagged as "Detachable" (opt-in).

CSV assumptions (robust to minor naming changes):
- ResourceType column includes 'ENI' or 'NetworkInterface' (case-insensitive).
- Resource_ID column is the ENI id (eni-xxxxxxxx).
- Flags/FlaggedForReview column contains a comma/pipe/semicolon list (case-insensitive).
  We look for tokens like: 'confidence=100', 'orphaneni', 'safedelete', 'unattached'.
- Signals column contains key=value tokens, one cell, separated by '|' or ','.
  We extract Region=... when present.

Usage:
    python auto_remediations_from_csv.py cleanup_estimates.csv
    python auto_remediations_from_csv.py cleanup_estimates.csv --execute
    python auto_remediations_from_csv.py cleanup_estimates.csv --execute --allow-detach
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

import boto3 # type: ignore
from botocore.config import Config # type: ignore
from botocore.exceptions import ClientError # type: ignore

# Try to borrow repo-wide SDK config if available
try:
    from FinOps_Toolset_V2_profiler import SDK_CONFIG as _SDK_CONFIG  # type: ignore
except Exception:
    _SDK_CONFIG = Config(
        retries={"max_attempts": 10, "mode": "standard"},
        user_agent_extra="finops-auto-remediator/1.0",
    )

# ------------------ CSV helpers ------------------

FLAG_COL_CANDIDATES = ["Flags", "FlaggedForReview", "flagged_for_review"]
SIGNALS_COL_CANDIDATES = ["Signals", "signals"]
RESOURCE_ID_COL = "Resource_ID"
RESOURCE_TYPE_COL = "ResourceType"
NAME_COL = "Name"

def _sniff_delimiter(path: str) -> str:
    with open(path, "r", encoding="utf-8") as f:
        sample = f.read(4096)
    try:
        dialect = csv.Sniffer().sniff(sample, delimiters=[",", ";", "\t", "|"])
        return dialect.delimiter
    except Exception:
        # Default to semicolon (common in the toolset)
        return ";"

def _normalize_flags(raw: str) -> List[str]:
    if not raw:
        return []
    # split on common separators and strip
    parts = re.split(r"[|,;]+", str(raw))
    return [p.strip().lower() for p in parts if p.strip()]

def _parse_signals(raw: str) -> Dict[str, str]:
    out: Dict[str, str] = {}
    if not raw:
        return out
    # split on '|' or ',' first
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

# ------------------ ENI remediation ------------------

CONF_TOKENS = {"confidence=100", "confidence=high", "conf=100"}
SAFE_ENI_TOKENS = {"orphaneni", "orphan_eni", "unattached", "safedelete", "safe_delete", "available"}
DETACH_TOKENS = {"detachable", "force_detach_ok", "safe_detach"}

@dataclass
class CsvItem:
    region: str
    resource_id: str
    name: str
    flags: List[str]
    signals: Dict[str, str]
    raw: dict

def _looks_like_eni(row: dict) -> bool:
    rt = (row.get(RESOURCE_TYPE_COL) or "").strip().lower()
    return rt in {"eni", "networkinterface", "ec2eni", "ec2_network_interface"}

def _extract_region(signals: Dict[str, str]) -> str:
    # Try Signals["Region"], else try AZ to infer region
    r = signals.get("Region") or signals.get("region") or ""
    if r:
        return r
    az = signals.get("AZ") or signals.get("AvailabilityZone") or ""
    if az and len(az) >= 2:
        # e.g., "eu-west-1a" -> "eu-west-1"
        return az[:-1]
    # Fallback: let boto pick default region (can be overridden via env)
    return os.getenv("AWS_REGION") or os.getenv("AWS_DEFAULT_REGION") or ""

def load_csv_candidates(path: str, require_confidence: bool = True) -> List[CsvItem]:
    delim = _sniff_delimiter(path)
    items: List[CsvItem] = []
    with open(path, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f, delimiter=delim)
        for row in reader:
            try:
                if not _looks_like_eni(row):
                    continue
                flags_col = _find_column(row, FLAG_COL_CANDIDATES)
                sig_col = _find_column(row, SIGNALS_COL_CANDIDATES)
                flags_raw = row.get(flags_col or "", "")
                sig_raw = row.get(sig_col or "", "")
                flags = _normalize_flags(flags_raw)
                sigs = _parse_signals(sig_raw)
                rid = (row.get(RESOURCE_ID_COL) or "").strip()
                if not rid or not rid.startswith("eni-"):
                    continue
                # must have confidence tokens (unless turned off)
                if require_confidence and not (CONF_TOKENS & set(flags)):
                    continue
                # must look like safe orphan unless allow_detach is used later
                if not any(t in flags for t in SAFE_ENI_TOKENS) and not any(t in flags for t in DETACH_TOKENS):
                    continue
                region = _extract_region(sigs)
                items.append(CsvItem(
                    region=region,
                    resource_id=rid,
                    name=(row.get(NAME_COL) or "").strip(),
                    flags=flags,
                    signals=sigs,
                    raw=row,
                ))
            except Exception:
                # skip malformed rows
                continue
    return items

def delete_or_detach_from_csv(
    csv_path: str,
    execute: bool = False,
    verify: bool = True,
    allow_detach: bool = False,
    sdk_config: Optional[Config] = None,
) -> Tuple[int, int, int]:
    """
    Act on ENI rows in the CSV.
    Returns (deleted, skipped, errors).
    """
    items = load_csv_candidates(csv_path, require_confidence=True)
    if not items:
        logging.info("No ENI candidates found in CSV (with confidence=100).")
        return (0, 0, 0)

    deleted = 0
    skipped = 0
    errors = 0

    # group by region for client reuse
    by_region: Dict[str, List[CsvItem]] = {}
    for it in items:
        by_region.setdefault(it.region or "default", []).append(it)

    cfg = sdk_config or _SDK_CONFIG

    for region, lst in by_region.items():
        ec2 = boto3.client("ec2", region_name=(region or None), config=cfg)
        logging.info("Processing %d ENIs in region %s (execute=%s, verify=%s, allow_detach=%s)",
                     len(lst), region or "(default)", execute, verify, allow_detach)
        for it in lst:
            try:
                # two paths: safe delete (orphan), or optional detach+delete if flagged
                is_detachable = any(t in it.flags for t in DETACH_TOKENS)
                is_safe_delete = any(t in it.flags for t in SAFE_ENI_TOKENS)

                if verify:
                    try:
                        resp = _aws_call(ec2.describe_network_interfaces,
                                         NetworkInterfaceIds=[it.resource_id])
                        eni = (resp.get("NetworkInterfaces") or [{}])[0]
                        status = eni.get("Status", "")
                        attached = bool(eni.get("Attachment"))
                    except Exception as e:
                        logging.warning("Describe failed for %s: %s", it.resource_id, e)
                        skipped += 1
                        continue
                else:
                    # Trust CSV blindly
                    status = "available" if is_safe_delete else "in-use"
                    attached = not is_safe_delete

                if is_safe_delete and status == "available" and not attached:
                    try:
                        _aws_call(ec2.delete_network_interface,
                                  NetworkInterfaceId=it.resource_id,
                                  DryRun=(not execute))
                        deleted += 1 if execute else 0
                        skipped += 0 if execute else 1
                        logging.info("%s %s", "DELETED" if execute else "DRY-RUN delete", it.resource_id)
                    except Exception as e:
                        errors += 1
                        logging.error("Delete failed for %s: %s", it.resource_id, e)
                    continue

                if allow_detach and is_detachable and attached:
                    try:
                        att_id = (eni.get("Attachment") or {}).get("AttachmentId") if verify else None
                        if verify and att_id:
                            _aws_call(ec2.detach_network_interface,
                                      AttachmentId=att_id, Force=True, DryRun=(not execute))
                            # wait briefly if executing, then delete
                            if execute:
                                # best-effort wait; not a full waiter to keep it light
                                for _ in range(20):
                                    time.sleep(3)
                                    try:
                                        e2 = _aws_call(ec2.describe_network_interfaces,
                                                       NetworkInterfaceIds=[it.resource_id])
                                        st = (e2.get("NetworkInterfaces") or [{}])[0].get("Status", "")
                                        if st == "available":
                                            break
                                    except Exception:
                                        break
                        # delete attempt
                        _aws_call(ec2.delete_network_interface,
                                  NetworkInterfaceId=it.resource_id,
                                  DryRun=(not execute))
                        deleted += 1 if execute else 0
                        skipped += 0 if execute else 1
                        logging.info("%s %s", "DETACHED+DELETED" if execute else "DRY-RUN detach+delete", it.resource_id)
                    except Exception as e:
                        errors += 1
                        logging.error("Detach/Delete failed for %s: %s", it.resource_id, e)
                    continue

                # If we reach here, we didn't meet strict conditions
                skipped += 1
                logging.info("Skipped %s (status=%s attached=%s flags=%s)", it.resource_id, status, attached, it.flags)

            except Exception as e:
                errors += 1
                logging.exception("Unhandled error for %s: %s", it.resource_id, e)

    return (deleted, skipped, errors)

# ------------------ CLI ------------------

def _parse_args(argv: List[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Auto-remediate ENIs from FinOps scanner CSV (no rescan).")
    p.add_argument("csv", help="Path to scanner CSV (e.g., cleanup_estimates.csv).")
    p.add_argument("--execute", action="store_true", help="Perform changes. Default: dry-run.")
    p.add_argument("--no-verify", action="store_true", help="Do NOT call Describe*; trust CSV strictly.")
    p.add_argument("--allow-detach", action="store_true",
                   help="Allow detach+delete for rows explicitly flagged as detachable in CSV.")
    p.add_argument("--log-level", default=os.getenv("LOG_LEVEL", "INFO"),
                   choices=["CRITICAL", "ERROR", "WARNING", "INFO", "DEBUG"])
    return p.parse_args(argv)

def main(argv: Optional[List[str]] = None) -> int:
    args = _parse_args(list(sys.argv[1:] if argv is None else argv))
    logging.basicConfig(level=getattr(logging, args.log_level), format="%(levelname)s %(message)s")
    if not os.path.exists(args.csv):
        logging.error("CSV not found: %s", args.csv)
        return 2
    deleted, skipped, errors = delete_or_detach_from_csv(
        csv_path=args.csv,
        execute=args.execute,
        verify=not args.no_verify,
        allow_detach=args.allow_detach,
    )
    print(f"\nSummary: deleted={deleted} skipped={skipped} errors={errors} "
          f"(mode={'EXECUTE' if args.execute else 'DRY-RUN'}, verify={'yes' if not args.no_verify else 'no'})")
    # Non-zero if errors occurred, so CI can catch
    return 0 if errors == 0 else 1

if __name__ == "__main__":
    sys.exit(main())
