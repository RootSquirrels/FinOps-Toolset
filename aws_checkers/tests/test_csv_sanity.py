"""Checkers: CSV sanity validation.

Purpose
-------
Run after a scan to validate the produced CSV file:
- required columns present
- types sane (numbers parse as finite floats)
- no empty Resource_ID
- no duplicates on Resource_ID (optionally include ResourceType/Region in key)
- no negative numeric values
- no Potential_Saving > Estimated_Cost
- basic structural sanity (row length matches header)

This checker is intentionally conservative: it *reports* issues rather than
attempting to "fix" the CSV.

Contract
--------
Designed to be callable with the same `run_check()` orchestrator wrapper as
other checkers. It does not depend on AWS APIs; it reads the CSV from disk.

Expected kwargs
---------------
csv_path: str (required)
report_path: str (optional) - defaults to "<csv_path>.sanity.csv"
strict: bool (optional) - if True, raises RuntimeError when issues are found
dedupe_key: str (optional) - "resource_id" (default) or "resource_id_type_region"
"""

from __future__ import annotations

import csv
import logging
import math
import os
from dataclasses import dataclass
from typing import Dict, Iterator, List, Optional, Sequence, Set, Tuple

from aws_checkers.common import _logger


# Output CSV headers produced by the profiler (canonical)
_REQUIRED_COLUMNS: Tuple[str, ...] = (
    "Resource_ID",
    "Name",
    "ResourceType",
    "OwnerId",
    "Region",
    "State",
    "Creation_Date",
    "Storage_GB",
    "Object_Count",
    "Estimated_Cost_USD",
    "Potential_Saving_USD",
    "ApplicationID",
    "Application",
    "Environment",
    "Referenced_In",
    "Flagged",
    "Confidence",
    "Signals",
)

# Numeric fields that should be parseable, finite floats when non-empty
_NUMERIC_COLUMNS: Tuple[str, ...] = (
    "Storage_GB",
    "Object_Count",
    "Estimated_Cost_USD",
    "Potential_Saving_USD",
)

# Columns where negative values are never expected
_NON_NEGATIVE_COLUMNS: Tuple[str, ...] = (
    "Storage_GB",
    "Object_Count",
    "Estimated_Cost_USD",
    "Potential_Saving_USD",
)


@dataclass(frozen=True)
class SanityIssue:
    """One sanity issue detected in the CSV."""
    issue_type: str
    row_number: int
    resource_id: str
    column: str
    value: str
    message: str


def _as_float(raw: str) -> Optional[float]:
    """Parse raw value to float, returning None if empty."""
    if raw is None:
        return None
    txt = str(raw).strip()
    if txt == "":
        return None
    try:
        val = float(txt)
    except (TypeError, ValueError):
        return None
    if not math.isfinite(val):
        return None
    return val


def _iter_rows(reader: csv.reader) -> Iterator[Tuple[int, List[str]]]:
    """Yield (1-based row_number, row_values) for data rows."""
    # Header is row 1
    for idx, row in enumerate(reader, start=2):
        yield idx, row


def _dedupe_tuple(
    dedupe_key: str,
    row: Dict[str, str],
) -> Tuple[str, ...]:
    rid = row.get("Resource_ID", "") or ""
    if dedupe_key == "resource_id_type_region":
        return (
            rid,
            row.get("ResourceType", "") or "",
            row.get("Region", "") or "",
        )
    return (rid,)


def _write_report(report_path: str, issues: Sequence[SanityIssue]) -> None:
    os.makedirs(os.path.dirname(report_path) or ".", exist_ok=True)
    with open(report_path, "w", newline="", encoding="utf-8") as fp:
        w = csv.writer(fp)
        w.writerow(["IssueType", "RowNumber", "Resource_ID", "Column", "Value", "Message"])
        for it in issues:
            w.writerow([it.issue_type, it.row_number, it.resource_id, it.column, it.value, it.message])


def _validate_header(
    header: Sequence[str],
) -> List[SanityIssue]:
    issues: List[SanityIssue] = []
    header_set = set(h.strip() for h in header if h is not None)
    missing = [c for c in _REQUIRED_COLUMNS if c not in header_set]
    extra = [c for c in header if c and c not in _REQUIRED_COLUMNS]

    if missing:
        issues.append(
            SanityIssue(
                issue_type="MissingColumns",
                row_number=1,
                resource_id="",
                column=";".join(missing),
                value="",
                message="Required columns missing from CSV header.",
            )
        )
    # Extra columns aren't an error, but they could signal schema drift
    if extra:
        issues.append(
            SanityIssue(
                issue_type="ExtraColumns",
                row_number=1,
                resource_id="",
                column=";".join(extra),
                value="",
                message="CSV header contains unexpected columns (schema drift).",
            )
        )
    return issues


def _validate_row(
    row_number: int,
    row: Dict[str, str],
) -> List[SanityIssue]:
    issues: List[SanityIssue] = []
    rid = (row.get("Resource_ID") or "").strip()

    if rid == "":
        issues.append(
            SanityIssue(
                issue_type="EmptyResourceId",
                row_number=row_number,
                resource_id="",
                column="Resource_ID",
                value="",
                message="Resource_ID is empty.",
            )
        )

    # Numeric sanity
    parsed: Dict[str, Optional[float]] = {}
    for col in _NUMERIC_COLUMNS:
        raw = (row.get(col) or "").strip()
        if raw == "":
            parsed[col] = None
            continue
        val = _as_float(raw)
        if val is None:
            issues.append(
                SanityIssue(
                    issue_type="InvalidNumber",
                    row_number=row_number,
                    resource_id=rid,
                    column=col,
                    value=raw,
                    message="Numeric field is not a finite float.",
                )
            )
            parsed[col] = None
        else:
            parsed[col] = val

    for col in _NON_NEGATIVE_COLUMNS:
        val = parsed.get(col)
        if val is not None and val < 0:
            issues.append(
                SanityIssue(
                    issue_type="NegativeValue",
                    row_number=row_number,
                    resource_id=rid,
                    column=col,
                    value=str(val),
                    message="Negative value not allowed for this column.",
                )
            )

    # Savings cannot exceed estimated cost (when both present and cost > 0)
    est = parsed.get("Estimated_Cost_USD")
    sav = parsed.get("Potential_Saving_USD")
    if est is not None and sav is not None:
        # Only enforce if both are non-negative and cost is meaningful
        if est >= 0 and sav >= 0 and sav > est:
            issues.append(
                SanityIssue(
                    issue_type="SavingGreaterThanCost",
                    row_number=row_number,
                    resource_id=rid,
                    column="Potential_Saving_USD",
                    value=f"{sav} > {est}",
                    message="Potential saving exceeds estimated cost.",
                )
            )

    return issues


def check_csv_sanity(  # pylint: disable=unused-argument
    region: str,
    *,
    csv_path: str,
    report_path: Optional[str] = None,
    strict: bool = False,
    dedupe_key: str = "resource_id",
    logger: Optional[logging.Logger] = None,
    **_kwargs,
) -> None:
    """Validate a produced CSV report for schema/type/consistency issues.

    Args:
        region: Orchestrator region (ignored; present for signature contract).
        csv_path: Path to the main output CSV (must exist).
        report_path: Where to write the sanity report CSV (defaults to
            "<csv_path>.sanity.csv").
        strict: If True, raise RuntimeError when any issues are found.
        dedupe_key: "resource_id" or "resource_id_type_region".
        logger: Optional logger.
    """
    log = _logger(logger)

    if dedupe_key not in ("resource_id", "resource_id_type_region"):
        raise ValueError("dedupe_key must be 'resource_id' or 'resource_id_type_region'")

    if not csv_path or not os.path.exists(csv_path):
        raise FileNotFoundError(f"csv_path not found: {csv_path}")

    rep_path = report_path or f"{csv_path}.sanity.csv"
    issues: List[SanityIssue] = []
    seen: Set[Tuple[str, ...]] = set()

    with open(csv_path, "r", newline="", encoding="utf-8") as fp:
        reader = csv.reader(fp)
        try:
            header = next(reader)
        except StopIteration:
            issues.append(
                SanityIssue(
                    issue_type="EmptyFile",
                    row_number=1,
                    resource_id="",
                    column="",
                    value="",
                    message="CSV file is empty.",
                )
            )
            _write_report(rep_path, issues)
            if strict:
                raise RuntimeError("CSV sanity check failed: empty file")
            log.warning("[csv_sanity] CSV file empty: %s", csv_path)
            return

        issues.extend(_validate_header(header))
        # Build mapping from required header names to column index
        col_index: Dict[str, int] = {h: i for i, h in enumerate(header) if h}

        # Validate row length and content
        expected_len = len(header)
        for row_number, row_vals in _iter_rows(reader):
            if len(row_vals) != expected_len:
                issues.append(
                    SanityIssue(
                        issue_type="RowLengthMismatch",
                        row_number=row_number,
                        resource_id="",
                        column="",
                        value=str(len(row_vals)),
                        message=f"Row has {len(row_vals)} columns, expected {expected_len}.",
                    )
                )
                # try best-effort align by padding/truncating
                if len(row_vals) < expected_len:
                    row_vals = row_vals + [""] * (expected_len - len(row_vals))
                else:
                    row_vals = row_vals[:expected_len]

            row_dict: Dict[str, str] = {}
            for col, idx in col_index.items():
                if idx < len(row_vals):
                    row_dict[col] = row_vals[idx]
                else:
                    row_dict[col] = ""

            # Required keys presence (row-level)
            for req in _REQUIRED_COLUMNS:
                if req not in row_dict:
                    issues.append(
                        SanityIssue(
                            issue_type="MissingColumnInRow",
                            row_number=row_number,
                            resource_id=(row_dict.get("Resource_ID") or "").strip(),
                            column=req,
                            value="",
                            message="Row missing required column value (header mismatch).",
                        )
                    )

            # Content checks
            issues.extend(_validate_row(row_number, row_dict))

            # Dedupe checks
            key = _dedupe_tuple(dedupe_key, row_dict)
            # Only check if resource id not empty, to reduce noise
            if key and key[0].strip():
                if key in seen:
                    issues.append(
                        SanityIssue(
                            issue_type="DuplicateResourceKey",
                            row_number=row_number,
                            resource_id=key[0],
                            column="Resource_ID",
                            value=";".join(key),
                            message=f"Duplicate key detected ({dedupe_key}).",
                        )
                    )
                else:
                    seen.add(key)

    _write_report(rep_path, issues)

    if issues:
        log.warning(
            "[csv_sanity] Found %d issue(s). Report: %s",
            len(issues),
            rep_path,
        )
        if strict:
            raise RuntimeError(f"CSV sanity check failed with {len(issues)} issue(s).")
    else:
        log.info("[csv_sanity] No issues found. CSV looks sane: %s", csv_path)
