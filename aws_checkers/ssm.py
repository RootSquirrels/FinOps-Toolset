"""Checkers: AWS Systems Manager (SSM).

Global checker (preferred):
  - check_ssm_resources

Legacy wrappers (backward compatible):
  - check_ssm_plaintext_parameters
  - check_ssm_stale_parameters
  - check_ssm_maintenance_windows_gaps

This module is production-oriented:
- single enumeration of parameters (no duplicate API cost)
- merged flags per resource (no duplicate CSV rows)
- structured signals (dict) to support CSV sanity validation
- run guard to avoid duplicate execution if wrappers are invoked.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone, timedelta
from threading import Lock
from typing import Any, Dict, List, Optional, Set, Tuple

from botocore.exceptions import ClientError

from core.retry import retry_with_backoff
from aws_checkers import config
from aws_checkers.common import _logger


# ------------------------------- config ---------------------------------- #

def _require_config() -> None:
    """Ensure checkers.config.setup(...) has been called."""
    if not (config.ACCOUNT_ID and config.WRITE_ROW):
        raise RuntimeError(
            "Checkers not configured. Call config.setup(account_id=..., write_row=..., "
            "get_price=..., logger=...) first."
        )


def _to_utc(dt_obj: datetime) -> datetime:
    """Return a timezone-aware UTC datetime for comparison."""
    if dt_obj.tzinfo is None:
        return dt_obj.replace(tzinfo=timezone.utc)
    return dt_obj.astimezone(timezone.utc)


def _extract_writer_ssm(
    args: Tuple[Any, ...],
    kwargs: Dict[str, Any],
) -> Tuple[Any, Any]:
    """
    Extract (writer, ssm) in a run_check-compatible way.

    Supports:
      - fn(writer, ssm, ...)
      - fn(region, writer, ssm, ...)  (orchestrators that inject region positionally)
      - fn(..., writer=..., ssm=...)
    """
    writer = kwargs.get("writer")
    ssm = kwargs.get("ssm")

    # Positional fallback:
    # common patterns:
    #   (writer, ssm, ...)
    #   (region, writer, ssm, ...)
    if writer is None or ssm is None:
        if len(args) >= 2:
            # assume (writer, ssm, ...)
            writer = writer or args[0]
            ssm = ssm or args[1]
        elif len(args) >= 3:
            # assume (region, writer, ssm, ...)
            writer = writer or args[1]
            ssm = ssm or args[2]

    if writer is None or ssm is None:
        raise TypeError(
            "Expected 'writer' and 'ssm' (got writer=%r, ssm=%r)" % (writer, ssm)
        )
    return writer, ssm


# -------------------------- dedupe / merge helpers ------------------------ #

def _dedupe_key(row: Dict[str, Any]) -> Tuple[str, str, str, str]:
    return (
        str(row.get("resource_id") or ""),
        str(row.get("resource_type") or ""),
        str(row.get("region") or ""),
        str(row.get("owner_id") or ""),
    )


def _merge_flags(existing: List[str], incoming: List[str]) -> List[str]:
    if not incoming:
        return existing
    if not existing:
        return list(incoming)
    seen = set(existing)
    for f in incoming:
        if f and f not in seen:
            existing.append(f)
            seen.add(f)
    return existing


def _merge_signals(existing: Dict[str, Any], incoming: Dict[str, Any]) -> Dict[str, Any]:
    if not incoming:
        return existing
    if not existing:
        return dict(incoming)
    for k, v in incoming.items():
        if k not in existing:
            existing[k] = v
            continue
        cur = existing.get(k)
        if cur in (None, "", "NULL") and v not in (None, "", "NULL"):
            existing[k] = v
    return existing


def _max_float(a: Any, b: Any) -> float:
    try:
        fa = float(a)
    except Exception:  # pylint: disable=broad-except
        fa = 0.0
    try:
        fb = float(b)
    except Exception:  # pylint: disable=broad-except
        fb = 0.0
    return fa if fa >= fb else fb


def _collect_row(
    rows: Dict[Tuple[str, str, str, str], Dict[str, Any]],
    row: Dict[str, Any],
) -> None:
    """Collect/merge a finding row for unique output (one row per resource)."""
    key = _dedupe_key(row)
    existing = rows.get(key)
    if existing is None:
        row.setdefault("flags", [])
        row.setdefault("signals", {})
        row.setdefault("estimated_cost", 0.0)
        row.setdefault("potential_saving", 0.0)
        row.setdefault("confidence", 0)
        rows[key] = row
        return

    existing["flags"] = _merge_flags(
        list(existing.get("flags") or []), list(row.get("flags") or [])
    )
    existing["signals"] = _merge_signals(
        dict(existing.get("signals") or {}), dict(row.get("signals") or {})
    )
    existing["estimated_cost"] = _max_float(
        existing.get("estimated_cost"), row.get("estimated_cost")
    )
    existing["potential_saving"] = _max_float(
        existing.get("potential_saving"), row.get("potential_saving")
    )
    existing["confidence"] = int(
        max(int(existing.get("confidence") or 0), int(row.get("confidence") or 0))
    )

    # Fill any missing fields
    for k, v in row.items():
        if k in ("flags", "signals", "estimated_cost", "potential_saving", "confidence"):
            continue
        cur = existing.get(k)
        if cur in (None, "", "NULL") and v not in (None, "", "NULL"):
            existing[k] = v


# ----------------------- global run guard (per run) ------------------------ #

_ALREADY_RAN_LOCK = Lock()
_ALREADY_RAN: Set[Tuple[int, str]] = set()


def _writer_key(writer: Any) -> int:
    """Best-effort stable identity for the underlying output stream."""
    for attr in ("f", "fp", "stream", "file", "buffer", "raw"):
        stream = getattr(writer, attr, None)
        if stream is not None:
            return id(stream)
    inner = getattr(writer, "writer", None)
    if inner is not None:
        for attr in ("f", "fp", "stream", "file", "buffer", "raw"):
            stream = getattr(inner, attr, None)
            if stream is not None:
                return id(stream)
        return id(inner)
    return id(writer)


# -------------------------- inventories / listing -------------------------- #

def _list_parameters(ssm, log: logging.Logger) -> List[Dict[str, Any]]:
    items: List[Dict[str, Any]] = []
    paginator = ssm.get_paginator("describe_parameters")
    for page in paginator.paginate():
        items.extend(page.get("Parameters", []) or [])
    log.debug("[ssm] loaded %d parameters", len(items))
    return items


def _list_all_window_targets(ssm, window_id: str) -> List[dict]:
    items: List[dict] = []
    paginator = ssm.get_paginator("describe_maintenance_window_targets")
    for page in paginator.paginate(WindowId=window_id):
        items.extend(page.get("Targets", []) or [])
    return items


def _list_all_window_tasks(ssm, window_id: str) -> List[dict]:
    items: List[dict] = []
    paginator = ssm.get_paginator("describe_maintenance_window_tasks")
    for page in paginator.paginate(WindowId=window_id):
        items.extend(page.get("Tasks", []) or [])
    return items


# --------------------------------- checker -------------------------------- #

@retry_with_backoff(exceptions=(ClientError,))
def check_ssm_resources(  # pylint: disable=unused-argument
    *args: Any,
    logger: Optional[logging.Logger] = None,
    stale_days: int = 365,
    **kwargs: Any,
) -> None:
    """
    Global SSM checker (preferred).

    - Parameters:
        * plaintext (non SecureString)
        * stale (LastModifiedDate older than stale_days)
      -> single row per parameter with merged flags.

    - Maintenance windows:
        * enabled MW with no targets and/or no tasks
      -> single row per window with merged flags.
    """
    _require_config()
    log = _logger(kwargs.get("logger") or logger)

    writer, ssm = _extract_writer_ssm(args, kwargs)
    owner = str(config.ACCOUNT_ID or "")
    region = getattr(getattr(ssm, "meta", None), "region_name", "") or ""

    run_key = (_writer_key(writer), owner)
    with _ALREADY_RAN_LOCK:
        if run_key in _ALREADY_RAN:
            log.info("[ssm] Skipping duplicate run (owner=%s)", owner)
            return
        _ALREADY_RAN.add(run_key)

    cutoff = datetime.now(timezone.utc).replace(microsecond=0) - timedelta(days=int(stale_days))

    # Prices (best-effort)
    price_plain = float(config.safe_price("SSMParameter", "PLAINTEXT_MONTH", 0.0))
    price_stale = float(config.safe_price("SSMParameter", "STALE_MONTH", 0.0))
    price_mw_no_targets = float(config.safe_price("SSMMaintenanceWindow", "NO_TARGETS_MONTH", 0.0))
    price_mw_no_tasks = float(config.safe_price("SSMMaintenanceWindow", "NO_TASKS_MONTH", 0.0))

    rows: Dict[Tuple[str, str, str, str], Dict[str, Any]] = {}

    # ------------------------------ parameters ------------------------------ #

    try:
        params = _list_parameters(ssm, log)
    except ClientError as exc:
        log.error("[ssm] describe_parameters failed: %s", exc)
        raise

    plaintext_count = 0
    stale_count = 0

    for param in params:
        name = str(param.get("Name") or "")
        if not name:
            continue

        ptype = param.get("Type")
        tier = param.get("Tier")
        last_mod = param.get("LastModifiedDate")

        flags: List[str] = []
        est_cost = 0.0

        if ptype != "SecureString":
            flags.append("SSMParameterPlaintext")
            est_cost = max(est_cost, price_plain)
            plaintext_count += 1

        is_stale = False
        if isinstance(last_mod, datetime):
            last_mod_utc = _to_utc(last_mod).replace(microsecond=0)
            is_stale = last_mod_utc < cutoff

        if is_stale:
            flags.append(f"SSMParameterStale{int(stale_days)}d")
            est_cost = max(est_cost, price_stale)
            stale_count += 1

        if not flags:
            continue

        signals: Dict[str, Any] = {
            "Region": region,
            "Type": ptype,
            "Tier": tier,
            "LastModifiedDate": last_mod.isoformat() if isinstance(last_mod, datetime) else None,
            "StaleDaysThreshold": int(stale_days),
        }

        _collect_row(
            rows,
            {
                "resource_id": name,
                "name": name,
                "owner_id": owner,
                "resource_type": "SSMParameter",
                "region": region,
                "estimated_cost": est_cost,
                "potential_saving": 0.0,
                "flags": flags,
                "confidence": 100,
                "signals": signals,
            },
        )

    # -------------------------- maintenance windows ------------------------- #

    mw_flagged = 0
    try:
        mw_paginator = ssm.get_paginator("describe_maintenance_windows")
        for page in mw_paginator.paginate():
            for mw in page.get("WindowIdentities", []) or []:
                window_id = str(mw.get("WindowId") or "")
                if not window_id:
                    continue

                enabled = bool(mw.get("Enabled", False))
                if not enabled:
                    continue

                name = str(mw.get("Name") or window_id)

                targets = _list_all_window_targets(ssm, window_id)
                tasks = _list_all_window_tasks(ssm, window_id)

                missing_targets = not targets
                missing_tasks = not tasks
                if not (missing_targets or missing_tasks):
                    continue

                flags: List[str] = []
                est_cost = 0.0
                if missing_targets:
                    flags.append("MaintenanceWindowNoTargets")
                    est_cost = max(est_cost, price_mw_no_targets)
                if missing_tasks:
                    flags.append("MaintenanceWindowNoTasks")
                    est_cost = max(est_cost, price_mw_no_tasks)

                signals = {
                    "Region": region,
                    "Enabled": enabled,
                    "TargetsCount": len(targets),
                    "TasksCount": len(tasks),
                }

                _collect_row(
                    rows,
                    {
                        "resource_id": window_id,
                        "name": name,
                        "owner_id": owner,
                        "resource_type": "SSMMaintenanceWindow",
                        "region": region,
                        "estimated_cost": est_cost,
                        "potential_saving": 0.0,
                        "flags": flags,
                        "confidence": 100,
                        "signals": signals,
                    },
                )
                mw_flagged += 1

    except ClientError as exc:
        log.error("[ssm] Error checking maintenance windows: %s", exc)
        raise

    # -------------------------------- flush -------------------------------- #

    ordered = sorted(
        rows.values(),
        key=lambda r: (str(r.get("resource_type") or ""), str(r.get("resource_id") or "")),
    )

    wrote = 0
    for row in ordered:
        try:
            # type: ignore[call-arg]
            config.WRITE_ROW(writer=writer, **row)
            wrote += 1
        except Exception as exc:  # pylint: disable=broad-except
            log.warning("[ssm] failed to write %s: %s", row.get("resource_id"), exc)

    log.info(
        "[ssm] Completed check_ssm_resources (rows=%d plaintext=%d stale=%d mw_flagged=%d)",
        wrote,
        plaintext_count,
        stale_count,
        mw_flagged,
    )
