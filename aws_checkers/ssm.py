"""Checkers: AWS Systems Manager (SSM).

This module provides:
  - check_ssm_plaintext_parameters: flags non-SecureString parameters.
  - check_ssm_stale_parameters: flags parameters not modified in N days.
  - check_ssm_maintenance_windows_gaps: flags Maintenance Windows with no targets
    and/or no tasks (merged into one pass to avoid redundant API calls).
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone as _tz, timedelta as _td
from typing import Callable, List, Optional
import csv

from botocore.exceptions import ClientError
from core.retry import retry_with_backoff


WriteRow = Callable[..., None]
GetPrice = Callable[[str, str], float]


def _safe_price(get_price_fn: GetPrice, service: str, key: str) -> float:
    """Fetch a price; fall back to 0.0 if key is missing/invalid."""
    try:
        return float(get_price_fn(service, key))
    except Exception:  # pylint: disable=broad-except
        return 0.0


def _to_utc(dt_obj: datetime) -> datetime:
    """Return a timezone-aware UTC datetime for comparison."""
    if dt_obj.tzinfo is None:
        return dt_obj.replace(tzinfo=_tz.utc)
    return dt_obj.astimezone(_tz.utc)


@retry_with_backoff(exceptions=(ClientError,))
def check_ssm_plaintext_parameters(
    ssm,
    account_id: str,
    write_row: WriteRow,
    writer: csv.writer,
    get_price_fn: GetPrice,
    logger: Optional[logging.Logger] = None,
) -> None:
    """
    Flag SSM parameters that are NOT SecureString (plaintext).

    Writes: one row per plaintext parameter with flag 'SSMParameterPlaintext'.
    """
    log = logger or logging.getLogger(__name__)
    try:
        paginator = ssm.get_paginator("describe_parameters")
        for page in paginator.paginate():
            for param in page.get("Parameters", []):
                name = param.get("Name")
                ptype = param.get("Type")
                tier = param.get("Tier")

                if ptype != "SecureString":
                    write_row(
                        writer=writer,
                        resource_id=name,
                        name=name or "",
                        owner_id=account_id,
                        resource_type="SSMParameter",
                        estimated_cost=_safe_price(get_price_fn, "SSMParameter", "PLAINTEXT_MONTH"),
                        flags=["SSMParameterPlaintext"],
                        confidence=100,
                    )

                log.info(
                    "[check_ssm_plaintext_parameters] Processed parameter: %s (type=%s tier=%s)",
                    name,
                    ptype,
                    tier,
                )
    except ClientError as exc:
        log.error("Error checking SSM plaintext parameters: %s", exc)
        raise


@retry_with_backoff(exceptions=(ClientError,))
def check_ssm_stale_parameters(
    ssm,
    account_id: str,
    write_row: WriteRow,
    writer: csv.writer,
    get_price_fn: GetPrice,
    logger: Optional[logging.Logger] = None,
    stale_days: int = 365,
) -> None:
    """
    Flag parameters not modified for `stale_days` (default 365).

    Writes: flag 'SSMParameterStaleXd' where X = stale_days.
    """
    log = logger or logging.getLogger(__name__)

    try:

        cutoff_local = datetime.now(_tz.utc).replace(microsecond=0) - _td(days=stale_days)

        paginator = ssm.get_paginator("describe_parameters")
        for page in paginator.paginate():
            for param in page.get("Parameters", []):
                name = param.get("Name")
                last_mod = param.get("LastModifiedDate")
                is_stale = False

                if isinstance(last_mod, datetime):
                    last_mod_utc = _to_utc(last_mod).replace(microsecond=0)
                    is_stale = last_mod_utc < cutoff_local

                if is_stale:
                    write_row(
                        writer=writer,
                        resource_id=name,
                        name=name or "",
                        owner_id=account_id,
                        resource_type="SSMParameter",
                        estimated_cost=_safe_price(get_price_fn, "SSMParameter", "STALE_MONTH"),
                        flags=[f"SSMParameterStale{stale_days}d"],
                        confidence=100,
                    )

                log.info(
                    "[check_ssm_stale_parameters] Processed param : %s (last_modified=%s stale=%s)",
                    name,
                    last_mod,
                    is_stale,
                )
    except ClientError as exc:
        log.error("Error checking SSM stale parameters: %s", exc)
        raise


def _list_all_window_targets(ssm, window_id: str) -> List[dict]:
    """Return all targets for a Maintenance Window (handles pagination)."""
    items: List[dict] = []
    paginator = ssm.get_paginator("describe_maintenance_window_targets")
    for page in paginator.paginate(WindowId=window_id):
        items.extend(page.get("Targets", []))
    return items


def _list_all_window_tasks(ssm, window_id: str) -> List[dict]:
    """Return all tasks for a Maintenance Window (handles pagination)."""
    items: List[dict] = []
    paginator = ssm.get_paginator("describe_maintenance_window_tasks")
    for page in paginator.paginate(WindowId=window_id):
        items.extend(page.get("Tasks", []))
    return items


@retry_with_backoff(exceptions=(ClientError,))
def check_ssm_maintenance_windows_gaps(
    ssm,
    account_id: str,
    write_row: WriteRow,
    writer: csv.writer,
    get_price_fn: GetPrice,
    logger: Optional[logging.Logger] = None,
    consolidate_rows: bool = False,
) -> None:
    """
    Flag enabled SSM Maintenance Windows that have no targets and/or no tasks.

    By default, writes one CSV row per missing aspect (targets, tasks) to preserve
    legacy output. Set `consolidate_rows=True` to emit a single row with both flags.
    """
    log = logger or logging.getLogger(__name__)
    try:
        mw_paginator = ssm.get_paginator("describe_maintenance_windows")
        for page in mw_paginator.paginate():
            for mw in page.get("WindowIdentities", []):
                window_id = mw.get("WindowId")
                name = mw.get("Name", "")
                enabled = mw.get("Enabled", False)

                if not enabled:
                    log.info(
                        "[check_ssm_maintenance_windows_gaps] Skipping disabled MW: %s",
                        window_id,
                    )
                    continue

                targets = _list_all_window_targets(ssm, window_id)
                tasks = _list_all_window_tasks(ssm, window_id)

                missing_targets = not targets
                missing_tasks = not tasks

                if not (missing_targets or missing_tasks):
                    log.info(
                        "[check_ssm_maintenance_windows_gaps] OK MW: %s (targets=%d tasks=%d)",
                        window_id,
                        len(targets),
                        len(tasks),
                    )
                    continue

                if consolidate_rows:
                    flags: List[str] = []
                    est_cost = 0.0
                    if missing_targets:
                        flags.append("MaintenanceWindowNoTargets")
                        est_cost += _safe_price(
                            get_price_fn, "SSMMaintenanceWindow", "NO_TARGETS_MONTH"
                        )
                    if missing_tasks:
                        flags.append("MaintenanceWindowNoTasks")
                        est_cost += _safe_price(
                            get_price_fn, "SSMMaintenanceWindow", "NO_TASKS_MONTH"
                        )

                    write_row(
                        writer=writer,
                        resource_id=window_id,
                        name=name,
                        owner_id=account_id,
                        resource_type="SSMMaintenanceWindow",
                        estimated_cost=est_cost,
                        flags=flags,
                        confidence=100,
                    )
                else:
                    if missing_targets:
                        write_row(
                            writer=writer,
                            resource_id=window_id,
                            name=name,
                            owner_id=account_id,
                            resource_type="SSMMaintenanceWindow",
                            estimated_cost=_safe_price(
                                get_price_fn, "SSMMaintenanceWindow", "NO_TARGETS_MONTH"
                            ),
                            flags=["MaintenanceWindowNoTargets"],
                            confidence=100,
                        )
                    if missing_tasks:
                        write_row(
                            writer=writer,
                            resource_id=window_id,
                            name=name,
                            owner_id=account_id,
                            resource_type="SSMMaintenanceWindow",
                            estimated_cost=_safe_price(
                                get_price_fn, "SSMMaintenanceWindow", "NO_TASKS_MONTH"
                            ),
                            flags=["MaintenanceWindowNoTasks"],
                            confidence=100,
                        )

                log.info(
                    "[check_ssm_maintenance_windows_gaps] Processed MW: %s (targets=%d tasks=%d)",
                    window_id,
                    len(targets),
                    len(tasks),
                )
    except ClientError as exc:
        log.error("Error checking SSM maintenance windows: %s", exc)
        raise
