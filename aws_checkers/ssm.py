"""Checkers: AWS Systems Manager (SSM).

Provides three SSM checks:
  - check_ssm_plaintext_parameters: flags non-SecureString parameters.
  - check_ssm_stale_parameters: flags parameters not modified in N days.
  - check_ssm_maintenance_windows_gaps: flags Maintenance Windows with no targets
    and/or no tasks (merged to avoid redundant enumeration).

Design:
  - Dependencies (account_id, write_row, get_price, logger) are injected once via
    finops_toolset.checkers.config.setup(...).
  - Each checker signature is (writer, ssm, logger=None, **_kwargs) so it can be
    called directly by run_check(writer=..., ssm=...).
  - No return values (legacy).
  - Retries handled by @retry_with_backoff on ClientError.
  - Logging uses lazy %s interpolation for pylint compliance.
  - Time handling is timezone-aware (datetime.now(timezone.utc)).
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone, timedelta
from typing import List, Optional

from botocore.exceptions import ClientError

from core.retry import retry_with_backoff
from aws_checkers import config


def _require_config() -> None:
    """Ensure checkers.config.setup(...) has been called."""
    if not (config.ACCOUNT_ID and config.WRITE_ROW and config.GET_PRICE):
        raise RuntimeError(
            "Checkers not configured. Call "
            "finops_toolset.checkers.config.setup(account_id=..., write_row=..., "
            "get_price=..., logger=...) first."
        )


def _logger(fallback: Optional[logging.Logger]) -> logging.Logger:
    """Return an appropriate logger."""
    return fallback or config.LOGGER or logging.getLogger(__name__)


def _to_utc(dt_obj: datetime) -> datetime:
    """Return a timezone-aware UTC datetime for comparison."""
    if dt_obj.tzinfo is None:
        return dt_obj.replace(tzinfo=timezone.utc)
    return dt_obj.astimezone(timezone.utc)


@retry_with_backoff(exceptions=(ClientError,))
def check_ssm_plaintext_parameters(  # pylint: disable=unused-argument
    writer,
    ssm,
    logger: Optional[logging.Logger] = None,
    **_kwargs,
) -> None:
    """
    Flag SSM parameters that are NOT SecureString (plaintext).

    Writes: one row per plaintext parameter with flag 'SSMParameterPlaintext'.
    """
    _require_config()
    log = _logger(logger)

    try:
        paginator = ssm.get_paginator("describe_parameters")
        for page in paginator.paginate():
            for param in page.get("Parameters", []):
                name = param.get("Name") or ""
                ptype = param.get("Type")
                tier = param.get("Tier")

                if ptype != "SecureString":
                    # type: ignore[call-arg] because WRITE_ROW is injected at runtime
                    config.WRITE_ROW(
                        writer=writer,
                        resource_id=name,
                        name=name,
                        owner_id=config.ACCOUNT_ID,  # type: ignore[arg-type]
                        resource_type="SSMParameter",
                        estimated_cost=config.safe_price("SSMParameter", "PLAINTEXT_MONTH"),
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
def check_ssm_stale_parameters(  # pylint: disable=unused-argument
    writer,
    ssm,
    logger: Optional[logging.Logger] = None,
    *,
    stale_days: int = 365,
    **_kwargs,
) -> None:
    """
    Flag parameters not modified for `stale_days` (default 365).

    Writes: flag 'SSMParameterStaleXd' where X = stale_days.
    """
    _require_config()
    log = _logger(logger)

    cutoff = datetime.now(timezone.utc).replace(microsecond=0) - timedelta(days=stale_days)

    try:
        paginator = ssm.get_paginator("describe_parameters")
        for page in paginator.paginate():
            for param in page.get("Parameters", []):
                name = param.get("Name") or ""
                last_mod = param.get("LastModifiedDate")

                is_stale = False
                if isinstance(last_mod, datetime):
                    last_mod_utc = _to_utc(last_mod).replace(microsecond=0)
                    is_stale = last_mod_utc < cutoff

                if is_stale:
                    # type: ignore[call-arg]
                    config.WRITE_ROW(
                        writer=writer,
                        resource_id=name,
                        name=name,
                        owner_id=config.ACCOUNT_ID,  # type: ignore[arg-type]
                        resource_type="SSMParameter",
                        estimated_cost=config.safe_price("SSMParameter", "STALE_MONTH"),
                        flags=[f"SSMParameterStale{stale_days}d"],
                        confidence=100,
                    )

                log.info(
                    "[check_ssm_stale_parameters] Processed parameter: %s (last_modified=%s stale=%s)",
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
def check_ssm_maintenance_windows_gaps(  # pylint: disable=unused-argument
    writer,
    ssm,
    logger: Optional[logging.Logger] = None,
    *,
    consolidate_rows: bool = False,
    **_kwargs,
) -> None:
    """
    Flag enabled SSM Maintenance Windows that have no targets and/or no tasks.

    By default, writes one CSV row per missing aspect (targets, tasks) to preserve
    legacy output. Set `consolidate_rows=True` to emit a single row with both flags.
    """
    _require_config()
    log = _logger(logger)

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
                        est_cost += config.safe_price("SSMMaintenanceWindow", "NO_TARGETS_MONTH")
                    if missing_tasks:
                        flags.append("MaintenanceWindowNoTasks")
                        est_cost += config.safe_price("SSMMaintenanceWindow", "NO_TASKS_MONTH")

                    # type: ignore[call-arg]
                    config.WRITE_ROW(
                        writer=writer,
                        resource_id=window_id,
                        name=name,
                        owner_id=config.ACCOUNT_ID,  # type: ignore[arg-type]
                        resource_type="SSMMaintenanceWindow",
                        estimated_cost=est_cost,
                        flags=flags,
                        confidence=100,
                    )
                else:
                    if missing_targets:
                        # type: ignore[call-arg]
                        config.WRITE_ROW(
                            writer=writer,
                            resource_id=window_id,
                            name=name,
                            owner_id=config.ACCOUNT_ID,  # type: ignore[arg-type]
                            resource_type="SSMMaintenanceWindow",
                            estimated_cost=config.safe_price("SSMMaintenanceWindow", "NO_TARGETS_MONTH"),
                            flags=["MaintenanceWindowNoTargets"],
                            confidence=100,
                        )
                    if missing_tasks:
                        # type: ignore[call-arg]
                        config.WRITE_ROW(
                            writer=writer,
                            resource_id=window_id,
                            name=name,
                            owner_id=config.ACCOUNT_ID,  # type: ignore[arg-type]
                            resource_type="SSMMaintenanceWindow",
                            estimated_cost=config.safe_price("SSMMaintenanceWindow", "NO_TASKS_MONTH"),
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
