"""Checkers: AWS Backup.

Includes three checks:
  - check_backup_plans_without_selections: plans that back up nothing.
  - check_backup_rules_no_lifecycle: rules missing cold-storage or delete lifecycle.
  - check_backup_stale_recovery_points: old recovery points likely ready to prune.

Design:
  - Dependencies (account_id, write_row, get_price, logger) are injected once via
    finops_toolset.checkers.config.setup(...).
  - Each checker signature tolerates run_check calling style and will skip
    gracefully if a required client or config is missing.
  - Emits Flags, Signals (compact k=v pairs), Estimated_Cost_USD, Potential_Saving_USD.
  - Time handling is timezone-aware (datetime.now(timezone.utc)).
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Iterable, Optional, Tuple, Callable

from botocore.exceptions import ClientError

from aws_checkers import config
from aws_checkers.common import (
    _logger,
    _signals_str,
    _to_utc_iso,
)
from core.retry import retry_with_backoff


# ----------------------------- shared helpers ---------------------------- #


def _have_config() -> bool:
    return bool(config.ACCOUNT_ID and config.WRITE_ROW and config.GET_PRICE)


def _extract_writer_backup(args: Tuple[Any, ...], kwargs: Dict[str, Any]) -> Tuple[Any, Any]:
    """Accept writer/backup passed positionally or by keyword; prefer keywords."""
    writer = kwargs.get("writer", args[0] if len(args) >= 1 else None)
    backup = kwargs.get("backup", args[1] if len(args) >= 2 else None)
    if writer is None or backup is None:
        raise TypeError(
            "Expected 'writer' and 'backup' (got writer=%r, backup=%r)" % (writer, backup)
        )
    return writer, backup


# ---- robust wrapper for list_recovery_points_by_vault (handles env diffs/mocks) ---- #

def _iter_recovery_points_by_vault(
    backup,
    vault_name: str,
    log: logging.Logger,
) -> Iterable[Dict[str, Any]]:
    """
    Yield recovery points in a vault using the best-available method name.

    Tries, in order:
      - backup.list_recovery_points_by_vault
      - backup.list_recovery_points_by_backup_vault   (fallback seen in some stubs)

    If neither exists, logs a warning and yields nothing.
    """
    method: Optional[Callable[..., Dict[str, Any]]] = getattr(backup, "list_recovery_points_by_vault", None)
    if method is None:
        method = getattr(backup, "list_recovery_points_by_backup_vault", None)

    if method is None:
        log.warning(
            "[backup] client has no 'list_recovery_points_by_vault' method; skipping vault %s",
            vault_name,
        )
        return  # nothing to iterate

    next_token: Optional[str] = None
    while True:
        try:
            params = {"BackupVaultName": vault_name}
            if next_token:
                params["NextToken"] = next_token
            resp = method(**params)
        except ClientError as exc:
            log.debug("[backup] list_recovery_points_by_vault failed for %s: %s", vault_name, exc)
            return

        for rp in resp.get("RecoveryPoints", []) or []:
            yield rp

        next_token = resp.get("NextToken")
        if not next_token:
            break


# ----------------------------- 1) plans without selections ---------------- #

@retry_with_backoff(exceptions=(ClientError,))
def check_backup_plans_without_selections(  # pylint: disable=unused-argument
    *args,
    logger: Optional[logging.Logger] = None,
    **kwargs,
) -> None:
    """
    Flag Backup Plans that have zero resource selections (i.e., they back up nothing).

    Flags:
      - BackupPlanNoSelections

    Notes:
      - Plans themselves don't incur storage cost; we keep `estimated_cost=0.0`
        and `potential_saving=0.0`. The value is in surfacing misconfigurations.
    """
    log = _logger(kwargs.get("logger") or logger)

    # tolerate missing config/clients in tests
    try:
        writer, backup = _extract_writer_backup(args, kwargs)
    except TypeError as exc:
        log.warning("[check_backup_plans_without_selections] Skipping: %s", exc)
        return
    if not _have_config():
        log.warning("[check_backup_plans_without_selections] Skipping: checker config not provided.")
        return

    region = getattr(getattr(backup, "meta", None), "region_name", "") or ""

    try:
        list_plans = backup.list_backup_plans
        next_token: Optional[str] = None

        while True:
            resp = list_plans(NextToken=next_token) if next_token else list_plans()
            for bp in resp.get("BackupPlansList", []) or []:
                plan_id = bp.get("BackupPlanId")
                plan_name = bp.get("BackupPlanName") or plan_id
                if not plan_id:
                    continue

                # selections
                sels_resp = backup.list_backup_selections(BackupPlanId=plan_id)
                selections = sels_resp.get("BackupSelectionsList", []) or []
                if not selections:
                    # type: ignore[call-arg]
                    config.WRITE_ROW(
                        writer=writer,
                        resource_id=plan_id,
                        name=plan_name or "",
                        owner_id=config.ACCOUNT_ID,  # type: ignore[arg-type]
                        resource_type="AWSBackupPlan",
                        estimated_cost=0.0,
                        potential_saving=0.0,
                        flags=["BackupPlanNoSelections"],
                        confidence=100,
                        signals=_signals_str({"Region": region, "PlanName": plan_name}),
                    )

                log.info(
                    "[check_backup_plans_without_selections] Processed plan: %s (selections=%d)",
                    plan_id,
                    len(selections),
                )

            next_token = resp.get("NextToken")
            if not next_token:
                break

    except ClientError as exc:
        log.error("Error checking backup plans without selections: %s", exc)
        raise


# ----------------------------- 2) rules missing lifecycle ---------------- #

@retry_with_backoff(exceptions=(ClientError,))
def check_backup_rules_no_lifecycle(  # pylint: disable=unused-argument
    *args,
    logger: Optional[logging.Logger] = None,
    **kwargs,
) -> None:
    """
    Flag Backup Rules that do not define a lifecycle (neither cold-storage move nor delete).

    Flags:
      - BackupRuleNoLifecycle

    Notes:
      - This check surfaces possible retention oversights; we don't attempt to price it.
    """
    log = _logger(kwargs.get("logger") or logger)

    try:
        writer, backup = _extract_writer_backup(args, kwargs)
    except TypeError as exc:
        log.warning("[check_backup_rules_no_lifecycle] Skipping: %s", exc)
        return
    if not _have_config():
        log.warning("[check_backup_rules_no_lifecycle] Skipping: checker config not provided.")
        return

    region = getattr(getattr(backup, "meta", None), "region_name", "") or ""

    try:
        next_token: Optional[str] = None
        while True:
            resp = backup.list_backup_plans(NextToken=next_token) if next_token else backup.list_backup_plans()
            for summary in resp.get("BackupPlansList", []) or []:
                plan_id = summary.get("BackupPlanId")
                if not plan_id:
                    continue

                plan_name = summary.get("BackupPlanName") or plan_id
                plan_detail = backup.get_backup_plan(BackupPlanId=plan_id).get("BackupPlan", {}) or {}
                rules = plan_detail.get("Rules", []) or []

                for rule in rules:
                    rule_name = rule.get("RuleName") or ""
                    lifecycle = rule.get("Lifecycle") or {}
                    move_days = lifecycle.get("MoveToColdStorageAfterDays")
                    delete_days = lifecycle.get("DeleteAfterDays")

                    if move_days in (None, 0) and delete_days in (None, 0):
                        # type: ignore[call-arg]
                        config.WRITE_ROW(
                            writer=writer,
                            resource_id=f"{plan_id}:{rule_name}",
                            name=f"{plan_name}:{rule_name}",
                            owner_id=config.ACCOUNT_ID,  # type: ignore[arg-type]
                            resource_type="AWSBackupRule",
                            estimated_cost=0.0,
                            potential_saving=0.0,
                            flags=["BackupRuleNoLifecycle"],
                            confidence=100,
                            signals=_signals_str(
                                {
                                    "Region": region,
                                    "PlanName": plan_name,
                                    "RuleName": rule_name,
                                    "MoveToColdDays": move_days,
                                    "DeleteAfterDays": delete_days,
                                }
                            ),
                        )

                    log.info(
                        "[check_backup_rules_no_lifecycle] Processed rule: %s (move=%s delete=%s)",
                        rule_name,
                        move_days,
                        delete_days,
                    )

            next_token = resp.get("NextToken")
            if not next_token:
                break

    except ClientError as exc:
        log.error("Error checking backup rules lifecycle: %s", exc)
        raise


# ----------------------------- 3) stale recovery points ------------------ #

@retry_with_backoff(exceptions=(ClientError,))
def check_backup_stale_recovery_points(  # pylint: disable=unused-argument
    *args,
    logger: Optional[logging.Logger] = None,
    stale_days: int = 90,
    **kwargs,
) -> None:
    """
    Flag recovery points older than `stale_days` that are still retained.

    Flags:
      - BackupRecoveryPointStale

    Estimated_Cost_USD and Potential_Saving_USD:
      - Uses BackupSizeInBytes and pricebook keys:
          AWSBackup/BACKUP_WARM_GB_MONTH (StorageClass=WARM)
          AWSBackup/BACKUP_COLD_GB_MONTH (StorageClass=COLD)
        Falls back to 0.0 if keys are missing.
      - potential_saving = estimated_cost for each stale RP (heuristic).
    """
    log = _logger(kwargs.get("logger") or logger)

    try:
        writer, backup = _extract_writer_backup(args, kwargs)
    except TypeError as exc:
        log.warning("[check_backup_stale_recovery_points] Skipping: %s", exc)
        return
    if not _have_config():
        log.warning("[check_backup_stale_recovery_points] Skipping: checker config not provided.")
        return

    region = getattr(getattr(backup, "meta", None), "region_name", "") or ""
    cutoff = (datetime.now(timezone.utc) - timedelta(days=stale_days)).replace(microsecond=0)

    price_warm = config.safe_price("AWSBackup", "BACKUP_WARM_GB_MONTH", default=0.0)
    price_cold = config.safe_price("AWSBackup", "BACKUP_COLD_GB_MONTH", default=0.0)

    try:
        # enumerate vaults
        next_token_v: Optional[str] = None
        while True:
            v_resp = backup.list_backup_vaults(NextToken=next_token_v) if next_token_v else backup.list_backup_vaults()
            for vault in v_resp.get("BackupVaultList", []) or []:
                vault_name = vault.get("BackupVaultName")
                if not vault_name:
                    continue

                # enumerate recovery points (robust method resolution)
                for rp in _iter_recovery_points_by_vault(backup, vault_name, log):
                    arn = rp.get("RecoveryPointArn")
                    created = rp.get("CreationDate")  # datetime
                    status = rp.get("Status")
                    sc = (rp.get("StorageClass") or "").upper()
                    size_bytes = float(rp.get("BackupSizeInBytes") or 0)
                    resource_type = rp.get("ResourceType") or ""
                    resource_arn = rp.get("ResourceArn") or ""
                    calc_lc = rp.get("CalculatedLifecycle") or {}
                    delete_at = calc_lc.get("DeleteAt")

                    if not isinstance(created, datetime) or not arn:
                        continue
                    created_utc = created if created.tzinfo else created.replace(tzinfo=timezone.utc)

                    # stale if older than cutoff and still present (not EXPIRED/DELETED)
                    if created_utc >= cutoff or status in {"EXPIRED", "DELETED"}:
                        continue

                    gb = size_bytes / (1024 ** 3) if size_bytes > 0 else 0.0
                    est_cost = gb * (price_cold if sc == "COLD" else price_warm)
                    potential_saving = est_cost  # heuristic: drop this old RP

                    # type: ignore[call-arg]
                    config.WRITE_ROW(
                        writer=writer,
                        resource_id=arn,
                        name=vault_name,
                        owner_id=config.ACCOUNT_ID,  # type: ignore[arg-type]
                        resource_type="AWSBackupRecoveryPoint",
                        estimated_cost=est_cost,
                        potential_saving=potential_saving,
                        flags=["BackupRecoveryPointStale"],
                        confidence=100,
                        signals=_signals_str(
                            {
                                "Region": region,
                                "Vault": vault_name,
                                "ResourceType": resource_type,
                                "ResourceArn": resource_arn,
                                "StorageClass": sc,
                                "SizeGB": round(gb, 3),
                                "CreatedAt": _to_utc_iso(created),
                                "DeleteAt": _to_utc_iso(delete_at) if isinstance(delete_at, datetime) else None,
                                "Status": status,
                                "StaleDays": stale_days,
                            }
                        ),
                    )

                    log.info(
                        "[Backup Stale] Wrote RP: %s (vault=%s sizeGB=%.3f sc=%s)",
                        arn,
                        vault_name,
                        gb,
                        sc,
                    )

            next_token_v = v_resp.get("NextToken")
            if not next_token_v:
                break

    except ClientError as exc:
        log.error("Error checking backup recovery points: %s", exc)
        raise
