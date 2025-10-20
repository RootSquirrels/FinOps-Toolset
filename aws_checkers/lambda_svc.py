"""Checkers: AWS Lambda.

Included:

  - check_lambda_unused_functions
      No invocations in the lookback window.

  - check_lambda_provisioned_concurrency_underutilized
      PC configured but average utilization is low; estimate monthly PC cost.

  - check_lambda_runtime_deprecated
      Functions running a deprecated / EOL’ed runtime (heuristic map).

  - check_lambda_large_packages
      Functions with large deployment packages (zip size > threshold).

  - check_lambda_old_functions
      Functions not modified for a long time (stale code / hygiene).

Design:
  - Dependencies via finops_toolset.checkers.config.setup(...).
  - Tolerant signatures; no returns.
  - CloudWatch via finops_toolset.cloudwatch.CloudWatchBatcher where needed.
  - UTC datetimes, lazy %% logging, lines ≤ 100 chars.

Pricing keys used (safe defaults if absent):
  "Lambda": {
      "PC_GB_SEC": 0.0000041667,  # ~ $0.015 per GB-hour
  }
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple

from botocore.exceptions import ClientError

from aws_checkers import config
from aws_checkers.common import (
    _logger,
    _signals_str,
    _to_utc_iso,
)
from core.retry import retry_with_backoff
from core.cloudwatch import CloudWatchBatcher


# ------------------------------- helpers -------------------------------- #


def _sum_from_result(res: Any) -> float:
    """Reduce CloudWatchBatcher result → sum of values."""
    if res is None:
        return 0.0
    if isinstance(res, list) and res and isinstance(res[0], tuple):
        try:
            return float(sum(float(v) for _, v in res))
        except Exception:  # pylint: disable=broad-except
            return 0.0
    if isinstance(res, dict):
        values = res.get("Values") or res.get("values") or []
        try:
            return float(sum(values))
        except Exception:  # pylint: disable=broad-except
            return 0.0
    return 0.0


def _avg_from_result(res: Any) -> float:
    """Reduce CloudWatchBatcher result → average of values."""
    if res is None:
        return 0.0
    if isinstance(res, list) and res and isinstance(res[0], tuple):
        try:
            vals = [float(v) for _, v in res]
            return float(sum(vals) / len(vals)) if vals else 0.0
        except Exception:  # pylint: disable=broad-except
            return 0.0
    if isinstance(res, dict):
        values = res.get("Values") or res.get("values") or []
        try:
            return float(sum(values) / len(values)) if values else 0.0
        except Exception:  # pylint: disable=broad-except
            return 0.0
    return 0.0


def _extract_writer_lambda_cw(
    args: Tuple[Any, ...],
    kwargs: Dict[str, Any],
) -> Tuple[Any, Any, Any]:
    """Accept writer/lambda_client/cloudwatch passed positionally or by keyword."""
    writer = kwargs.get("writer", args[0] if len(args) >= 1 else None)
    lmbd = kwargs.get("lambda_client", args[1] if len(args) >= 2 else None)
    cloudwatch = kwargs.get("cloudwatch", args[2] if len(args) >= 3 else None)
    if writer is None or lmbd is None or cloudwatch is None:
        raise TypeError(
            "Expected 'writer', 'lambda_client', and 'cloudwatch' "
            f"(got writer={writer!r}, lambda_client={lmbd!r}, cloudwatch={cloudwatch!r})"
        )
    return writer, lmbd, cloudwatch


def _list_functions(lmbd, log: logging.Logger) -> List[Dict[str, Any]]:
    funcs: List[Dict[str, Any]] = []
    try:
        paginator = lmbd.get_paginator("list_functions")
        for page in paginator.paginate():
            funcs.extend(page.get("Functions", []) or [])
    except ClientError as exc:
        log.error("[lambda] list_functions failed: %s", exc)
    return funcs


def _parse_last_modified(s: Optional[str]) -> Optional[datetime]:
    if not s:
        return None
    # Examples: "2021-01-29T13:34:06.870+0000", "2020-05-05T22:20:13.123+0000"
    fmts = ("%Y-%m-%dT%H:%M:%S.%f%z", "%Y-%m-%dT%H:%M:%S%z")
    for f in fmts:
        try:
            return datetime.strptime(s, f).astimezone(timezone.utc).replace(microsecond=0)
        except Exception:  # pylint: disable=broad-except
            continue
    return None


def _pc_monthly_cost(memory_mb: int, pc_units: int) -> float:
    """Provisioned Concurrency monthly cost (heuristic)."""
    gb = max(0.0, float(memory_mb) / 1024.0)
    gb_sec_price = config.safe_price("Lambda", "PC_GB_SEC", 0.0000041667)
    seconds = 730.0 * 3600.0
    return gb * float(pc_units) * seconds * gb_sec_price


def _runtime_status(runtime: str) -> Tuple[Optional[str], Optional[str]]:
    """Return ('DEPRECATED'|'EOL_SOON'|None, reason). Heuristic list."""
    r = (runtime or "").lower()
    deprecated = {
        "nodejs10.x", "nodejs12.x", "nodejs14.x",
        "python2.7", "python3.6", "python3.7",
        "dotnetcore1.0", "dotnetcore2.0", "dotnetcore2.1",
        "java8", "go1.x"  # go1.x generally deprecated in many regions
    }
    eol_soon = {
        # Example placeholders you can tune as your policy changes
        # "python3.8", "nodejs16.x",
    }
    if r in deprecated:
        return "DEPRECATED", "Runtime deprecated"
    if r in eol_soon:
        return "EOL_SOON", "Runtime approaching EOL"
    return None, None


# ----------------------- 1) Unused functions (no calls) ----------------- #

@retry_with_backoff(exceptions=(ClientError,))
def check_lambda_unused_functions(  # pylint: disable=unused-argument
    *args,
    logger: Optional[logging.Logger] = None,
    lookback_days: int = 30,
    **kwargs,
) -> None:
    """Flag Lambda functions with zero invocations in the lookback window."""
    log = _logger(kwargs.get("logger") or logger)

    try:
        writer, lmbd, cloudwatch = _extract_writer_lambda_cw(args, kwargs)
    except TypeError as exc:
        log.warning("[check_lambda_unused_functions] Skipping: %s", exc)
        return
    if not (config.ACCOUNT_ID and config.WRITE_ROW):
        log.warning("[check_lambda_unused_functions] Skipping: checker config not provided.")
        return

    region = getattr(getattr(lmbd, "meta", None), "region_name", "") or ""
    funcs = _list_functions(lmbd, log)
    if not funcs:
        return

    now_utc = datetime.now(timezone.utc).replace(microsecond=0)
    start = now_utc - timedelta(days=int(lookback_days))
    period = 300

    # Batch Invocations metric per function
    id_map: Dict[str, str] = {}
    results: Dict[str, Any] = {}
    metrics_ok = True
    try:
        cw = CloudWatchBatcher(region=region, client=cloudwatch)
        for f in funcs:
            name = f.get("FunctionName")
            if not name:
                continue
            qid = f"inv_{name}"
            dims = [("FunctionName", name)]
            cw.add_q(
                id_hint=qid,
                namespace="AWS/Lambda",
                metric="Invocations",
                dims=dims,
                stat="Sum",
                period=period,
            )
            id_map[name] = qid
        results = cw.execute(start=start, end=now_utc)
    except ClientError as exc:
        log.warning("[check_lambda_unused_functions] CloudWatch metrics unavailable: %s", exc)
        metrics_ok = False
    except Exception as exc:  # pylint: disable=broad-except
        log.warning("[check_lambda_unused_functions] CloudWatch batch error: %s", exc)
        metrics_ok = False

    if not metrics_ok:
        return

    for f in funcs:
        name = f.get("FunctionName") or ""
        arn = f.get("FunctionArn") or name
        inv_sum = _sum_from_result(results.get(id_map.get(name)))
        if inv_sum > 0.0:
            continue

        last_mod = _parse_last_modified(f.get("LastModified"))
        runtime = f.get("Runtime")
        mem = f.get("MemorySize")

        signals = _signals_str(
            {
                "Region": region,
                "Function": name,
                "ARN": arn,
                "InvocationsSum": int(inv_sum),
                "LookbackDays": lookback_days,
                "Runtime": runtime,
                "MemoryMB": mem,
                "LastModified": _to_utc_iso(last_mod),
            }
        )

        try:
            # type: ignore[call-arg]
            config.WRITE_ROW(
                writer=writer,
                resource_id=arn,
                name=name,
                owner_id=config.ACCOUNT_ID,  # type: ignore[arg-type]
                resource_type="LambdaFunction",
                estimated_cost=0.0,
                potential_saving=0.0,
                flags=["LambdaFunctionUnused"],
                confidence=100,
                signals=signals,
            )
        except Exception as exc:  # pylint: disable=broad-except
            log.warning("[check_lambda_unused_functions] write_row failed for %s: %s", name, exc)

        log.info("[check_lambda_unused_functions] Wrote: %s", name)


# --------- 2) Provisioned Concurrency underutilized (costly) ------------ #

@retry_with_backoff(exceptions=(ClientError,))
def check_lambda_provisioned_concurrency_underutilized(  # pylint: disable=unused-argument
    *args,
    logger: Optional[logging.Logger] = None,
    lookback_days: int = 14,
    util_threshold: float = 0.05,
    **kwargs,
) -> None:
    """
    Flag provisioned concurrency configs with low average utilization.

    Estimated monthly cost: memory_GB * PC_units * 730h * price("Lambda","PC_GB_SEC")
    Potential saving: full estimated cost when avg utilization < util_threshold.
    """
    log = _logger(kwargs.get("logger") or logger)

    try:
        writer, lmbd, cloudwatch = _extract_writer_lambda_cw(args, kwargs)
    except TypeError as exc:
        log.warning("[check_lambda_provisioned_concurrency_underutilized] Skipping: %s", exc)
        return
    if not (config.ACCOUNT_ID and config.WRITE_ROW and config.GET_PRICE):
        log.warning("[check_lambda_provisioned_concurrency_underutilized] Skipping: checker config.")
        return

    region = getattr(getattr(lmbd, "meta", None), "region_name", "") or ""
    funcs = _list_functions(lmbd, log)
    if not funcs:
        return

    # Map function name → memory size (for cost)
    mem_by_fn: Dict[str, int] = {}
    for f in funcs:
        name = f.get("FunctionName")
        mem = int(f.get("MemorySize") or 0)
        if name:
            mem_by_fn[name] = mem

    # Discover PC configs
    pc_items: List[Tuple[str, str, int]] = []  # (fn, qualifier, pc_units)
    for f in funcs:
        name = f.get("FunctionName")
        if not name:
            continue
        try:
            paginator = lmbd.get_paginator("list_provisioned_concurrency_configs")
            for page in paginator.paginate(FunctionName=name):
                for c in page.get("ProvisionedConcurrencyConfigs", []) or []:
                    qual = c.get("Qualifier")
                    units = int(c.get("AllocatedProvisionedConcurrentExecutions") or 0)
                    if qual and units > 0:
                        pc_items.append((name, qual, units))
        except ClientError as exc:
            # Permission or API not supported in region
            log.debug("[lambda] list_provisioned_concurrency_configs %s: %s", name, exc)

    if not pc_items:
        log.info("[lambda PC] No provisioned concurrency configs in %s", region)
        return

    # CW metrics for utilization: needs Resource=FunctionName:Qualifier
    now_utc = datetime.now(timezone.utc).replace(microsecond=0)
    start = now_utc - timedelta(days=int(lookback_days))
    period = 300

    id_map: Dict[Tuple[str, str], str] = {}
    results: Dict[str, Any] = {}
    metrics_ok = True
    try:
        cw = CloudWatchBatcher(region=region, client=cloudwatch)
        for fn, qual, _units in pc_items:
            qid = f"u_{fn}_{qual}"
            dims = [("FunctionName", fn), ("Resource", f"{fn}:{qual}")]
            cw.add_q(
                id_hint=qid,
                namespace="AWS/Lambda",
                metric="ProvisionedConcurrencyUtilization",
                dims=dims,
                stat="Average",
                period=period,
            )
            id_map[(fn, qual)] = qid
        results = cw.execute(start=start, end=now_utc)
    except ClientError as exc:
        log.warning("[lambda PC] CloudWatch metrics unavailable: %s", exc)
        metrics_ok = False
    except Exception as exc:  # pylint: disable=broad-except
        log.warning("[lambda PC] CloudWatch batch error: %s", exc)
        metrics_ok = False

    if not metrics_ok:
        return

    for fn, qual, units in pc_items:
        util_avg = _avg_from_result(results.get(id_map.get((fn, qual))))
        if util_avg >= float(util_threshold):
            continue

        mem = mem_by_fn.get(fn, 0)
        est = _pc_monthly_cost(mem, units)
        potential = est  # if you drop PC on an unused/low-util config

        arn = f"{fn}:{qual}"
        signals = _signals_str(
            {
                "Region": region,
                "Function": fn,
                "Qualifier": qual,
                "MemoryMB": mem,
                "PCUnits": units,
                "UtilAvg": round(util_avg, 4),
                "LookbackDays": lookback_days,
                "UtilThreshold": util_threshold,
            }
        )

        try:
            # type: ignore[call-arg]
            config.WRITE_ROW(
                writer=writer,
                resource_id=arn,
                name=arn,
                owner_id=config.ACCOUNT_ID,  # type: ignore[arg-type]
                resource_type="LambdaProvisionedConcurrency",
                estimated_cost=est,
                potential_saving=potential,
                flags=["LambdaProvisionedConcurrencyUnderutilized"],
                confidence=100,
                signals=signals,
            )
        except Exception as exc:  # pylint: disable=broad-except
            log.warning("[lambda PC] write_row failed for %s: %s", arn, exc)

        log.info("[lambda PC] Wrote: %s (%s)", fn, qual)


# ---------------- 3) Deprecated / EOL runtimes (hygiene) ---------------- #

@retry_with_backoff(exceptions=(ClientError,))
def check_lambda_runtime_deprecated(  # pylint: disable=unused-argument
    *args,
    logger: Optional[logging.Logger] = None,
    **kwargs,
) -> None:
    """Flag functions using deprecated or EOL-soon runtimes (heuristic map)."""
    log = _logger(kwargs.get("logger") or logger)

    try:
        writer, lmbd, cloudwatch = _extract_writer_lambda_cw(args, kwargs)  # cloudwatch unused
    except TypeError as exc:
        log.warning("[check_lambda_runtime_deprecated] Skipping: %s", exc)
        return
    if not (config.ACCOUNT_ID and config.WRITE_ROW):
        log.warning("[check_lambda_runtime_deprecated] Skipping: checker config not provided.")
        return

    region = getattr(getattr(lmbd, "meta", None), "region_name", "") or ""
    funcs = _list_functions(lmbd, log)
    if not funcs:
        return

    for f in funcs:
        name = f.get("FunctionName") or ""
        arn = f.get("FunctionArn") or name
        runtime = f.get("Runtime") or ""
        status, reason = _runtime_status(runtime)
        if not status:
            continue

        last_mod = _parse_last_modified(f.get("LastModified"))

        try:
            # type: ignore[call-arg]
            config.WRITE_ROW(
                writer=writer,
                resource_id=arn,
                name=name,
                owner_id=config.ACCOUNT_ID,  # type: ignore[arg-type]
                resource_type="LambdaFunction",
                estimated_cost=0.0,
                potential_saving=0.0,
                flags=[
                    "LambdaRuntimeDeprecated" if status == "DEPRECATED"
                    else "LambdaRuntimeEOLSoon"
                ],
                confidence=100,
                signals=_signals_str(
                    {
                        "Region": region,
                        "Function": name,
                        "ARN": arn,
                        "Runtime": runtime,
                        "Reason": reason,
                        "LastModified": _to_utc_iso(last_mod),
                    }
                ),
            )
        except Exception as exc:  # pylint: disable=broad-except
            log.warning("[check_lambda_runtime_deprecated] write_row failed for %s: %s", name, exc)

        log.info("[check_lambda_runtime_deprecated] Wrote: %s (%s)", name, runtime)


# ------------------- 4) Large packages (zip size > N MB) ---------------- #

@retry_with_backoff(exceptions=(ClientError,))
def check_lambda_large_packages(  # pylint: disable=unused-argument
    *args,
    logger: Optional[logging.Logger] = None,
    size_threshold_mb: int = 50,
    **kwargs,
) -> None:
    """Flag functions with large deployment package size (CodeSize)."""
    log = _logger(kwargs.get("logger") or logger)

    try:
        writer, lmbd, cloudwatch = _extract_writer_lambda_cw(args, kwargs)  # cloudwatch unused
    except TypeError as exc:
        log.warning("[check_lambda_large_packages] Skipping: %s", exc)
        return
    if not (config.ACCOUNT_ID and config.WRITE_ROW):
        log.warning("[check_lambda_large_packages] Skipping: checker config not provided.")
        return

    region = getattr(getattr(lmbd, "meta", None), "region_name", "") or ""
    funcs = _list_functions(lmbd, log)
    if not funcs:
        return

    thr_bytes = int(size_threshold_mb) * 1024 * 1024

    for f in funcs:
        name = f.get("FunctionName") or ""
        arn = f.get("FunctionArn") or name
        size = int(f.get("CodeSize") or 0)
        if size <= thr_bytes:
            continue

        runtime = f.get("Runtime")
        mem = f.get("MemorySize")
        last_mod = _parse_last_modified(f.get("LastModified"))

        try:
            # type: ignore[call-arg]
            config.WRITE_ROW(
                writer=writer,
                resource_id=arn,
                name=name,
                owner_id=config.ACCOUNT_ID,  # type: ignore[arg-type]
                resource_type="LambdaFunction",
                estimated_cost=0.0,
                potential_saving=0.0,
                flags=["LambdaPackageLarge"],
                confidence=100,
                signals=_signals_str(
                    {
                        "Region": region,
                        "Function": name,
                        "ARN": arn,
                        "Runtime": runtime,
                        "MemoryMB": mem,
                        "CodeSizeBytes": size,
                        "ThresholdMB": size_threshold_mb,
                        "LastModified": _to_utc_iso(last_mod),
                    }
                ),
            )
        except Exception as exc:  # pylint: disable=broad-except
            log.warning("[check_lambda_large_packages] write_row failed for %s: %s", name, exc)

        log.info("[check_lambda_large_packages] Wrote: %s (size=%dMB)", name, size // (1024 * 1024))


# ---------------------- 5) Old functions (stale code) ------------------- #

@retry_with_backoff(exceptions=(ClientError,))
def check_lambda_old_functions(  # pylint: disable=unused-argument
    *args,
    logger: Optional[logging.Logger] = None,
    age_days: int = 180,
    **kwargs,
) -> None:
    """Flag functions last modified earlier than 'age_days'."""
    log = _logger(kwargs.get("logger") or logger)

    try:
        writer, lmbd, cloudwatch = _extract_writer_lambda_cw(args, kwargs)  # cloudwatch unused
    except TypeError as exc:
        log.warning("[check_lambda_old_functions] Skipping: %s", exc)
        return
    if not (config.ACCOUNT_ID and config.WRITE_ROW):
        log.warning("[check_lambda_old_functions] Skipping: checker config not provided.")
        return

    region = getattr(getattr(lmbd, "meta", None), "region_name", "") or ""
    funcs = _list_functions(lmbd, log)
    if not funcs:
        return

    cutoff = (datetime.now(timezone.utc) - timedelta(days=int(age_days))).replace(microsecond=0)

    for f in funcs:
        name = f.get("FunctionName") or ""
        arn = f.get("FunctionArn") or name
        last_mod = _parse_last_modified(f.get("LastModified"))

        if not last_mod or last_mod >= cutoff:
            continue

        runtime = f.get("Runtime")
        mem = f.get("MemorySize")

        try:
            # type: ignore[call-arg]
            config.WRITE_ROW(
                writer=writer,
                resource_id=arn,
                name=name,
                owner_id=config.ACCOUNT_ID,  # type: ignore[arg-type]
                resource_type="LambdaFunction",
                estimated_cost=0.0,
                potential_saving=0.0,
                flags=["LambdaFunctionOld"],
                confidence=100,
                signals=_signals_str(
                    {
                        "Region": region,
                        "Function": name,
                        "ARN": arn,
                        "Runtime": runtime,
                        "MemoryMB": mem,
                        "LastModified": _to_utc_iso(last_mod),
                        "AgeDays": age_days,
                    }
                ),
            )
        except Exception as exc:  # pylint: disable=broad-except
            log.warning("[check_lambda_old_functions] write_row failed for %s: %s", name, exc)

        log.info("[check_lambda_old_functions] Wrote: %s", name)
