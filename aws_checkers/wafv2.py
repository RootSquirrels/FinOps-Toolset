"""Checkers: AWS WAFv2.

Checks:
  - check_wafv2_unassociated_web_acls
  - check_wafv2_logging_disabled
  - check_wafv2_rules_no_matches
  - check_wafv2_empty_acl_associated
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple

from botocore.exceptions import ClientError

from aws_checkers import config
from core.retry import retry_with_backoff
from core.cloudwatch import CloudWatchBatcher


# -------------------------------- helpers -------------------------------- #

def _logger(fallback: Optional[logging.Logger]) -> logging.Logger:
    return fallback or config.LOGGER or logging.getLogger(__name__)


def _signals_str(pairs: Dict[str, object]) -> str:
    items: List[str] = []
    for k, v in pairs.items():
        if v is None or v == "":
            continue
        items.append(f"{k}={v}")
    return "|".join(items)


def _to_utc_iso(dt_obj: Optional[datetime]) -> Optional[str]:
    if not isinstance(dt_obj, datetime):
        return None
    if dt_obj.tzinfo is None:
        dt_obj = dt_obj.replace(tzinfo=timezone.utc)
    else:
        dt_obj = dt_obj.astimezone(timezone.utc)
    return dt_obj.replace(microsecond=0).isoformat()


def _extract_writer_wafv2(
    args: Tuple[Any, ...],
    kwargs: Dict[str, Any],
) -> Tuple[Any, Any]:
    writer = kwargs.get("writer", args[0] if len(args) >= 1 else None)
    wafv2 = kwargs.get("wafv2", args[1] if len(args) >= 2 else None)
    if writer is None or wafv2 is None:
        raise TypeError(
            "Expected 'writer' and 'wafv2' "
            f"(got writer={writer!r}, wafv2={wafv2!r})"
        )
    return writer, wafv2


def _extract_writer_wafv2_cw(
    args: Tuple[Any, ...],
    kwargs: Dict[str, Any],
) -> Tuple[Any, Any, Any]:
    writer = kwargs.get("writer", args[0] if len(args) >= 1 else None)
    wafv2 = kwargs.get("wafv2", args[1] if len(args) >= 2 else None)
    cloudwatch = kwargs.get("cloudwatch", args[2] if len(args) >= 3 else None)
    if writer is None or wafv2 is None or cloudwatch is None:
        raise TypeError(
            "Expected 'writer', 'wafv2' and 'cloudwatch' "
            f"(got writer={writer!r}, wafv2={wafv2!r}, cloudwatch={cloudwatch!r})"
        )
    return writer, wafv2, cloudwatch


def _list_web_acls(waf, scope: str, log: logging.Logger) -> List[Dict[str, Any]]:
    """Manual pagination for list_web_acls (no paginator in some boto3 versions)."""
    out: List[Dict[str, Any]] = []
    marker: Optional[str] = None
    while True:
        try:
            params = {"Scope": scope, "Limit": 100}
            if marker:
                params["NextMarker"] = marker
            resp = waf.list_web_acls(**params)
            out.extend(resp.get("WebACLs", []) or [])
            marker = resp.get("NextMarker")
            if not marker:
                break
        except ClientError as exc:
            log.error("[wafv2] list_web_acls(%s) failed: %s", scope, exc)
            break
    return out


def _get_web_acl(waf, scope: str, name: str, wid: str, log: logging.Logger) -> Dict[str, Any]:
    try:
        return waf.get_web_acl(Name=name, Scope=scope, Id=wid).get("WebACL", {}) or {}
    except ClientError as exc:
        log.debug("[wafv2] get_web_acl %s/%s (%s) failed: %s", name, wid, scope, exc)
        return {}


def _list_associated_resources(
    waf, arn: str, scope: str, log: logging.Logger
) -> List[str]:
    """
    Robust wrapper for list_resources_for_web_acl.

    - Some SDK models don't accept Limit, so we never send it.
    - We always send ResourceType.
    - We iterate all relevant resource types for REGIONAL scope.
    """
    out: List[str] = []
    scope_u = (scope or "").upper()

    if scope_u == "CLOUDFRONT":
        rtypes = ["CLOUDFRONT"]
    else:
        rtypes = [
            "APPLICATION_LOAD_BALANCER",
            "API_GATEWAY",
            "APPSYNC",
            "COGNITO_USER_POOL",
        ]

    for rtype in rtypes:
        marker: Optional[str] = None
        while True:
            params = {"WebACLArn": arn, "ResourceType": rtype}
            if marker:
                # NextMarker is supported on most recent models; if not, we'll fall back.
                params["NextMarker"] = marker
            try:
                resp = waf.list_resources_for_web_acl(**params)
            except ClientError as exc:
                log.debug(
                    "[wafv2] list_resources_for_web_acl arn=%s type=%s failed: %s",
                    arn,
                    rtype,
                    exc,
                )
                break
            except Exception as exc:  # pylint: disable=broad-except
                # Covers ParamValidationError on unknown parameter in very old models.
                log.debug(
                    "[wafv2] list_resources_for_web_acl arn=%s type=%s error: %s",
                    arn,
                    rtype,
                    exc,
                )
                break

            out.extend(resp.get("ResourceArns", []) or [])
            marker = resp.get("NextMarker")
            if not marker:
                break

    return out


def _acl_monthly_cost(rule_count: int) -> float:
    base = float(config.safe_price("WAFV2", "WEB_ACL_MONTH", 5.0))
    per = float(config.safe_price("WAFV2", "RULE_MONTH", 1.0))
    return base + max(0, int(rule_count)) * per


def _rule_monthly_cost() -> float:
    return float(config.safe_price("WAFV2", "RULE_MONTH", 1.0))


def _region_value_for_scope(region: str, scope: str) -> str:
    return "Global" if scope.upper() == "CLOUDFRONT" else region


def _sum_from_result(res: Any) -> float:
    if res is None:
        return 0.0
    if isinstance(res, list) and res and isinstance(res[0], tuple):
        try:
            return float(sum(float(v) for _, v in res))
        except Exception:  # pylint: disable=broad-except
            return 0.0
    if isinstance(res, dict):
        vals = res.get("Values") or res.get("values") or []
        try:
            return float(sum(vals))
        except Exception:  # pylint: disable=broad-except
            return 0.0
    return 0.0


def _scopes_and_clients(
    wafv2,
    kwargs: Dict[str, Any],
    region: str,
    log: logging.Logger,
    include_cloudfront: bool,
) -> List[Tuple[str, Any]]:
    scopes: List[Tuple[str, Any]] = [("REGIONAL", wafv2)]
    if include_cloudfront:
        cf_client = kwargs.get("wafv2_cf")
        if cf_client is None and region == "us-east-1":
            cf_client = wafv2
        if cf_client is not None:
            scopes.append(("CLOUDFRONT", cf_client))
        else:
            log.debug("[wafv2] CloudFront scope requested but no 'wafv2_cf' client provided.")
    return scopes


# -------------------- 1) Unassociated Web ACLs (cost) -------------------- #

@retry_with_backoff(exceptions=(ClientError,))
def check_wafv2_unassociated_web_acls(  # pylint: disable=unused-argument
    *args,
    logger: Optional[logging.Logger] = None,
    include_cloudfront: bool = False,
    **kwargs,
) -> None:
    log = _logger(kwargs.get("logger") or logger)

    try:
        writer, wafv2 = _extract_writer_wafv2(args, kwargs)
    except TypeError as exc:
        log.warning("[check_wafv2_unassociated_web_acls] Skipping: %s", exc)
        return
    if not (config.ACCOUNT_ID and config.WRITE_ROW and config.GET_PRICE):
        log.warning("[check_wafv2_unassociated_web_acls] Skipping: checker config not provided.")
        return

    region = getattr(getattr(wafv2, "meta", None), "region_name", "") or ""
    for scope, client in _scopes_and_clients(wafv2, kwargs, region, log, include_cloudfront):
        acls = _list_web_acls(client, scope, log)
        for s in acls:
            name, wid, arn = s.get("Name"), s.get("Id"), s.get("ARN")
            if not (name and wid and arn):
                continue

            full = _get_web_acl(client, scope, name, wid, log)
            rules = full.get("Rules", []) or []
            assoc = _list_associated_resources(client, arn, scope, log)
            if assoc:
                continue

            rule_count = len(rules)
            est = _acl_monthly_cost(rule_count)
            potential = est

            try:
                # type: ignore[call-arg]
                config.WRITE_ROW(
                    writer=writer,
                    resource_id=arn,
                    name=name,
                    owner_id=config.ACCOUNT_ID,  # type: ignore[arg-type]
                    resource_type="WAFv2WebACL",
                    estimated_cost=est,
                    potential_saving=potential,
                    flags=["WAFv2WebACLUnassociated"],
                    confidence=100,
                    signals=_signals_str(
                        {
                            "Region": region,
                            "Scope": scope,
                            "WebACLName": name,
                            "WebACLId": wid,
                            "RuleCount": rule_count,
                            "AssociatedCount": 0,
                        }
                    ),
                )
            except Exception as exc:  # pylint: disable=broad-except
                log.warning("[wafv2] write_row unassociated %s: %s", arn, exc)

            log.info("[wafv2] Wrote unassociated WebACL: %s (%s)", name, scope)


# ----------------------- 2) Logging disabled (hygiene) ------------------- #

@retry_with_backoff(exceptions=(ClientError,))
def check_wafv2_logging_disabled(  # pylint: disable=unused-argument
    *args,
    logger: Optional[logging.Logger] = None,
    include_cloudfront: bool = False,
    **kwargs,
) -> None:
    log = _logger(kwargs.get("logger") or logger)

    try:
        writer, wafv2 = _extract_writer_wafv2(args, kwargs)
    except TypeError as exc:
        log.warning("[check_wafv2_logging_disabled] Skipping: %s", exc)
        return
    if not (config.ACCOUNT_ID and config.WRITE_ROW):
        log.warning("[check_wafv2_logging_disabled] Skipping: checker config not provided.")
        return

    region = getattr(getattr(wafv2, "meta", None), "region_name", "") or ""
    for scope, client in _scopes_and_clients(wafv2, kwargs, region, log, include_cloudfront):
        acls = _list_web_acls(client, scope, log)
        for s in acls:
            name, wid, arn = s.get("Name"), s.get("Id"), s.get("ARN")
            if not (name and wid and arn):
                continue
            try:
                cfg = client.get_logging_configuration(ResourceArn=arn)
                has_logging = bool(cfg.get("LoggingConfiguration"))
            except ClientError as exc:
                log.debug("[wafv2] get_logging_configuration %s: %s", arn, exc)
                has_logging = False

            if has_logging:
                continue

            try:
                # type: ignore[call-arg]
                config.WRITE_ROW(
                    writer=writer,
                    resource_id=arn,
                    name=name,
                    owner_id=config.ACCOUNT_ID,  # type: ignore[arg-type]
                    resource_type="WAFv2WebACL",
                    estimated_cost=0.0,
                    potential_saving=0.0,
                    flags=["WAFv2WebACLLoggingDisabled"],
                    confidence=100,
                    signals=_signals_str(
                        {"Region": region, "Scope": scope, "WebACLName": name, "WebACLId": wid}
                    ),
                )
            except Exception as exc:  # pylint: disable=broad-except
                log.warning("[wafv2] write_row logging-disabled %s: %s", arn, exc)

            log.info("[wafv2] Wrote logging-disabled WebACL: %s (%s)", name, scope)


# ---------------------- 3) Rules with no matches (cost) ------------------ #

@retry_with_backoff(exceptions=(ClientError,))
def check_wafv2_rules_no_matches(  # pylint: disable=unused-argument
    *args,
    logger: Optional[logging.Logger] = None,
    lookback_days: int = 14,
    include_cloudfront: bool = False,
    **kwargs,
) -> None:
    log = _logger(kwargs.get("logger") or logger)

    try:
        writer, wafv2, cloudwatch = _extract_writer_wafv2_cw(args, kwargs)
    except TypeError as exc:
        log.warning("[check_wafv2_rules_no_matches] Skipping: %s", exc)
        return
    if not (config.ACCOUNT_ID and config.WRITE_ROW and config.GET_PRICE):
        log.warning("[check_wafv2_rules_no_matches] Skipping: checker config not provided.")
        return

    region = getattr(getattr(wafv2, "meta", None), "region_name", "") or ""
    now_utc = datetime.now(timezone.utc).replace(microsecond=0)
    start = now_utc - timedelta(days=int(lookback_days))
    period = 300
    rule_cost = float(config.safe_price("WAFV2", "RULE_MONTH", 1.0))

    for scope, client in _scopes_and_clients(wafv2, kwargs, region, log, include_cloudfront):
        acls = _list_web_acls(client, scope, log)
        if not acls:
            continue

        region_dim = "Global" if scope.upper() == "CLOUDFRONT" else region

        id_map: Dict[Tuple[str, str], Dict[str, str]] = {}
        metrics_ok = True
        results: Dict[str, Any] = {}
        try:
            cw = CloudWatchBatcher(region=region, client=cloudwatch)
            for s in acls:
                name, wid = s.get("Name"), s.get("Id")
                if not (name and wid):
                    continue
                full = _get_web_acl(client, scope, name, wid, log)
                if not full:
                    continue
                acl_metric = (full.get("VisibilityConfig") or {}).get("MetricName")
                if not acl_metric:
                    continue
                for r in (full.get("Rules") or []):
                    vis = r.get("VisibilityConfig") or {}
                    rule_metric = vis.get("MetricName")
                    if not rule_metric:
                        continue
                    dims = [("Region", region_dim), ("WebACL", acl_metric),
                            ("Rule", rule_metric)]

                    id_a = f"a_{acl_metric}_{rule_metric}"
                    id_b = f"b_{acl_metric}_{rule_metric}"
                    id_c = f"c_{acl_metric}_{rule_metric}"

                    cw.add_q(
                        id_hint=id_a,
                        namespace="AWS/WAFV2",
                        metric="AllowedRequests",
                        dims=dims,
                        stat="Sum",
                        period=period,
                    )
                    cw.add_q(
                        id_hint=id_b,
                        namespace="AWS/WAFV2",
                        metric="BlockedRequests",
                        dims=dims,
                        stat="Sum",
                        period=period,
                    )
                    cw.add_q(
                        id_hint=id_c,
                        namespace="AWS/WAFV2",
                        metric="CountedRequests",
                        dims=dims,
                        stat="Sum",
                        period=period,
                    )

                    id_map[(acl_metric, rule_metric)] = {"a": id_a, "b": id_b, "c": id_c}

            results = cw.execute(start=start, end=now_utc)
        except ClientError as exc:
            logging.warning("[wafv2] CloudWatch metrics unavailable: %s", exc)
            metrics_ok = False
        except Exception as exc:  # pylint: disable=broad-except
            logging.warning("[wafv2] CloudWatch batch error: %s", exc)
            metrics_ok = False

        if not metrics_ok:
            continue

        for (acl_metric, rule_metric), ids in id_map.items():
            s_allowed = _sum_from_result(results.get(ids.get("a")))
            s_blocked = _sum_from_result(results.get(ids.get("b")))
            s_counted = _sum_from_result(results.get(ids.get("c")))
            total = s_allowed + s_blocked + s_counted
            if total > 0.0:
                continue

            try:
                # type: ignore[call-arg]
                config.WRITE_ROW(
                    writer=writer,
                    resource_id=f"{acl_metric}:{rule_metric}:{scope}",
                    name=f"{acl_metric}/{rule_metric}",
                    owner_id=config.ACCOUNT_ID,  # type: ignore[arg-type]
                    resource_type="WAFv2Rule",
                    estimated_cost=rule_cost,
                    potential_saving=rule_cost,
                    flags=["WAFv2RuleNoMatches"],
                    confidence=100,
                    signals=_signals_str(
                        {
                            "Region": region,
                            "Scope": scope,
                            "WebACLMetric": acl_metric,
                            "RuleMetric": rule_metric,
                            "AllowedSum": int(s_allowed),
                            "BlockedSum": int(s_blocked),
                            "CountedSum": int(s_counted),
                            "LookbackDays": lookback_days,
                        }
                    ),
                )
            except Exception as exc:  # pylint: disable=broad-except
                logging.warning(
                    "[wafv2] write_row rule no-matches %s/%s: %s",
                    acl_metric,
                    rule_metric,
                    exc,
                )

            logging.info(
                "[wafv2] Wrote rule with no matches: %s/%s (%s)",
                acl_metric,
                rule_metric,
                scope,
            )


# --------- 4) ACL with zero rules but associated (ineffective, cost) ----- #

@retry_with_backoff(exceptions=(ClientError,))
def check_wafv2_empty_acl_associated(  # pylint: disable=unused-argument
    *args,
    logger: Optional[logging.Logger] = None,
    include_cloudfront: bool = False,
    **kwargs,
) -> None:
    log = _logger(kwargs.get("logger") or logger)

    try:
        writer, wafv2 = _extract_writer_wafv2(args, kwargs)
    except TypeError as exc:
        logging.warning("[check_wafv2_empty_acl_associated] Skipping: %s", exc)
        return
    if not (config.ACCOUNT_ID and config.WRITE_ROW and config.GET_PRICE):
        logging.warning(
            "[check_wafv2_empty_acl_associated] Skipping: checker config not provided."
        )
        return

    region = getattr(getattr(wafv2, "meta", None), "region_name", "") or ""
    for scope, client in _scopes_and_clients(wafv2, kwargs, region, log, include_cloudfront):
        acls = _list_web_acls(client, scope, log)
        for s in acls:
            name, wid, arn = s.get("Name"), s.get("Id"), s.get("ARN")
            if not (name and wid and arn):
                continue

            full = _get_web_acl(client, scope, name, wid, log)
            rules = full.get("Rules", []) or []
            assoc = _list_associated_resources(client, arn, scope, log)
            if len(rules) > 0 or not assoc:
                continue

            est = _acl_monthly_cost(0)
            potential = est

            try:
                # type: ignore[call-arg]
                config.WRITE_ROW(
                    writer=writer,
                    resource_id=arn,
                    name=name,
                    owner_id=config.ACCOUNT_ID,  # type: ignore[arg-type]
                    resource_type="WAFv2WebACL",
                    estimated_cost=est,
                    potential_saving=potential,
                    flags=["WAFv2WebACLNoRulesAssociated"],
                    confidence=100,
                    signals=_signals_str(
                        {
                            "Region": region,
                            "Scope": scope,
                            "WebACLName": name,
                            "WebACLId": wid,
                            "AssociatedCount": len(assoc),
                            "RuleCount": 0,
                        }
                    ),
                )
            except Exception as exc:  # pylint: disable=broad-except
                logging.warning("[wafv2] write_row empty-associated %s: %s", arn, exc)

            logging.info("[wafv2] Wrote empty but associated WebACL: %s (%s)", name, scope)
