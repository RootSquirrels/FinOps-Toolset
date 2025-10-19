"""Checkers: Amazon S3.

Checks included:

  Security & Hygiene
  - check_s3_public_buckets
  - check_s3_buckets_without_default_encryption
  - check_s3_versioned_without_lifecycle
  - check_s3_buckets_without_lifecycle

  Storage & Cost
  - check_s3_empty_buckets
  - check_s3_ia_tiering_candidates
  - check_s3_stale_multipart_uploads

Design:
  - Dependencies (account_id, write_row, get_price, logger) via
    finops_toolset.checkers.config.setup(...).
  - CloudWatch via finops_toolset.cloudwatch.CloudWatchBatcher.
  - Tolerant signatures; graceful skips when deps/clients are missing.
  - Emits Flags, Signals (compact k=v), Estimated_Cost_USD, Potential_Saving_USD.
  - Timezone-aware datetimes (datetime.now(timezone.utc)).
  - Pylint-friendly lazy %s logging and ≤ 100-char lines.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Iterable, List, Optional, Tuple

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


def _extract_writer_s3_cw(
    args: Tuple[Any, ...],
    kwargs: Dict[str, Any],
) -> Tuple[Any, Any, Any]:
    """Accept writer/s3/cloudwatch passed positionally or by keyword."""
    writer = kwargs.get("writer", args[0] if len(args) >= 1 else None)
    s3 = kwargs.get("s3", args[1] if len(args) >= 2 else None)
    cloudwatch = kwargs.get("cloudwatch", args[2] if len(args) >= 3 else None)
    if writer is None or s3 is None or cloudwatch is None:
        raise TypeError(
            "Expected 'writer', 's3', and 'cloudwatch' "
            f"(got writer={writer!r}, s3={s3!r}, cloudwatch={cloudwatch!r})"
        )
    return writer, s3, cloudwatch


def _bytes_to_gb(bval: float) -> float:
    return max(0.0, float(bval) / (1024.0 ** 3))


def _last_from_result(res: Any) -> float:
    """Return last datapoint value from CloudWatchBatcher series."""
    if res is None:
        return 0.0
    if isinstance(res, list) and res:
        try:
            # Expect list[(ts, val), ...]
            return float(res[-1][1])
        except Exception:  # pylint: disable=broad-except
            return 0.0
    if isinstance(res, dict):
        vals = res.get("Values") or res.get("values") or []
        try:
            return float(vals[-1]) if vals else 0.0
        except Exception:  # pylint: disable=broad-except
            return 0.0
    return 0.0


def _s3_bucket_region(s3, name: str, log: logging.Logger) -> Optional[str]:
    """Resolve bucket region; None on error."""
    try:
        resp = s3.get_bucket_location(Bucket=name)
        loc = resp.get("LocationConstraint")
        if not loc:
            return "us-east-1"  # legacy None => us-east-1
        # Some APIs return "EU" for eu-west-1
        return "eu-west-1" if loc == "EU" else str(loc)
    except ClientError as exc:
        log.debug("[s3] get_bucket_location failed for %s: %s", name, exc)
        return None


def _list_buckets_in_region(
    s3,
    desired_region: str,
    log: logging.Logger,
) -> List[Tuple[str, datetime]]:
    """List (bucket_name, creation_date) filtered to desired_region."""
    out: List[Tuple[str, datetime]] = []
    try:
        resp = s3.list_buckets()
    except ClientError as exc:
        log.error("[s3] list_buckets failed: %s", exc)
        return out

    for b in resp.get("Buckets", []) or []:
        name = b.get("Name")
        if not name:
            continue
        region = _s3_bucket_region(s3, name, log)
        if region and region == desired_region:
            created = b.get("CreationDate")
            if isinstance(created, datetime):
                out.append((name, created))
            else:
                out.append((name, datetime.now(timezone.utc)))
    return out


def _storage_price_key(storage_type: str) -> Optional[str]:
    """Map S3 CloudWatch storage type to pricebook key (heuristic)."""
    st = (storage_type or "").lower()
    if st == "standardstorage":
        return "STANDARD_GB_MONTH"
    if st == "standardiastorage":
        return "STANDARD_IA_GB_MONTH"
    if st == "onezoneiastorage":
        return "ONEZONE_IA_GB_MONTH"
    if st == "glacierinstantretrievalstorage":
        return "GLACIER_IR_GB_MONTH"
    if st == "glacierstorage":
        return "GLACIER_GB_MONTH"
    if st == "deeparchivestorage":
        return "GLACIER_DEEP_GB_MONTH"
    if st == "noncurrentversionstorage":
        # noncurrent defaults to Standard unless lifecycle moves it
        return "STANDARD_GB_MONTH"
    return None


def _estimate_storage_cost_gb_by_type(gb_by_type: Dict[str, float]) -> float:
    total = 0.0
    for stype, gbs in gb_by_type.items():
        pkey = _storage_price_key(stype)
        price = config.safe_price("S3", pkey, 0.0) if pkey else 0.0
        total += gbs * price
    return total


def _cw_add_storage_queries(
    cw: CloudWatchBatcher,
    bucket: str,
    types: Iterable[str],
) -> Dict[str, str]:
    """Queue S3 storage metrics for a bucket; return id map."""
    ids: Dict[str, str] = {}
    for stype in types:
        qid = f"s3_{bucket}_{stype}"
        dims = [("BucketName", bucket), ("StorageType", stype)]
        cw.add_q(
            id_hint=qid,
            namespace="AWS/S3",
            metric="BucketSizeBytes",
            dims=dims,
            stat="Average",
            period=86400,
        )
        ids[stype] = qid
    # Also number of objects (daily)
    qid_cnt = f"s3_{bucket}_obj_count"
    dims_cnt = [("BucketName", bucket), ("StorageType", "AllStorageTypes")]
    cw.add_q(
        id_hint=qid_cnt,
        namespace="AWS/S3",
        metric="NumberOfObjects",
        dims=dims_cnt,
        stat="Average",
        period=86400,
    )
    ids["__NumberOfObjects__"] = qid_cnt
    return ids


# ------------------------- 1) Public buckets check ----------------------- #

@retry_with_backoff(exceptions=(ClientError,))
def check_s3_public_buckets(  # pylint: disable=unused-argument
    *args,
    logger: Optional[logging.Logger] = None,
    **kwargs,
) -> None:
    """Flag buckets that are publicly accessible (policy or ACL)."""
    log = _logger(kwargs.get("logger") or logger)

    try:
        writer, s3, cloudwatch = _extract_writer_s3_cw(args, kwargs)  # cloudwatch unused
    except TypeError as exc:
        log.warning("[check_s3_public_buckets] Skipping: %s", exc)
        return
    if not (config.ACCOUNT_ID and config.WRITE_ROW):
        log.warning("[check_s3_public_buckets] Skipping: checker config not provided.")
        return

    cw_region = getattr(getattr(cloudwatch, "meta", None), "region_name", "") or ""
    buckets = _list_buckets_in_region(s3, cw_region, log)
    if not buckets:
        log.info("[check_s3_public_buckets] No buckets in %s", cw_region)
        return

    for bname, created in buckets:
        is_public = False
        pab = {}
        try:
            pab = (s3.get_public_access_block(Bucket=bname) or {}).get("PublicAccessBlockConfiguration", {})  # noqa: E501
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code != "NoSuchPublicAccessBlockConfiguration":
                log.debug("[s3] get_public_access_block %s: %s", bname, exc)

        try:
            pol = s3.get_bucket_policy_status(Bucket=bname)
            is_public = bool(pol.get("PolicyStatus", {}).get("IsPublic"))
        except ClientError as exc:
            # No policy or permission → fall back to ACL
            log.debug("[s3] get_bucket_policy_status %s: %s", bname, exc)

        if not is_public:
            try:
                acl = s3.get_bucket_acl(Bucket=bname)
                grants = acl.get("Grants", []) or []
                for g in grants:
                    gr = g.get("Grantee", {}) or {}
                    uri = (gr.get("URI") or "").lower()
                    if "allusers" in uri or "authenticatedusers" in uri:
                        is_public = True
                        break
            except ClientError as exc:
                log.debug("[s3] get_bucket_acl %s: %s", bname, exc)

        if not is_public:
            continue

        flags = ["S3BucketPublic"]
        signals = _signals_str(
            {
                "Region": cw_region,
                "Bucket": bname,
                "CreatedAt": _to_utc_iso(created),
                "PAB_BlockPublicAcls": pab.get("BlockPublicAcls"),
                "PAB_BlockPublicPolicy": pab.get("BlockPublicPolicy"),
                "PAB_IgnorePublicAcls": pab.get("IgnorePublicAcls"),
                "PAB_RestrictPublicBuckets": pab.get("RestrictPublicBuckets"),
            }
        )

        try:
            # type: ignore[call-arg]
            config.WRITE_ROW(
                writer=writer,
                resource_id=bname,
                name=bname,
                owner_id=config.ACCOUNT_ID,  # type: ignore[arg-type]
                resource_type="S3Bucket",
                estimated_cost=0.0,
                potential_saving=0.0,
                flags=flags,
                confidence=100,
                signals=signals,
            )
        except Exception as exc:  # pylint: disable=broad-except
            log.warning("[check_s3_public_buckets] write_row failed for %s: %s", bname, exc)

        log.info("[check_s3_public_buckets] Wrote: %s", bname)


# --------------- 2) Default encryption missing (SSE) --------------------- #

@retry_with_backoff(exceptions=(ClientError,))
def check_s3_buckets_without_default_encryption(  # pylint: disable=unused-argument
    *args,
    logger: Optional[logging.Logger] = None,
    **kwargs,
) -> None:
    """Flag buckets that do not have default encryption configured."""
    log = _logger(kwargs.get("logger") or logger)

    try:
        writer, s3, cloudwatch = _extract_writer_s3_cw(args, kwargs)  # cloudwatch unused
    except TypeError as exc:
        log.warning("[check_s3_buckets_without_default_encryption] Skipping: %s", exc)
        return
    if not (config.ACCOUNT_ID and config.WRITE_ROW):
        log.warning("[check_s3_buckets_without_default_encryption] Skipping: checker config.")
        return

    cw_region = getattr(getattr(cloudwatch, "meta", None), "region_name", "") or ""
    buckets = _list_buckets_in_region(s3, cw_region, log)
    if not buckets:
        return

    for bname, created in buckets:
        has_enc = True
        enc_algo = None
        try:
            enc = s3.get_bucket_encryption(Bucket=bname)
            rules = enc.get("ServerSideEncryptionConfiguration", {}).get("Rules", [])  # noqa: E501
            if rules:
                algo = rules[0].get("ApplyServerSideEncryptionByDefault", {}).get("SSEAlgorithm")  # noqa: E501
                enc_algo = algo
                has_enc = bool(algo)
            else:
                has_enc = False
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code == "ServerSideEncryptionConfigurationNotFoundError":
                has_enc = False
            else:
                log.debug("[s3] get_bucket_encryption %s: %s", bname, exc)
                has_enc = True  # unknown → don't flag

        if has_enc:
            continue

        try:
            # type: ignore[call-arg]
            config.WRITE_ROW(
                writer=writer,
                resource_id=bname,
                name=bname,
                owner_id=config.ACCOUNT_ID,  # type: ignore[arg-type]
                resource_type="S3Bucket",
                estimated_cost=0.0,
                potential_saving=0.0,
                flags=["S3BucketNoDefaultEncryption"],
                confidence=100,
                signals=_signals_str(
                    {
                        "Region": cw_region,
                        "Bucket": bname,
                        "CreatedAt": _to_utc_iso(created),
                        "SSEAlgorithm": enc_algo or "",
                    }
                ),
            )
        except Exception as exc:  # pylint: disable=broad-except
            log.warning("[check_s3_buckets_without_default_encryption] write_row %s: %s", bname, exc)

        log.info("[check_s3_buckets_without_default_encryption] Wrote: %s", bname)


# -------- 3) Versioning enabled but no lifecycle (cost growth risk) ----- #

@retry_with_backoff(exceptions=(ClientError,))
def check_s3_versioned_without_lifecycle(  # pylint: disable=unused-argument
    *args,
    logger: Optional[logging.Logger] = None,
    **kwargs,
) -> None:
    """
    Flag buckets with versioning enabled but without lifecycle config.
    """
    log = _logger(kwargs.get("logger") or logger)

    try:
        writer, s3, cloudwatch = _extract_writer_s3_cw(args, kwargs)  # cloudwatch unused
    except TypeError as exc:
        log.warning("[check_s3_versioned_without_lifecycle] Skipping: %s", exc)
        return
    if not (config.ACCOUNT_ID and config.WRITE_ROW):
        log.warning("[check_s3_versioned_without_lifecycle] Skipping: checker config.")
        return

    cw_region = getattr(getattr(cloudwatch, "meta", None), "region_name", "") or ""
    buckets = _list_buckets_in_region(s3, cw_region, log)
    if not buckets:
        return

    for bname, created in buckets:
        ver = {}
        try:
            ver = s3.get_bucket_versioning(Bucket=bname) or {}
        except ClientError as exc:
            log.debug("[s3] get_bucket_versioning %s: %s", bname, exc)
            continue

        if (ver.get("Status") or "").upper() != "ENABLED":
            continue

        has_lc = True
        try:
            lc = s3.get_bucket_lifecycle_configuration(Bucket=bname)
            rules = lc.get("Rules", []) or []
            has_lc = bool(rules)
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code == "NoSuchLifecycleConfiguration":
                has_lc = False
            else:
                log.debug("[s3] get_bucket_lifecycle_configuration %s: %s", bname, exc)
                has_lc = True

        if has_lc:
            continue

        try:
            # type: ignore[call-arg]
            config.WRITE_ROW(
                writer=writer,
                resource_id=bname,
                name=bname,
                owner_id=config.ACCOUNT_ID,  # type: ignore[arg-type]
                resource_type="S3Bucket",
                estimated_cost=0.0,
                potential_saving=0.0,
                flags=["S3BucketVersionedNoLifecycle"],
                confidence=100,
                signals=_signals_str(
                    {"Region": cw_region, "Bucket": bname, "CreatedAt": _to_utc_iso(created)}
                ),
            )
        except Exception as exc:  # pylint: disable=broad-except
            log.warning("[check_s3_versioned_without_lifecycle] write_row %s: %s", bname, exc)

        log.info("[check_s3_versioned_without_lifecycle] Wrote: %s", bname)


# --------------- 4) Any bucket without lifecycle configuration ---------- #

@retry_with_backoff(exceptions=(ClientError,))
def check_s3_buckets_without_lifecycle(  # pylint: disable=unused-argument
    *args,
    logger: Optional[logging.Logger] = None,
    **kwargs,
) -> None:
    """Flag buckets that have no lifecycle configuration at all."""
    log = _logger(kwargs.get("logger") or logger)

    try:
        writer, s3, cloudwatch = _extract_writer_s3_cw(args, kwargs)  # cloudwatch unused
    except TypeError as exc:
        log.warning("[check_s3_buckets_without_lifecycle] Skipping: %s", exc)
        return
    if not (config.ACCOUNT_ID and config.WRITE_ROW):
        log.warning("[check_s3_buckets_without_lifecycle] Skipping: checker config.")
        return

    cw_region = getattr(getattr(cloudwatch, "meta", None), "region_name", "") or ""
    buckets = _list_buckets_in_region(s3, cw_region, log)
    if not buckets:
        return

    for bname, created in buckets:
        has_lc = True
        try:
            lc = s3.get_bucket_lifecycle_configuration(Bucket=bname)
            has_lc = bool(lc.get("Rules", []) or [])
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code == "NoSuchLifecycleConfiguration":
                has_lc = False
            else:
                log.debug("[s3] get_bucket_lifecycle_configuration %s: %s", bname, exc)
                has_lc = True

        if has_lc:
            continue

        try:
            # type: ignore[call-arg]
            config.WRITE_ROW(
                writer=writer,
                resource_id=bname,
                name=bname,
                owner_id=config.ACCOUNT_ID,  # type: ignore[arg-type]
                resource_type="S3Bucket",
                estimated_cost=0.0,
                potential_saving=0.0,
                flags=["S3BucketNoLifecycle"],
                confidence=100,
                signals=_signals_str(
                    {"Region": cw_region, "Bucket": bname, "CreatedAt": _to_utc_iso(created)}
                ),
            )
        except Exception as exc:  # pylint: disable=broad-except
            log.warning("[check_s3_buckets_without_lifecycle] write_row %s: %s", bname, exc)

        log.info("[check_s3_buckets_without_lifecycle] Wrote: %s", bname)


# ------------------- 5) Empty buckets (0 bytes / 0 objects) ------------- #

@retry_with_backoff(exceptions=(ClientError,))
def check_s3_empty_buckets(  # pylint: disable=unused-argument
    *args,
    logger: Optional[logging.Logger] = None,
    **kwargs,
) -> None:
    """
    Flag buckets with 0 objects and 0 storage, based on CloudWatch daily storage
    metrics (BucketSizeBytes, NumberOfObjects). No direct saving, but cleanup
    is recommended.
    """
    log = _logger(kwargs.get("logger") or logger)

    try:
        writer, s3, cloudwatch = _extract_writer_s3_cw(args, kwargs)
    except TypeError as exc:
        log.warning("[check_s3_empty_buckets] Skipping: %s", exc)
        return
    if not (config.ACCOUNT_ID and config.WRITE_ROW):
        log.warning("[check_s3_empty_buckets] Skipping: checker config.")
        return

    cw_region = getattr(getattr(cloudwatch, "meta", None), "region_name", "") or ""
    buckets = _list_buckets_in_region(s3, cw_region, log)
    if not buckets:
        return

    types = ["StandardStorage"]
    id_map: Dict[str, Dict[str, str]] = {}
    results: Dict[str, Any] = {}
    metrics_ok = True

    try:
        cw = CloudWatchBatcher(region=cw_region, client=cloudwatch)
        for bname, _created in buckets:
            id_map[bname] = _cw_add_storage_queries(cw, bname, types)
        # S3 storage metrics are daily. Look back ~3 days for a stable point.
        end = datetime.now(timezone.utc).replace(microsecond=0)
        start = end - timedelta(days=3)
        results = cw.execute(start=start, end=end)
    except ClientError as exc:
        log.warning("[check_s3_empty_buckets] CloudWatch metrics unavailable: %s", exc)
        metrics_ok = False
    except Exception as exc:  # pylint: disable=broad-except
        log.warning("[check_s3_empty_buckets] CloudWatch batch error: %s", exc)
        metrics_ok = False

    if not metrics_ok:
        return

    for bname, created in buckets:
        ids = id_map.get(bname, {})
        size_last = _last_from_result(results.get(ids.get("StandardStorage")))
        obj_last = _last_from_result(results.get(ids.get("__NumberOfObjects__")))
        if float(size_last) <= 0.0 and float(obj_last) <= 0.0:
            try:
                # type: ignore[call-arg]
                config.WRITE_ROW(
                    writer=writer,
                    resource_id=bname,
                    name=bname,
                    owner_id=config.ACCOUNT_ID,  # type: ignore[arg-type]
                    resource_type="S3Bucket",
                    estimated_cost=0.0,
                    potential_saving=0.0,
                    flags=["S3BucketEmpty"],
                    confidence=100,
                    signals=_signals_str(
                        {
                            "Region": cw_region,
                            "Bucket": bname,
                            "CreatedAt": _to_utc_iso(created),
                            "Objects": int(obj_last),
                            "Bytes": int(size_last),
                        }
                    ),
                )
            except Exception as exc:  # pylint: disable=broad-except
                log.warning("[check_s3_empty_buckets] write_row %s: %s", bname, exc)

            log.info("[check_s3_empty_buckets] Wrote: %s", bname)


# --------- 6) IA / Archive tiering candidates (low requests) ------------ #

@retry_with_backoff(exceptions=(ClientError,))
def check_s3_ia_tiering_candidates(  # pylint: disable=unused-argument
    *args,
    logger: Optional[logging.Logger] = None,
    lookback_days: int = 30,
    min_standard_gb: float = 50.0,
    request_threshold: int = 1000,
    conservative_ratio: float = 0.5,
    **kwargs,
) -> None:
    """
    Suggest moving cold data to cheaper tiers when StandardStorage is large but
    requests are low.

    Heuristic saving:
      potential_saving = StandardGB * (STANDARD - STANDARD_IA) * conservative_ratio
    """
    log = _logger(kwargs.get("logger") or logger)

    try:
        writer, s3, cloudwatch = _extract_writer_s3_cw(args, kwargs)
    except TypeError as exc:
        log.warning("[check_s3_ia_tiering_candidates] Skipping: %s", exc)
        return
    if not (config.ACCOUNT_ID and config.WRITE_ROW and config.GET_PRICE):
        log.warning("[check_s3_ia_tiering_candidates] Skipping: checker config.")
        return

    cw_region = getattr(getattr(cloudwatch, "meta", None), "region_name", "") or ""
    buckets = _list_buckets_in_region(s3, cw_region, log)
    if not buckets:
        return

    types = ["StandardStorage", "StandardIAStorage", "GlacierInstantRetrievalStorage"]
    id_map: Dict[str, Dict[str, str]] = {}
    results: Dict[str, Any] = {}
    metrics_ok = True

    try:
        cw = CloudWatchBatcher(region=cw_region, client=cloudwatch)
        for bname, _created in buckets:
            ids = _cw_add_storage_queries(cw, bname, types)
            # Request metrics (if enabled) per bucket
            qid_req = f"s3_req_{bname}"
            dims_req = [("BucketName", bname), ("FilterId", "EntireBucket")]
            cw.add_q(
                id_hint=qid_req,
                namespace="AWS/S3",
                metric="AllRequests",
                dims=dims_req,
                stat="Sum",
                period=3600,
            )
            ids["__AllRequests__"] = qid_req
            id_map[bname] = ids

        end = datetime.now(timezone.utc).replace(microsecond=0)
        start = end - timedelta(days=lookback_days)
        results = cw.execute(start=start, end=end)
    except ClientError as exc:
        log.warning("[check_s3_ia_tiering_candidates] CloudWatch metrics unavailable: %s", exc)
        metrics_ok = False
    except Exception as exc:  # pylint: disable=broad-except
        log.warning("[check_s3_ia_tiering_candidates] CloudWatch batch error: %s", exc)
        metrics_ok = False

    if not metrics_ok:
        return

    price_std = config.safe_price("S3", "STANDARD_GB_MONTH", 0.023)
    price_ia = config.safe_price("S3", "STANDARD_IA_GB_MONTH", 0.0125)

    for bname, created in buckets:
        ids = id_map.get(bname, {})
        std_bytes = _last_from_result(results.get(ids.get("StandardStorage")))
        req_sum = 0.0
        # Request metrics might be missing (not enabled). Treat as high to avoid FPs.
        if ids.get("__AllRequests__") in results:
            req_series = results.get(ids.get("__AllRequests__"))
            if isinstance(req_series, list):
                req_sum = sum(float(v) for _, v in req_series)
            elif isinstance(req_series, dict):
                vals = req_series.get("Values") or req_series.get("values") or []
                req_sum = float(sum(vals))

        std_gb = _bytes_to_gb(std_bytes)
        if std_gb < float(min_standard_gb) or req_sum > float(request_threshold):
            continue

        est_cost = std_gb * price_std
        potential = std_gb * max(0.0, price_std - price_ia) * float(conservative_ratio)

        signals = _signals_str(
            {
                "Region": cw_region,
                "Bucket": bname,
                "CreatedAt": _to_utc_iso(created),
                "StandardGB": round(std_gb, 3),
                "AllRequestsSum": int(req_sum),
                "LookbackDays": lookback_days,
                "ConservativeRatio": conservative_ratio,
            }
        )

        try:
            # type: ignore[call-arg]
            config.WRITE_ROW(
                writer=writer,
                resource_id=bname,
                name=bname,
                owner_id=config.ACCOUNT_ID,  # type: ignore[arg-type]
                resource_type="S3Bucket",
                estimated_cost=est_cost,
                potential_saving=potential,
                flags=["S3BucketIATieringCandidate"],
                confidence=100,
                signals=signals,
            )
        except Exception as exc:  # pylint: disable=broad-except
            log.warning("[check_s3_ia_tiering_candidates] write_row %s: %s", bname, exc)

        log.info("[check_s3_ia_tiering_candidates] Wrote: %s", bname)


# ---------------- 7) Stale multipart uploads (storage leak) -------------- #

@retry_with_backoff(exceptions=(ClientError,))
def check_s3_stale_multipart_uploads(  # pylint: disable=unused-argument
    *args,
    logger: Optional[logging.Logger] = None,
    stale_days: int = 7,
    **kwargs,
) -> None:
    """
    Flag buckets with multipart uploads initiated before 'stale_days' and not
    completed. Size is unknown via ListMultipartUploads, so we report counts.
    """
    log = _logger(kwargs.get("logger") or logger)

    try:
        writer, s3, cloudwatch = _extract_writer_s3_cw(args, kwargs)  # cloudwatch unused
    except TypeError as exc:
        log.warning("[check_s3_stale_multipart_uploads] Skipping: %s", exc)
        return
    if not (config.ACCOUNT_ID and config.WRITE_ROW):
        log.warning("[check_s3_stale_multipart_uploads] Skipping: checker config.")
        return

    cw_region = getattr(getattr(cloudwatch, "meta", None), "region_name", "") or ""
    buckets = _list_buckets_in_region(s3, cw_region, log)
    if not buckets:
        return

    cutoff = datetime.now(timezone.utc) - timedelta(days=stale_days)

    for bname, created in buckets:
        key_marker = None
        upload_marker = None
        stale_count = 0

        while True:
            try:
                params: Dict[str, Any] = {"Bucket": bname}
                if key_marker:
                    params["KeyMarker"] = key_marker
                if upload_marker:
                    params["UploadIdMarker"] = upload_marker
                resp = s3.list_multipart_uploads(**params)
            except ClientError as exc:
                code = exc.response.get("Error", {}).get("Code")
                if code in {"NoSuchUpload", "NoSuchBucket"}:
                    break
                log.debug("[s3] list_multipart_uploads %s: %s", bname, exc)
                break

            uploads = resp.get("Uploads", []) or []
            for up in uploads:
                init = up.get("Initiated")
                if isinstance(init, datetime):
                    init_utc = init if init.tzinfo else init.replace(tzinfo=timezone.utc)
                    if init_utc < cutoff:
                        stale_count += 1

            if not resp.get("IsTruncated"):
                break
            key_marker = resp.get("NextKeyMarker")
            upload_marker = resp.get("NextUploadIdMarker")

        if stale_count <= 0:
            continue

        try:
            # type: ignore[call-arg]
            config.WRITE_ROW(
                writer=writer,
                resource_id=bname,
                name=bname,
                owner_id=config.ACCOUNT_ID,  # type: ignore[arg-type]
                resource_type="S3Bucket",
                estimated_cost=0.0,
                potential_saving=0.0,
                flags=["S3BucketStaleMultipartUploads"],
                confidence=100,
                signals=_signals_str(
                    {
                        "Region": cw_region,
                        "Bucket": bname,
                        "CreatedAt": _to_utc_iso(created),
                        "StaleUploads": stale_count,
                        "StaleDays": stale_days,
                    }
                ),
            )
        except Exception as exc:  # pylint: disable=broad-except
            log.warning("[check_s3_stale_multipart_uploads] write_row %s: %s", bname, exc)

        log.info("[check_s3_stale_multipart_uploads] Wrote: %s (%d stale)", bname, stale_count)
