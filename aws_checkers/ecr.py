"""Checkers: Amazon ECR (Elastic Container Registry).

Includes three checks:
  - check_ecr_repositories_without_lifecycle_policy: repos missing lifecycle policy.
  - check_ecr_empty_repositories: repos with zero images.
  - check_ecr_stale_or_untagged_images: stale (by pushedAt) and untagged images; sums
    potential savings by image size * price per GB-month.

Design:
  - Dependencies (account_id, write_row, get_price, logger) are provided once via
    finops_toolset.checkers.config.setup(...).
  - Each checker is tolerant to how run_check passes args and will skip gracefully
    if a required client or config is missing.
  - Emits Flags, Signals (compact k=v pairs), Estimated_Cost_USD, Potential_Saving_USD.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, Iterable, List, Optional, Tuple

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


def _extract_writer_ecr(args: Tuple[Any, ...], kwargs: Dict[str, Any]) -> Tuple[Any, Any]:
    """Accept writer/ecr passed positionally or by keyword; prefer keywords."""
    writer = kwargs.get("writer", args[0] if len(args) >= 1 else None)
    ecr = kwargs.get("ecr", args[1] if len(args) >= 2 else None)
    if writer is None or ecr is None:
        raise TypeError("Expected 'writer' and 'ecr' (got writer=%r, ecr=%r)" % (writer, ecr))
    return writer, ecr


def _list_repositories(ecr, log: logging.Logger) -> List[Dict[str, Any]]:
    repos: List[Dict[str, Any]] = []
    try:
        next_token: Optional[str] = None
        while True:
            if next_token:
                resp = ecr.describe_repositories(nextToken=next_token)
            else:
                resp = ecr.describe_repositories()
            repos.extend(resp.get("repositories", [])
                         or resp.get("repositories", []) or resp.get("repositories", []))
            # boto3 returns 'nextToken' (lower camel) for ECR
            next_token = resp.get("nextToken")
            if not next_token:
                break
    except ClientError as exc:
        log.error("[ecr] describe_repositories failed: %s", exc)
    return repos


def _repo_image_counts(ecr, repo_name: str, log: logging.Logger) -> int:
    """Count images in a repository (best-effort)."""
    count = 0
    try:
        next_token: Optional[str] = None
        while True:
            params = {"repositoryName": repo_name, "filter": {"tagStatus": "ANY"}}
            if next_token:
                params["nextToken"] = next_token
            resp = ecr.list_images(**params)
            count += len(resp.get("imageIds", []) or [])
            next_token = resp.get("nextToken")
            if not next_token:
                break
    except ClientError as exc:
        log.debug("[ecr] list_images failed for %s: %s", repo_name, exc)
    return count


def _iter_images(ecr, repo_name: str, *, tag_status: str, 
                 log: logging.Logger) -> Iterable[Dict[str, Any]]:
    """
    Yield imageDetails via describe_images(filter={'tagStatus': tag_status}).
    tag_status in {'TAGGED','UNTAGGED'}
    """
    next_token: Optional[str] = None
    while True:
        try:
            params = {"repositoryName": repo_name, "filter":
                      {"tagStatus": tag_status}, "maxResults": 1000}
            if next_token:
                params["nextToken"] = next_token
            resp = ecr.describe_images(**params)
            for img in resp.get("imageDetails", []) or []:
                yield img
            next_token = resp.get("nextToken")
            if not next_token:
                break
        except ClientError as exc:
            log.debug("[ecr] describe_images(%s) failed for %s: %s", tag_status, repo_name, exc)
            return


# ---------------------------- 1) lifecycle policy ------------------------ #

@retry_with_backoff(exceptions=(ClientError,))
def check_ecr_repositories_without_lifecycle_policy(  # pylint: disable=unused-argument
    *args,
    logger: Optional[logging.Logger] = None,
    **kwargs,
) -> None:
    """
    Flag ECR repositories that do not have a lifecycle policy.

    Flags:
      - ECRRepositoryNoLifecyclePolicy

    Notes:
      - Repos themselves aren't billed; we leave estimated_cost/potential_saving at 0.0.
    """
    log = _logger(kwargs.get("logger") or logger)

    try:
        writer, ecr = _extract_writer_ecr(args, kwargs)
    except TypeError as exc:
        log.warning("[ECR Lifecycle] Skipping: %s", exc)
        return
    if not _have_config():
        log.warning("[ECR Lifecycle] Skipping: checker config not provided.")
        return

    region = getattr(getattr(ecr, "meta", None), "region_name", "") or ""
    repos = _list_repositories(ecr, log)

    for r in repos:
        name = r.get("repositoryName") or ""
        arn = r.get("repositoryArn") or name

        has_policy = False
        try:
            _ = ecr.get_lifecycle_policy(repositoryName=name)
            has_policy = True
        except ClientError as exc:
            # if NotFound -> no policy; for AccessDenied, treat as unknown (skip flag)
            code = getattr(exc, "response", {}).get("Error", {}).get("Code")
            if code not in {"LifecyclePolicyNotFoundException", 
                            "RepositoryPolicyNotFoundException", "ResourceNotFoundException"}:
                log.debug("[ecr] get_lifecycle_policy error for %s: %s", name, exc)
                has_policy = True  # don't flag on permission issues

        if not has_policy:
            try:
                # type: ignore[call-arg]
                config.WRITE_ROW(
                    writer=writer,
                    resource_id=arn,
                    name=name,
                    owner_id=config.ACCOUNT_ID,  # type: ignore[arg-type]
                    resource_type="ECRRepository",
                    estimated_cost=0.0,
                    potential_saving=0.0,
                    flags=["ECRRepositoryNoLifecyclePolicy"],
                    confidence=100,
                    signals=_signals_str({"Region": region, "Repository": name}),
                )
            except Exception as exc:  # pylint: disable=broad-except
                log.warning("[ECR Lifecycle] write_row failed for %s: %s", name, exc)

        log.info("[ECR Lifecycle] Processed repo: %s (has_policy=%s)", name, has_policy)


# ---------------------------- 2) empty repositories ---------------------- #

@retry_with_backoff(exceptions=(ClientError,))
def check_ecr_empty_repositories(  # pylint: disable=unused-argument
    *args,
    logger: Optional[logging.Logger] = None,
    **kwargs,
) -> None:
    """
    Flag ECR repositories that currently contain zero images.

    Flags:
      - ECRRepositoryEmpty

    Notes:
      - Repo itself is free; we keep estimated_cost/potential_saving at 0.0.
    """
    log = _logger(kwargs.get("logger") or logger)

    try:
        writer, ecr = _extract_writer_ecr(args, kwargs)
    except TypeError as exc:
        log.warning("[check_ecr_empty_repositories] Skipping: %s", exc)
        return
    if not _have_config():
        log.warning("[check_ecr_empty_repositories] Skipping: checker config not provided.")
        return

    region = getattr(getattr(ecr, "meta", None), "region_name", "") or ""
    repos = _list_repositories(ecr, log)

    for r in repos:
        name = r.get("repositoryName") or ""
        arn = r.get("repositoryArn") or name
        count = _repo_image_counts(ecr, name, log)

        if count == 0:
            try:
                # type: ignore[call-arg]
                config.WRITE_ROW(
                    writer=writer,
                    resource_id=arn,
                    name=name,
                    owner_id=config.ACCOUNT_ID,  # type: ignore[arg-type]
                    resource_type="ECRRepository",
                    estimated_cost=0.0,
                    potential_saving=0.0,
                    flags=["ECRRepositoryEmpty"],
                    confidence=100,
                    signals=_signals_str({"Region": region, "Repository": name}),
                )
            except Exception as exc:  # pylint: disable=broad-except
                log.warning("[check_ecr_empty_repositories] write_row failed for %s: %s", name, exc)

        log.info("[check_ecr_empty_repositories] Processed repo: %s (images=%d)", name, count)


# --------------------- 3) stale or untagged images ---------------------- #

@retry_with_backoff(exceptions=(ClientError,))
def check_ecr_stale_or_untagged_images(  # pylint: disable=unused-argument
    *args,
    logger: Optional[logging.Logger] = None,
    stale_days: int = 90,
    min_size_bytes: int = 0,
    **kwargs,
) -> None:
    """
    Flag ECR images that are either:
      - Untagged; or
      - Tagged but 'stale' (imagePushedAt older than `stale_days`).

    For each flagged image, estimate monthly storage cost and treat as potential saving
    if the image were deleted.

    Flags:
      - ECRImageUntagged
      - ECRImageStale{Xd}
    """
    log = _logger(kwargs.get("logger") or logger)

    try:
        writer, ecr = _extract_writer_ecr(args, kwargs)
    except TypeError as exc:
        log.warning("[check_ecr_stale_or_untagged_images] Skipping: %s", exc)
        return
    if not _have_config():
        log.warning("[check_ecr_stale_or_untagged_images] Skipping: checker config not provided.")
        return

    region = getattr(getattr(ecr, "meta", None), "region_name", "") or ""
    cutoff = (datetime.now(timezone.utc) - timedelta(days=stale_days)).replace(microsecond=0)
    price_per_gb = config.safe_price("ECR", "STORAGE_GB_MONTH", default=0.10)

    repos = _list_repositories(ecr, log)

    for r in repos:
        repo = r.get("repositoryName") or ""
        if not repo:
            continue

        # 1) Untagged images
        for img in _iter_images(ecr, repo, tag_status="UNTAGGED", log=log):
            digest = img.get("imageDigest") or ""
            size = float(img.get("imageSizeInBytes") or 0)
            pushed = img.get("imagePushedAt")
            if size < float(min_size_bytes):
                continue

            gb = max(0.0, size / (1024 ** 3))
            est = gb * price_per_gb
            flags = ["ECRImageUntagged"]
            signals = _signals_str(
                {
                    "Region": region,
                    "Repository": repo,
                    "Digest": digest,
                    "Tags": "",  # untagged
                    "SizeGB": round(gb, 3),
                    "PushedAt": _to_utc_iso(pushed),
                }
            )

            try:
                # type: ignore[call-arg]
                config.WRITE_ROW(
                    writer=writer,
                    resource_id=f"{repo}@{digest}",
                    name=repo,
                    owner_id=config.ACCOUNT_ID,  # type: ignore[arg-type]
                    resource_type="ECRImage",
                    estimated_cost=est,
                    potential_saving=est,  # deleting frees storage
                    flags=flags,
                    confidence=100,
                    signals=signals,
                )
            except Exception as exc:  # pylint: disable=broad-except
                log.warning("[ECR Stale] write_row failed for %s@%s: %s", repo, digest, exc)

            log.info("[ecr] Untagged image: %s@%s size=%.3fGB", repo, digest, gb)

        # 2) Tagged but stale images
        for img in _iter_images(ecr, repo, tag_status="TAGGED", log=log):
            digest = img.get("imageDigest") or ""
            tags = img.get("imageTags") or []
            pushed = img.get("imagePushedAt")
            size = float(img.get("imageSizeInBytes") or 0)

            if not isinstance(pushed, datetime):
                continue
            pushed_utc = pushed if pushed.tzinfo else pushed.replace(tzinfo=timezone.utc)

            if pushed_utc >= cutoff:
                continue  # not stale
            if size < float(min_size_bytes):
                continue

            gb = max(0.0, size / (1024 ** 3))
            est = gb * price_per_gb
            flags = [f"ECRImageStale{stale_days}d"]

            # Emit
            signals = _signals_str(
                {
                    "Region": region,
                    "Repository": repo,
                    "Digest": digest,
                    "Tags": ",".join(tags),
                    "SizeGB": round(gb, 3),
                    "PushedAt": _to_utc_iso(pushed),
                    "StaleDays": stale_days,
                }
            )

            try:
                # type: ignore[call-arg]
                config.WRITE_ROW(
                    writer=writer,
                    resource_id=f"{repo}@{digest}",
                    name=f"{repo}:{tags[0]}" if tags else repo,
                    owner_id=config.ACCOUNT_ID,  # type: ignore[arg-type]
                    resource_type="ECRImage",
                    estimated_cost=est,
                    potential_saving=est,
                    flags=flags,
                    confidence=100,
                    signals=signals,
                )
            except Exception as exc:  # pylint: disable=broad-except
                log.warning("[ECR Stale] write_row failed for %s@%s: %s", repo, digest, exc)

            log.info("[ecr] Stale image: %s@%s size=%.3fGB", repo, digest, gb)
