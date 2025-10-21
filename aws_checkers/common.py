"""Common helpers for FinOps checkers (shared across AWS services).

Keeps modules DRY and silences pylint R0801:
- _logger: consistent logger selection with config fallback.
- _signals_str: "k=v" pipe-joined encoding for signals column.
- _to_utc_iso / _utc_iso_or_blank: safe UTC ISO8601 helpers for CSV dates.
- Tag helpers: _nonnull, tags_to_dict, pick_tag, tag_triplet.
- Concurrency helpers: _pool_size, _safe_workers, iter_chunks.
- Runtime helpers: _client_region, _ensure_setup, _extract_params.
- _write_row: normalized CSV writer wrapper using config.WRITE_ROW.

All functions are small and dependency-free; import what you need:
    from finops_toolset.checkers.common import (
        _logger, _signals_str, _to_utc_iso, _utc_iso_or_blank,
        tags_to_dict, tag_triplet, _safe_workers, iter_chunks,
        _client_region, _ensure_setup, _extract_params, _write_row
    )
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple, Mapping

from aws_checkers import config


def _logger(fallback: Optional[logging.Logger]) -> logging.Logger:
    """Return the given logger or a sensible default."""
    return fallback or config.LOGGER or logging.getLogger(__name__)


def _signals_str(pairs: Dict[str, object]) -> str:
    """Encode a small dict of details as 'k=v' joined by pipes, skipping blanks."""
    items: List[str] = []
    for k, v in pairs.items():
        if v is None or v == "":
            continue
        items.append(f"{k}={v}")
    return "|".join(items)


def _client_region(client) -> str:
    return getattr(getattr(client, "meta", None), "region_name", "") or ""


def _to_utc_iso(dt_obj: Optional[datetime]) -> Optional[str]:
    """Return datetime as UTC ISO8601 (no microseconds), or None if not a datetime."""
    if not isinstance(dt_obj, datetime):
        return None
    if dt_obj.tzinfo is None:
        dt_obj = dt_obj.replace(tzinfo=timezone.utc)
    else:
        dt_obj = dt_obj.astimezone(timezone.utc)
    return dt_obj.replace(microsecond=0).isoformat()


def _nonnull(s: Optional[str]) -> str:
    """Return 'NULL' for falsy strings (used for tag columns)."""
    return "NULL" if not s else s


def _utc_iso_or_blank(dt_obj: Optional[datetime]) -> str:
    """Return UTC ISO string or empty string when datetime is missing."""
    val = _to_utc_iso(dt_obj)
    return "" if val is None else val


def tags_to_dict(pairs: Optional[List[Dict[str, str]]]) -> Dict[str, str]:
    """Convert AWS [{'Key','Value'}] into a plain dict; empty on errors."""
    out: Dict[str, str] = {}
    for t in pairs or []:
        k, v = t.get("Key"), t.get("Value")
        if k:
            out[str(k)] = "" if v is None else str(v)
    return out


def pick_tag(tags: Dict[str, str], keys: Iterable[str]) -> Optional[str]:
    """Fetch first matching tag value by trying several case-insensitive keys."""
    low = {k.lower(): v for k, v in tags.items()}
    for k in keys:
        v = low.get(str(k).lower())
        if v:
            return v
    return None


def tag_triplet(tags: Dict[str, str]) -> Tuple[str, str, str]:
    """Return (app_id, app, env) with 'NULL' fallbacks."""
    app_id = pick_tag(tags, ["app_id", "application_id", "app-id"])
    app = pick_tag(tags, ["app", "application", "service"])
    env = pick_tag(tags, ["environment", "env", "stage"])
    return _nonnull(app_id), _nonnull(app), _nonnull(env)


def _pool_size(client) -> int:
    """Best-effort read of the client HTTP pool size; default 10."""
    try:
        cfg = getattr(getattr(client, "meta", None), "config", None)
        val = getattr(cfg, "max_pool_connections", 10)
        return int(val) if val else 10
    except Exception:  # pylint: disable=broad-except
        return 10


def _safe_workers(client, requested: Optional[int]) -> int:
    """Pick a thread count <= pool size (minus small headroom)."""
    pool = _pool_size(client)
    target = requested if requested is not None else min(16, pool)
    return max(2, min(int(target), max(1, pool - 2)))


def iter_chunks(items: List[Any], n: int):
    """Yield size-n chunks from items; never yields empty or zero-sized chunks."""
    size = max(1, n)
    for i in range(0, len(items), size):
        yield items[i : i + size]


def _extract_params(
    args: Sequence[Any],
    kwargs: Mapping[str, Any],
    *,
    required: Sequence[str],
    optional: Sequence[str] = (),
) -> Tuple[Any, ...]:
    """
    Resolve positional/keyword arguments for checkers in a DRY fashion.

    Example:
        writer, ec2 = _extract_params(args, kwargs, required=("writer", "ec2"))
        writer, ec2, cloudwatch = _extract_params(
            args, kwargs, required=("writer", "ec2"), optional=("cloudwatch",)
        )
    """
    ordered_names: Tuple[str, ...] = tuple(required) + tuple(optional)

    # Too many positional args
    if len(args) > len(ordered_names):
        extras = args[len(ordered_names):]
        raise TypeError(
            f"Expected at most {len(ordered_names)} positional arguments "
            f"({', '.join(ordered_names)}), but got {len(args)}: {extras!r}"
        )

    # Unexpected kwargs
    unexpected = [k for k in kwargs if k not in ordered_names]
    if unexpected:
        raise TypeError(f"Got unexpected keyword argument(s): {', '.join(sorted(unexpected))}")

    values: Dict[str, Any] = {}
    for idx, name in enumerate(ordered_names):
        have_pos = idx < len(args)
        have_kw = name in kwargs

        # Same param provided twice (like Python would error)
        if have_pos and have_kw:
            raise TypeError(f"Got multiple values for argument '{name}'")

        if have_kw:
            values[name] = kwargs[name]
        elif have_pos:
            values[name] = args[idx]
        else:
            values[name] = None

    missing = [name for name in required if values.get(name) is None]
    if missing:
        expected = " and ".join(f"'{name}'" for name in required)
        got = ", ".join(f"{name}={values.get(name)!r}" for name in ordered_names)
        raise TypeError(f"Expected {expected} (got {got})")

    return tuple(values[name] for name in ordered_names)


def _normalize_flags(flags: Iterable[str] | str) -> List[str]:
    """Ensure flags are emitted as a list of non-empty strings."""
    if isinstance(flags, str):
        return [flags] if flags else []
    out: List[str] = []
    for flag in flags:
        if not flag:
            continue
        out.append(str(flag))
    return out


def _write_row(  # noqa: D401
    *,
    writer,
    resource_id: str,
    name: str,
    resource_type: str,
    region: str,
    flags: Iterable[str] | str,
    estimated_cost: float | str = 0.0,
    potential_saving: float | str | None = None,
    signals: Dict[str, object] | None = None,
    logger: Optional[logging.Logger] = None,
    confidence: Optional[int] = 100,
    # Optional CSV columns (safely defaulted)
    state: str = "",
    creation_date: str = "",
    storage_gb: float | str = 0.0,
    app_id: str = "NULL",
    app: str = "NULL",
    env: str = "NULL",
    referenced_in: str = "",
    object_count: int | str | None = "",
) -> None:
    """Unified CSV writer wrapper using config.WRITE_ROW."""
    log = _logger(logger)
    try:
        norm_flags = _normalize_flags(flags)
        # type: ignore[call-arg]
        config.WRITE_ROW(
            writer=writer,
            resource_id=resource_id,
            name=name,
            resource_type=resource_type,
            region=region,
            owner_id=config.ACCOUNT_ID,  # type: ignore[arg-type]
            state=state,
            creation_date=creation_date,
            storage_gb=storage_gb,
            estimated_cost=estimated_cost,
            app_id=app_id,
            app=app,
            env=env,
            referenced_in=referenced_in,
            flags=norm_flags,
            object_count=object_count if object_count is not None else "",
            potential_saving=potential_saving,
            confidence=confidence,
            signals=_signals_str(signals or {}),
        )
    except Exception as exc:  # pylint: disable=broad-except
        log.warning(f"[common] write_row failed for {resource_id}: {exc}")
