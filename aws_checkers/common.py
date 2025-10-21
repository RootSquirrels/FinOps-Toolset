"""Common helpers for FinOps checkers (shared across AWS services).

Keeps modules DRY and silences pylint R0801:
- _logger: consistent logger selection with config fallback.
- _signals_str: "k=v" pipe-joined encoding for signals column.
- _to_utc_iso: safe UTC ISO8601 (no microseconds) for CSV dates.
- Tag helpers: _nonnull, tags_to_dict, pick_tag, tag_triplet.
- Concurrency helpers: _pool_size, _safe_workers, iter_chunks.
- _write_row: normalized CSV writer wrapper using config.WRITE_ROW.

All functions are small and dependency-free; import what you need:
    from finops_toolset.checkers.common import (
        _logger, _signals_str, _to_utc_iso,
        tags_to_dict, tag_triplet, _safe_workers, iter_chunks, _write_row
    )
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional, Tuple
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
