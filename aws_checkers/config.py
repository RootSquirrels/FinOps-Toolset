"""Runtime config for checker modules (simple dependency injection)."""

from __future__ import annotations
from typing import Callable, Optional
import logging
from decimal import Decimal
from finops_toolset import pricing

ACCOUNT_ID: Optional[str] = None
WRITE_ROW: Optional[Callable[..., None]] = None
GET_PRICE: Optional[Callable[[str, str], float]] = getattr(pricing, "get_price", None)
LOGGER: Optional[logging.Logger] = None


def setup(
    *,
    account_id: str,
    write_row: Callable[..., None],
    get_price: Callable[[str, str], float],
    logger: Optional[logging.Logger] = None,
) -> None:
    """Provide shared dependencies to all checker modules."""
    # pylint: disable=global-statement
    global ACCOUNT_ID, WRITE_ROW, GET_PRICE, LOGGER
    ACCOUNT_ID = account_id
    WRITE_ROW = write_row
    GET_PRICE = get_price
    LOGGER = logger or logging.getLogger("aws_checkers")


def safe_price(service: str, key: str, default: float = 0.0) -> float:
    """
    Best-effort price lookup from your pricebook.

    Returns:
        The numeric price for (service, key), or `default` if GET_PRICE is not
        configured or lookup/parsing fails.
    """
    try:
        if GET_PRICE is None:
            return float(default)
        value = GET_PRICE(service, key)
        if isinstance(value, (int, float)):
            return float(value)
        if isinstance(value, Decimal):
            return float(value)
        # handle string-y numbers
        return float(value)  # type: ignore[arg-type]
    except Exception:  # pylint: disable=broad-except
        # Keep this quiet in normal runs; useful debug if a key is missing.
        if LOGGER:
            LOGGER.debug("safe_price fallback for %s.%s", service, key)
        return float(default)
