"""Runtime config for checker modules (simple dependency injection)."""

from __future__ import annotations
from typing import Callable, Optional
import logging

ACCOUNT_ID: Optional[str] = None
WRITE_ROW: Optional[Callable[..., None]] = None
GET_PRICE: Optional[Callable[[str, str], float]] = None
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
    LOGGER = logger or logging.getLogger("finops_toolset.checkers")
