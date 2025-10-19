"""
Retry decorator module
"""
from __future__ import annotations
import time
import random
from functools import wraps
from typing import Tuple, Type, Callable, Any, Optional


def retry_with_backoff(
    exceptions: Tuple[Type[BaseException], ...] = (Exception,),
    tries: int = 5,
    base_delay: float = 0.5,
    max_delay: float = 10.0,
    jitter: bool = True,
    logger: Optional[Any] = None,
) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    """
    Decorator to retry a function with exponential backoff and optional jitter. -> Used of jitter to avoid thundering herd 
    
    Args:
        max_retries (int): Maximum number of retries.
        backoff_factor (float): Multiplier for delay between retries.
        jitter (bool): Whether to add random jitter to delay.
        exceptions (tuple): Exceptions to catch and retry on.
    """
    def _decorate(func: Callable[..., Any]) -> Callable[..., Any]:
        @wraps(func)
        def _wrapped(*args: Any, **kwargs: Any) -> Any:
            attempt = 0
            delay = base_delay
            while True:
                try:
                    return func(*args, **kwargs)
                except exceptions as exc:  # pylint: disable=broad-except
                    attempt += 1
                    if attempt >= tries:
                        if logger:
                            logger.error("Retries exhausted for %s: %s", func.__name__, exc)
                        raise
                    sleep_for = min(delay, max_delay)
                    if jitter:
                        sleep_for += random.uniform(0, sleep_for / 2.0)
                    if logger:
                        logger.warning(
                            "Retrying %s in %.2fs (attempt %d/%d) due to: %s",
                            func.__name__, sleep_for, attempt, tries, exc
                        )
                    time.sleep(sleep_for)
                    delay *= 2.0
        return _wrapped
    return _decorate
