"""Checker: Detached Network Interfaces (ENI).

Finds ENIs that are detached (Status == "available" and no Attachment) and writes
them to CSV. This checker is tolerant to how `run_check` passes arguments: it accepts
positional, keyword, or mixed styles for (writer, ec2) without raising 'multiple values'
errors.

"""

from __future__ import annotations

import logging
from typing import Optional, Tuple, Any
from botocore.exceptions import ClientError

from core.retry import retry_with_backoff
from aws_checkers import config


def _require_config() -> None:
    if not (config.ACCOUNT_ID and config.WRITE_ROW and config.GET_PRICE):
        raise RuntimeError(
            "Checkers not configured. Call "
            "finops_toolset.checkers.config.setup(account_id=..., write_row=..., "
            "get_price=..., logger=...) first."
        )


def _logger(fallback: Optional[logging.Logger]) -> logging.Logger:
    return fallback or config.LOGGER or logging.getLogger(__name__)


def _safe_price(service: str, key: str) -> float:
    try:
        # type: ignore[arg-type]
        return float(config.GET_PRICE(service, key))  # pylint: disable=not-callable
    except Exception:  # pylint: disable=broad-except
        return 0.0


def _extract_writer_ec2(args: Tuple[Any, ...], kwargs: dict) -> Tuple[Any, Any]:
    """Accept writer/ec2 passed positionally or by keyword; prefer keywords."""
    writer = kwargs.get("writer", args[0] if len(args) >= 1 else None)
    ec2 = kwargs.get("ec2", args[1] if len(args) >= 2 else None)
    if writer is None or ec2 is None:
        raise TypeError(
            "check_detached_network_interfaces expected 'writer' and 'ec2' "
            f"(got writer={writer!r}, ec2={ec2!r})"
        )
    return writer, ec2


@retry_with_backoff(exceptions=(ClientError,))
def check_detached_network_interfaces(
    *args,
    logger: Optional[logging.Logger] = None,
    **kwargs,
) -> None:
    """
    Write detached ENIs to CSV.

    Detached definition:
      - ENI Status is 'available' AND
      - no 'Attachment' present.
    """
    _require_config()
    log = _logger(logger)

    writer, ec2 = _extract_writer_ec2(args, kwargs)

    try:
        paginator = ec2.get_paginator("describe_network_interfaces")
        for page in paginator.paginate():
            for eni in page.get("NetworkInterfaces", []):
                eni_id = eni.get("NetworkInterfaceId")
                status = eni.get("Status")
                is_attached = bool(eni.get("Attachment"))

                if status == "available" and not is_attached:
                    # type: ignore[call-arg]
                    config.WRITE_ROW(
                        writer=writer,
                        resource_id=eni_id,
                        name="",  # keep legacy: empty name
                        owner_id=config.ACCOUNT_ID,  # type: ignore[arg-type]
                        resource_type="NetworkInterface",
                        estimated_cost=_safe_price("ENI", "DETACHED_MONTH"),
                        flags=["DetachedNetworkInterface"],
                        confidence=100,
                    )

                log.info(
                    "[check_detached_network_interfaces] Processed ENI: %s (status=%s attached=%s)",
                    eni_id,
                    status,
                    is_attached,
                )
    except ClientError as exc:
        log.error("Error checking detached network interfaces: %s", exc)
        raise
