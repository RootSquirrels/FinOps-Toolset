"""Checker: Detached Network Interfaces (ENIs).

Scans EC2 for ENIs that are detached (i.e., have Status == "available" and no
Attachment) and writes them to the CSV 

"""

from __future__ import annotations

import logging
import csv
from typing import Optional
from botocore.exceptions import ClientError
from aws_checkers import config

from core.retry import retry_with_backoff


def _logger(fallback: Optional[logging.Logger]) -> logging.Logger:
    return fallback or config.LOGGER or logging.getLogger(__name__)


def _require_config() -> None:
    if not (config.ACCOUNT_ID and config.WRITE_ROW and config.GET_PRICE):
        raise RuntimeError(
            "Checkers not configured. Call "
            "aws_checkers.config.setup(account_id=..., " \
            "write_row=..., get_price=..., logger=...) first."
        )


@retry_with_backoff(exceptions=(ClientError,))
def check_detached_network_interfaces(
    ec2,
    account_id: str,
    writer: csv.writer,
    logger: Optional[logging.Logger] = None, **_kwargs # pylint: disable=unused-argument
) -> None:
    """
    Find detached (unassociated) Elastic Network Interfaces (ENIs) and write them to CSV.

    An ENI is considered detached if:
      - its ``Status`` is ``available`` AND
      - it has no ``Attachment`` object.

    Uses a paginator to cover all interfaces in large accounts. Errors are logged and
    then re-raised so the retry decorator can handle retries.

    Args:
        writer: csv.writer-like object passed through to ``write_row``.
        ec2: boto3 EC2 client.
        account_id: AWS Account ID used for the OwnerId field.
        write_row: CSV row writer (e.g., ``write_resource_to_csv``).
        get_price_fn: Pricing helper (e.g., ``get_price("ENI", "DETACHED_MONTH")``).
        logger: Optional logger; falls back to the module logger.

    Returns:
        None

    Raises:
        botocore.exceptions.ClientError: Re-raised after logging to enable retries.
    """

    _require_config()
    log = _logger(logger) or logging.getLogger(__name__)
    detached_count = 0

    try:
        paginator = ec2.get_paginator("describe_network_interfaces")
        for page in paginator.paginate():
            for eni in page.get("NetworkInterfaces", []):
                eni_id = eni.get("NetworkInterfaceId")
                status = eni.get("Status")
                is_attached = bool(eni.get("Attachment"))

                # Detached ENI (available + no attachment)
                if status == "available" and not is_attached:

                    tags = {tag["Key"]: tag["Value"] for tag in eni.get("TagSet", [])}

                    config.WRITE_ROW(
                        writer=writer,
                        resource_id=eni_id,
                        name=tags.get("Name", ""),
                        owner_id=account_id,
                        resource_type="NetworkInterface",
                        estimated_cost=config.GET_PRICE("ENI", "DETACHED_MONTH"),
                        flags=["DetachedNetworkInterface"],
                        confidence=100,
                    )
                    detached_count += 1

                log.info(
                    "[check_detached_network_interfaces] Processed ENI: %s (status=%s attached=%s)",
                    eni_id,
                    status,
                    is_attached,
                )

        log.debug(
            "[check_detached_network_interfaces] Detached ENIs written: %d",
            detached_count,
        )

    except ClientError as exc:
        log.error("Error checking detached network interfaces: %s", exc)
        raise
