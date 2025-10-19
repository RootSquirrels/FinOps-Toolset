"""Checker: Detached Network Interfaces (ENIs).

Scans EC2 for ENIs that are detached (i.e., have Status == "available" and no
Attachment) and writes them to the CSV 

"""

from __future__ import annotations

import logging
from typing import Callable, Optional
from botocore.exceptions import ClientError
import csv

from core.retry import retry_with_backoff

WriteRow = Callable[..., None]
GetPrice = Callable[[str, str], float]


@retry_with_backoff(exceptions=(ClientError,))
def check_detached_network_interfaces(
    ec2,
    account_id: str,
    write_row: WriteRow,
    writer: csv.writer,
    get_price_fn: GetPrice,
    logger: Optional[logging.Logger] = None,
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
    log = logger or logging.getLogger(__name__)
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

                    write_row(
                        writer=writer,
                        resource_id=eni_id,
                        name=tags.get("Name", ""),
                        owner_id=account_id,
                        resource_type="NetworkInterface",
                        estimated_cost=get_price_fn("ENI", "DETACHED_MONTH"),
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
