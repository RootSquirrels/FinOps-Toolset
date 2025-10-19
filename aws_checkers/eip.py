"""
EIP module checker
"""

# finops_toolset/checkers/eip.py
from __future__ import annotations
from typing import Callable, Optional
import logging
from botocore.exceptions import ClientError
from core.retry import retry_with_backoff

# Type for the CSV row writer you already have (write_resource_to_csv)
WriteRow = Callable[..., None]
GetPrice = Callable[[str, str], float]


@retry_with_backoff(exceptions=(ClientError,))
def check_unused_elastic_ips(
    ec2,
    account_id: str,
    write_row: WriteRow,
    get_price_fn: GetPrice,
    logger: Optional[logging.Logger] = None,
) -> int:
    """
    Scan EC2 Elastic IP addresses and write unassociated ones to CSV.

    An Elastic IP is considered unused if it is not associated with either an
    EC2 instance (``InstanceId``) or a network interface (``NetworkInterfaceId``).

    Args:
        ec2: boto3 EC2 client with ``describe_addresses()``.
        account_id: AWS account ID used for the CSV's OwnerId field.
        write_row: Callable that writes one normalized CSV row (your existing
            ``write_resource_to_csv``).
        get_price_fn: Pricing helper, e.g. ``get_price("EIP", "UNASSIGNED_MONTH")``.
        logger: Optional logger; uses module logger if omitted.

    Returns:
        Number of unused Elastic IPs written to CSV.
    """
    log = logger or logging.getLogger(__name__)

    try:
        resp = ec2.describe_addresses()
        for addr in resp.get("Addresses", []):
            resource_id_or_ip = addr.get("AllocationId", addr.get("PublicIp"))

            if "InstanceId" not in addr and "NetworkInterfaceId" not in addr:
                write_row(
                    resource_id=resource_id_or_ip,
                    name="",
                    owner_id=account_id,
                    resource_type="ElasticIP",
                    estimated_cost=get_price_fn("EIP", "UNASSIGNED_MONTH"),
                    potential_saving=get_price_fn("EIP", "UNASSIGNED_MONTH"),
                    flags=["UnusedElasticIP"],
                    confidence=100,
                )

            log.info("[check_unused_elastic_ips] Processed IP: %s", resource_id_or_ip)
    except ClientError as exc:
        log.error("Error checking Elastic IPs: %s", exc)
