"""
EIP module checker
"""
from typing import List
import csv
import logging
from botocore.exceptions import ClientError


@retry_with_backoff()
def check_unused_elastic_ips(writer: csv.writer, ec2) -> None:
    """
    Write all unassociated (unused) Elastic IPs in the account to a CSV.

    An Elastic IP is considered unused if it is not associated with either an
    EC2 instance (``InstanceId``) or a network interface (``NetworkInterfaceId``)
    in the response from ``describe_addresses``.

    Args:
        writer: A csv.writer-like object used by ``write_resource_to_csv``.
        ec2: A boto3 EC2 *client* with a ``describe_addresses()`` method.

    Side Effects:
        Appends one CSV row per unused Elastic IP via ``write_resource_to_csv``.

    Raises:
        ClientError: Propagated if the EC2 ``describe_addresses`` call fails.
    """
    try:
        resp = ec2.describe_addresses()
        for addr in resp.get("Addresses", []):
            resource_id_or_ip = addr.get("AllocationId", addr.get("PublicIp"))
            flags: List[str] = []

            # Unassociated if neither an instance nor a network interface is present
            if "InstanceId" not in addr and "NetworkInterfaceId" not in addr:
                flags.append("UnusedElasticIP")
                write_resource_to_csv(
                    writer=writer,
                    resource_id=resource_id_or_ip,
                    name="",
                    owner_id=ACCOUNT_ID,
                    resource_type="ElasticIP",
                    estimated_cost=get_price("EIP", "UNASSIGNED_MONTH"),
                    flags=flags,
                    confidence=100,
                )

            logging.info(
                "[check_unused_elastic_ips] Processed IP: %s",
                resource_id_or_ip,
            )
    except ClientError as exc:
        logging.error("Error checking Elastic IPs: %s", exc)
        # Optionally re-raise if you want callers to handle it:
        # raise