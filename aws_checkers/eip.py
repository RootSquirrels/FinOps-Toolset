"""Checker: Unused Elastic IPs (EIP)."""

from __future__ import annotations
from typing import Optional
import logging
import csv
from botocore.exceptions import ClientError
from core.retry import retry_with_backoff
from aws_checkers import config


def _safe_price(service: str, key: str) -> float:
    try:
        return float(config.GET_PRICE(service, key))  # type: ignore[arg-type]
    except Exception:  # pylint: disable=broad-except
        return 0.0


def _logger(fallback: Optional[logging.Logger]) -> logging.Logger:
    return fallback or config.LOGGER or logging.getLogger(__name__)


def _require_config() -> None:
    if not (config.ACCOUNT_ID and config.WRITE_ROW and config.GET_PRICE):
        raise RuntimeError(
            "Checkers not configured. Call "
            "finops_toolset.checkers.config.setup(account_id=..., write_row=..., get_price=..., logger=...) first."
        )


@retry_with_backoff(exceptions=(ClientError,))
def check_unused_elastic_ips(writer: csv.writer, ec2, 
    logger: Optional[logging.Logger] = None, **_kwargs) -> None:  # pylint: disable=unused-argument
    """
    Write all unassociated Elastic IPs to CSV.

    A public IP is 'unused' if it has neither InstanceId nor NetworkInterfaceId
    in ec2.describe_addresses().
    """
    _require_config()
    log = _logger(logger)

    try:
        resp = ec2.describe_addresses()
        for addr in resp.get("Addresses", []):
            rid = addr.get("AllocationId", addr.get("PublicIp"))
            unused = "InstanceId" not in addr and "NetworkInterfaceId" not in addr

            if unused:
                config.WRITE_ROW(  # type: ignore[call-arg]
                    writer=writer,
                    resource_id=rid,
                    name="",
                    owner_id=config.ACCOUNT_ID,  # type: ignore[arg-type]
                    resource_type="ElasticIP",
                    estimated_cost=_safe_price("EIP", "UNASSIGNED_MONTH"),
                    flags=["UnusedElasticIP"],
                    confidence=100,
                )

            log.info("[check_unused_elastic_ips] Processed IP: %s (unused=%s)", rid, unused)
    except ClientError as exc:
        log.error("Error checking Elastic IPs: %s", exc)
        raise
