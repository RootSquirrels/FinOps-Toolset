"""
Contains up to date prices for services in AWS. Provide a way to get the price of each service
"""
# finops_toolset/pricing.py
from __future__ import annotations

from typing import Dict, Union, Optional, Mapping
from finops_toolset.config import HOURS_PER_MONTH

Number = float
PriceLeaf = Union[Number, Mapping[str, Number]]
PriceMap = Dict[str, Dict[str, PriceLeaf]]


# --------------------------------------------------------------------------------------
# CENTRALIZED PRICING (USD)
# Notes:
# - Region overrides are optional; if missing, "default" is used.
# --------------------------------------------------------------------------------------
PRICING: PriceMap = {
    "EBS": {
        "GP2_GB_MONTH": 0.10,
        "GP3_GB_MONTH": 0.08,
        "IO1_GB_MONTH": 0.125,
        "IO2_GB_MONTH": 0.125,
        "ST1_GB_MONTH": 0.045,
        "SC1_GB_MONTH": 0.025,
        "MAGNETIC_GB_MONTH": 0.05,
        "IO1_IOPS_MONTH": 0.065,
        "IO2_IOPS_MONTH": 0.0625,
        "GP3_IOPS_MONTH": 0.005,
        "GP3_THROUGHPUT_MBPS_MONTH": 0.04,
        "SNAPSHOT_STANDARD_GB_MONTH": 0.05,
        "SNAPSHOT_ARCHIVE_GB_MONTH": 0.0125,
    },

    "EIP": {
        # New (Feb 1, 2024): $0.005 per public IPv4 per hour whether attached or idle.
        "IP_HOUR": 0.005,
        "UNASSIGNED_MONTH": 3.65,
    },

    "S3": {
        "STANDARD_GB_MONTH": 0.023,
        "STANDARD_IA_GB_MONTH": 0.0125,
        "ONEZONE_IA_GB_MONTH": 0.01,
        "GLACIER_IR_GB_MONTH": 0.004,
        "GLACIER_GB_MONTH": 0.0036,
        "GLACIER_DEEP_GB_MONTH": 0.00099,
        # Optional request-cost modelling if you ever want it:
        # "PUT_1K": 0.005, "GET_1K": 0.0004,
    },

    "EFS": {
        "EFS_STANDARD_GB_MONTH": 0.25,
        "EFS_IA_GB_MONTH": 0.025,
        "ARCHIVE_GB_MONTH": 0.008,
        "IO_GB": 0.05,
        "MOUNT_TARGET_HOUR": 0.015,
        "PROV_TPUT_MIBPS_MONTH": 6.0,
        "IA_RETRIEVAL_GB": 0.01,
    },

    "LAMBDA": {
        # Requests: $0.20 per 1M; compute: $0.0000166667 per GB-second
        "REQUESTS_PER_MILLION": 0.20,
        "GB_SECOND": 0.0000166667,
        "EPHEMERAL_GB_SECOND": 0.0000000309,
        "PROVISIONED_CONCURRENCY_GB_SECOND": 0.0000041667,
    },

    "DynamoDB": {
        "STORAGE_GB_MONTH": 0.25,       
        "STORAGE_IA_GB_MONTH": 0.10,    
        "PROV_RCU_HR": 0.00013,
        "PROV_WCU_HR": 0.00065,
        "PITR_GB_MONTH": 0.20,
    },

    "CLOUDWATCH": {
        "LOG_GB_MONTH": 0.03,       # log storage per GB-month
        "LOG_INGEST_GB": 0.50,      # common ingest baseline (region varies a bit)
        # (Logs Insights per-GB-scanned exists but we omit)
    },

    "NATGateway": {
        "NATGW_MONTH": 32.85,  # ≈ $0.045/h * 730h
        "NATGW_DATA_GB": 0.045
    },

    "ALB": {
        "HOUR": {
            "default": 0.0225,
            "eu-west-1": 0.0225,
            "eu-west-3": 0.0225,
        },
        "LCU_HOUR": {
            "default": 0.008,
            "eu-west-1": 0.008,
            "eu-west-3": 0.008,
        },
    },

    "NLB": {
        "HOUR": {
            "default": 0.0225,
            "eu-west-1": 0.0225,
            "eu-west-3": 0.0225,
        },
        "NLCU_HOUR": {
            "default": 0.006,
            "eu-west-1": 0.006,
            "eu-west-3": 0.006,
        },
    },

    "CLB": {
        "HOUR": {
            "default": 0.0225,
            "eu-west-1": 0.0225,
        }
    },

    "NETWORK": {
        # Handy baseline for cross-region data transfer (directional, depends on pair).
        "INTER_REGION_GB": 0.02,
    },

    "ECR": {
        "STORAGE_GB_MONTH": 0.10,
    },

    "RDS": {
        # Automated backup storage (beyond free quota ~= size of DB)
        "BACKUP_GB_MONTH": 0.095,
    },

    "EKS": {
        # Control plane cost depends on support window. Default here reflects "standard support".
        "CONTROL_PLANE_HOUR": 0.10,
        "CONTROL_PLANE_HOUR_EXTENDED": 0.60,  # when the cluster version is in extended support
    },

    "KINESIS": {
        # Provisioned shards (baseline). Region variations exist; default fits many examples.
        "STREAM_SHARD_MONTH": 10.95
    },

    "WAFV2": {
        # WebACL + rules + request-charge exist; we only track WebACL flat monthly by default.
        "WEBACL_MONTH": 5.00
    },

    "SSM": {
        # Advanced parameter monthly fee. (Standard is free; API request costs omitted here.)
        "ADV_PARAM_MONTH": 0.05,
        "SSMParameter": 0.0,
        "PLAINTEXT_MONTH": 0.0
    },

    "SSMMaintenanceWindow":{
        "NO_TARGETS_MONTH": 0.0,
        "NO_TASKS_MONTH": 0.0
    },

    "FSX": {
        "BACKUP_GB_MONTH": 0.05
    },
    "ENI": {
        "DETACHED_MONTH": 0.0
    },
    "ACMPCA": {
        # Private CA monthly fee per CA (root or subordinate). Charged until deleted.
        "ACTIVE_MONTH": 400.00,
        "DISABLED_MONTH": 400.00,
        "EXPIRED_MONTH": 400.00,
        "FAILED_MONTH": 0.00,           # creation failed / unusable
        "PENDING_CERT_MONTH": 400.00,   # created but waiting on cert still accrues
        # optional future key if you ever count issuance: "CERT_ISSUANCE_EACH": 0.75,
    },
    "KMS": {
        # Customer-managed key monthly fee
        "CMK_MONTH": 1.00,
        # optional: "MULTI_REGION_CMK_MONTH": 2.00,
    },
    "AWSBackup": {
        # Warm/cold storage per GB-month (ballpark)
        "BACKUP_WARM_GB_MONTH": 0.05,
        "BACKUP_COLD_GB_MONTH": 0.01,
    },
    "CloudFront": {
        "REQUESTS_1M": 0.65,
        "DATA_OUT_GB": 0.085,

    },
}

# --------------------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------------------
def _pick_region_value(leaf: PriceLeaf, region: Optional[str]) -> Number:
    """
    Resolve a price leaf:
    - If it's a number, return it.
    - If it's a dict of region->price, try region, else 'default', else raise.
    """
    if isinstance(leaf, (int, float)):
        return float(leaf)
    if not isinstance(leaf, Mapping):
        raise KeyError(f"Invalid price leaf: {leaf}")
    if region and region in leaf:
        return float(leaf[region])  # type: ignore[index]
    if "default" in leaf:
        return float(leaf["default"])  # type: ignore[index]
    # Fallback: single-value dict? pick first numeric
    for v in leaf.values():
        if isinstance(v, (int, float)):
            return float(v)
    raise KeyError(f"No price for region={region} and no default in leaf {leaf}")

def get_price(service: str, key: str, region: Optional[str] = None) -> Number:
    """
    Region-aware price resolver:
      - Looks up PRICING[service][key]
      - If that value is a number => return it
      - If that value is a dict => try region, else 'default', else first numeric
    Raises KeyError if missing.
    """
    svc = PRICING.get(service)
    if not svc:
        raise KeyError(f"Unknown service '{service}'")
    if key not in svc:
        raise KeyError(f"Unknown price key '{service}.{key}'")
    return _pick_region_value(svc[key], region)

def per_month(hourly: Number, hours_per_month: Number = HOURS_PER_MONTH) -> Number:
    """Utility: convert per-hour to per-month using your standard HOURS_PER_MONTH."""
    return float(hourly) * float(hours_per_month)

def get_eip_unassigned_month() -> Number:
    """
    Preserve your original UNASSIGNED_MONTH behavior but derive it from the canonical hourly.
    """
    try:
        return get_price("EIP", "UNASSIGNED_MONTH", None)
    except KeyError:
        return per_month(get_price("EIP", "IP_HOUR", None))
