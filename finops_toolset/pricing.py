"""
Contains up to date prices for services in AWS. Provide a way to get the price of each service
"""
# finops_toolset/pricing.py
from __future__ import annotations

from typing import Dict, Union, Optional, Mapping

Number = float
PriceLeaf = Union[Number, Mapping[str, Number]]
PriceMap = Dict[str, Dict[str, PriceLeaf]]

from finops_toolset.config import HOURS_PER_MONTH  # default 730

# --------------------------------------------------------------------------------------
# CENTRALIZED PRICING (USD)
# Notes:
# - Region overrides are optional; if missing, "default" is used.
# --------------------------------------------------------------------------------------
PRICING: PriceMap = {
    "EBS": {
        # gp2/gp3 baseline examples from AWS docs (region-specific in reality).
        "SNAPSHOT_GB_MONTH": 0.06,
        "GP2_GB_MONTH": 0.10,
        "GP3_GB_MONTH": 0.08,
        "GP3_IOPS_PER_MONTH": 0.005,      
        "GP3_TPUT_MIBPS_MONTH": 0.04,     
        "FSR_PER_AZ_HOUR": 0.75,          
    },

    "EIP": {
        # New (Feb 1, 2024): $0.005 per public IPv4 per hour whether attached or idle.
        "IP_HOUR": 0.005,
        "UNASSIGNED_MONTH": 3.65,
    },

    "S3": {
        "STANDARD_GB_MONTH": 0.019,
        "STANDARD_IA_GB_MONTH": 0.0125,
        "GLACIER_GB_MONTH": 0.004,
    },

    "EFS": {
        "STANDARD_GB_MONTH": 0.25,
        "IA_GB_MONTH": 0.025,
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

    "DYNAMODB": {
        "RCU_HOUR": 0.00013,
        "WCU_HOUR": 0.00065,
        # On-demand mode per-request:
        "OD_RRU": 0.25 / 1_000_000,
        "OD_WRU": 1.25 / 1_000_000,   
        "STORAGE_GB_MONTH_STD": 0.25,
        "STORAGE_GB_MONTH_STD_IA": 0.10,
    },

    "CLOUDWATCH": {
        "LOG_GB_MONTH": 0.03,       # log storage per GB-month
        "LOG_INGEST_GB": 0.50,      # common ingest baseline (region varies a bit)
        # (Logs Insights per-GB-scanned exists but we omit)
    },

    "NAT": {
        "HOUR": {
            "default": 0.065,
            "eu-west-1": 0.065,
            "eu-west-3": 0.070,
        },
        "GB_PROCESSED": {
            "default": 0.045,
        },
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
        "SHARD_HOUR": 0.015
    },

    "WAFV2": {
        # WebACL + rules + request-charge exist; we only track WebACL flat monthly by default.
        "WEBACL_MONTH": 5.00
    },

    "SSM": {
        # Advanced parameter monthly fee. (Standard is free; API request costs omitted here.)
        "ADV_PARAM_MONTH": 0.05
    },

    "FSX": {
        "BACKUP_GB_MONTH": 0.05
    }
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
