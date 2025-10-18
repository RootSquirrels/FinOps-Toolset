# finops_toolset/config.py
from __future__ import annotations
import os
from typing import Iterable, Set, Optional
from botocore.config import Config #type: ignore

# ---- Env helpers
def _env_str(key: str, default: str) -> str:
    v = os.getenv(key)
    return v if v is not None else default

def _env_int(key: str, default: int) -> int:
    try:
        return int(os.getenv(key, str(default)))
    except Exception:
        return default

def _env_float(key: str, default: float) -> float:
    try:
        return float(os.getenv(key, str(default)))
    except Exception:
        return default

def _env_bool(key: str, default: bool) -> bool:
    v = os.getenv(key)
    return default if v is None else v.strip().lower() in {"1", "true", "yes", "y"}

def _env_list(key: str, default: Iterable[str]) -> list[str]:
    v = os.getenv(key)
    return [s.strip() for s in v.split(",")] if v else list(default)

def _env_set(key: str, default: Iterable[str]) -> Set[str]:
    return set(_env_list(key, default))

# ---- SDK config
SDK_CONFIG = Config(
    retries={"max_attempts": 10, "mode": "standard"},
    connect_timeout=5, read_timeout=60,
    user_agent_extra="finops-toolset/1.0",
)

# ------------------------------------------------------------
# CONSTANTS (non-pricing)
# You can override any of these via env vars (documented inline).
# ------------------------------------------------------------

# Regions / outputs
REGIONS = _env_list("FINOPS_REGIONS", ["eu-west-1", "eu-west-2", "eu-west-3"])
OUTPUT_FILE = _env_str("FINOPS_OUTPUT_FILE", "cleanup_estimates.csv")
LOG_FILE = _env_str("FINOPS_LOG_FILE", "cleanup_analysis.log")
BATCH_SIZE = _env_int("FINOPS_BATCH_SIZE", 100)
REQUIRED_TAG_KEYS = _env_list("FINOPS_REQUIRED_TAG_KEYS", ["ApplicationID", "Application", "Environment"])

# S3 multipart
_S3_MPU_BUCKET_WORKERS: int      = _env_int("FINOPS_S3_MPU_BUCKET_WORKERS", 16)
_S3_MPU_PART_WORKERS: int        = _env_int("FINOPS_S3_MPU_PART_WORKERS", 8)
_S3_MPU_PAGE_SIZE: int           = _env_int("FINOPS_S3_MPU_PAGE_SIZE", 1000)
_S3_MPU_GLOBAL_FINDINGS_CAP: int = _env_int("FINOPS_S3_MPU_GLOBAL_FINDINGS_CAP", 5000)
_S3_MPU_PARTS_MODE: str          = _env_str("FINOPS_S3_MPU_PARTS_MODE", "first_page")  # "first_page" | "full"

# --- DynamoDB thresholds ---
DDB_LOOKBACK_DAYS = _env_int("FINOPS_DDB_LOOKBACK_DAYS", 30)
DDB_CW_PERIOD = _env_int("FINOPS_DDB_CW_PERIOD", 86400)  # 1 day
DDB_BACKUP_AGE_DAYS = _env_int("FINOPS_DDB_BACKUP_AGE_DAYS", 180)

# --- EFS thresholds ---
EFS_LOOKBACK_DAYS = _env_int("FINOPS_EFS_LOOKBACK_DAYS", 30)
EFS_IA_LARGE_THRESHOLD_GB = _env_float("FINOPS_EFS_IA_LARGE_THRESHOLD_GB", 100.0)
EFS_IA_READS_HIGH_GB_PER_DAY = _env_float("FINOPS_EFS_IA_READS_HIGH_GB_PER_DAY", 1.0)
EFS_IDLE_THRESHOLD_GB_PER_DAY = _env_float("FINOPS_EFS_IDLE_THRESHOLD_GB_PER_DAY", 0.05)
EFS_STANDARD_THRESHOLD_GB = _env_float("FINOPS_EFS_STANDARD_THRESHOLD_GB", 50.0)
EFS_STANDARD_ARCHIVE_THRESHOLD_GB = _env_float("FINOPS_EFS_STANDARD_ARCHIVE_THRESHOLD_GB", 1000.0)
EFS_BURST_CREDIT_LOW_WATERMARK = _env_float("FINOPS_EFS_BURST_CREDIT_LOW_WATERMARK", 1e6)
HOURS_PER_MONTH = _env_int("FINOPS_HOURS_PER_MONTH", 730)

# --- Lambda thresholds ---
LAMBDA_LOOKBACK_DAYS = _env_int("FINOPS_LAMBDA_LOOKBACK_DAYS", 90)
LAMBDA_ERROR_RATE_THRESHOLD = _env_float("FINOPS_LAMBDA_ERROR_RATE_THRESHOLD", 0.10)
LAMBDA_LOW_CONCURRENCY_THRESHOLD = _env_float("FINOPS_LAMBDA_LOW_CONCURRENCY_THRESHOLD", 0.1)
LAMBDA_LOW_TRAFFIC_THRESHOLD = _env_int("FINOPS_LAMBDA_LOW_TRAFFIC_THRESHOLD", 50)
LAMBDA_LARGE_PACKAGE_MB = _env_int("FINOPS_LAMBDA_LARGE_PACKAGE_MB", 50)
LAMBDA_LOW_PROVISIONED_UTILIZATION = _env_float("FINOPS_LAMBDA_LOW_PROVISIONED_UTILIZATION", 0.2)
LAMBDA_VERSION_SPRAWL_THRESHOLD = _env_int("FINOPS_LAMBDA_VERSION_SPRAWL_THRESHOLD", 10)

# --- VPC peering thresholds ---
VPC_LOOKBACK_DAYS = _env_int("FINOPS_VPC_LOOKBACK_DAYS", 30)
MIN_COST_THRESHOLD = _env_float("FINOPS_MIN_COST_THRESHOLD", 1.0)  # USD

# --- NAT Gateway thresholds ---
NAT_LOOKBACK_DAYS = _env_int("FINOPS_NAT_LOOKBACK_DAYS", 30)
NAT_IDLE_TRAFFIC_THRESHOLD_GB = _env_float("FINOPS_NAT_IDLE_TRAFFIC_THRESHOLD_GB", 1.0)
NAT_IDLE_CONNECTION_THRESHOLD = _env_int("FINOPS_NAT_IDLE_CONNECTION_THRESHOLD", 0)

# --- S3 metrics helpers ---
BIG_BUCKET_THRESHOLD_GB = _env_float("FINOPS_S3_BIG_BUCKET_THRESHOLD_GB", 500.0)
STALE_DAYS_THRESHOLD = _env_int("FINOPS_S3_STALE_DAYS_THRESHOLD", 180)
S3_MULTIPART_STALE_DAYS = _env_int("FINOPS_S3_MULTIPART_STALE_DAYS", 7)
S3_LOOKBACK_DAYS = _env_int("FINOPS_S3_LOOKBACK_DAYS", 90)
MAX_KEYS_TO_SCAN = _env_int("FINOPS_S3_MAX_KEYS_TO_SCAN", 10000)

# --- DynamoDB worker knobs (advanced) ---
_DDB_TABLE_WORKERS: int = _env_int("FINOPS_DDB_TABLE_WORKERS", 6)
_DDB_META_WORKERS: int  = _env_int("FINOPS_DDB_META_WORKERS", 4)
_DDB_GSI_METRICS_LIMIT: Optional[int] = (
    None if os.getenv("FINOPS_DDB_GSI_METRICS_LIMIT") in (None, "", "none")
    else _env_int("FINOPS_DDB_GSI_METRICS_LIMIT", 0)
)

_DDB_CW_PERIOD: int = DDB_CW_PERIOD

S3_STORAGE_TYPES = [
    "StandardStorage",
    "StandardIAStorage",
    "OneZoneIAStorage",
    "ReducedRedundancyStorage",
    "IntelligentTieringFAStorage",
    "IntelligentTieringIAStorage",
    "IntelligentTieringAAStorage",
    "GlacierInstantRetrievalStorage",
    "GlacierStorage",
    "GlacierDeepArchiveStorage",
]

# --- BACKUP ---
VALID_RETENTION_DAYS = {7, 35, 90}

# --- SSM ---
SSM_ADV_STALE_DAYS = _env_int("FINOPS_SSM_ADV_STALE_DAYS", 180)

MAX_CUSTOM_METRICS_CHECK = _env_int("FINOPS_MAX_CUSTOM_METRICS_CHECK", 500)

# --- EC2 ---
EC2_LOOKBACK_DAYS = _env_int("FINOPS_EC2_LOOKBACK_DAYS", 30)
EC2_CW_PERIOD = _env_int("FINOPS_EC2_CW_PERIOD", 86400)
EC2_IDLE_CPU_PCT = _env_float("FINOPS_EC2_IDLE_CPU_PCT", 5.0)
EC2_IDLE_NET_GB = _env_float("FINOPS_EC2_IDLE_NET_GB", 0.1)
EC2_IDLE_DISK_OPS = _env_int("FINOPS_EC2_IDLE_DISK_OPS", 10)

# --- CloudFront ---
CLOUDFRONT_LOOKBACK_DAYS = _env_int("FINOPS_CLOUDFRONT_LOOKBACK_DAYS", 60)
CLOUDFRONT_PERIOD = _env_int("FINOPS_CLOUDFRONT_PERIOD", 86400)
CLOUDFRONT_IDLE_REQUESTS = _env_int("FINOPS_CLOUDFRONT_IDLE_REQUESTS", 10)
CLOUDFRONT_IDLE_BYTES_GB = _env_float("FINOPS_CLOUDFRONT_IDLE_BYTES_GB", 1.0)

# --- Load Balancers ---
LOAD_BALANCER_LOOKBACK_DAYS = _env_int("FINOPS_LB_LOOKBACK_DAYS", 60)