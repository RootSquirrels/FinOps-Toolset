"""Optional integration test suite using moto (in-memory AWS).

- Spins up moto's mock_aws context.
- Seeds minimal resources for common services (DynamoDB, S3, EC2).
- Discovers checkers and calls a conventional entrypoint if present:
  one of: run(regions), collect(regions), main(regions).

Enable with: `pytest -m integration`

Note: Keep this light. If your checker needs other services, seed them here.
"""

from __future__ import annotations

from importlib import import_module
from typing import Callable, Dict, Iterable, List, Optional

import boto3
import pytest
from moto import mock_aws

from test_checkers_generic import (  # reuse invariants
        _discover_checker_modules,
        _assert_row_schema_invariants,
        _assert_owner_id_safe,
    )

CHECKERS_PACKAGE = "aws_checkers"
CONFIG_MODULE = "aws_checkers.config"


def _discover_entrypoint(modname: str) -> Optional[Callable[[Iterable[str]], None]]:
    module_obj = import_module(modname)
    for cand in ("run", "collect", "main"):
        func = getattr(module_obj, cand, None)
        if callable(func):
            return func
    return None


def _seed_fake_aws(region: str = "us-east-1") -> None:
    """Create minimal resources many checkers expect. Extend as needed."""
    # S3: one bucket
    s3 = boto3.client("s3", region_name=region)
    s3.create_bucket(Bucket="finops-toolset-ci")

    # DynamoDB: one table
    ddb = boto3.client("dynamodb", region_name=region)
    ddb.create_table(
        TableName="Orders",
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
    )

    # EC2: trivial instance (moto accepts placeholder AMI IDs)
    ec2 = boto3.client("ec2", region_name=region)
    vpc_id = ec2.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]["VpcId"]
    subnet_id = ec2.create_subnet(
        VpcId=vpc_id, CidrBlock="10.0.0.0/24"
    )["Subnet"]["SubnetId"]
    ec2.run_instances(
        ImageId="ami-12345678",
        MinCount=1,
        MaxCount=1,
        SubnetId=subnet_id,
        InstanceType="t3.micro",
    )


@pytest.fixture(name="captured_rows")
def fixture_captured_rows(monkeypatch) -> List[Dict[str, object]]:
    cfg = import_module(CONFIG_MODULE)
    rows: List[Dict[str, object]] = []
    monkeypatch.setattr(cfg, "WRITE_ROW", lambda r: rows.append(r), raising=True)
    return rows


@pytest.fixture(name="fake_account_id")
def fixture_fake_account_id(monkeypatch) -> str:
    cfg = import_module(CONFIG_MODULE)
    ACCOUNT_ID = "123456789012"
    monkeypatch.setattr(cfg, "ACCOUNT_ID", ACCOUNT_ID, raising=True)
    return ACCOUNT_ID


@pytest.mark.integration
def test_checkers_run_against_moto(
    captured_rows: List[Dict[str, object]],
    fake_account_id: str,  # noqa: ARG001 (used implicitly via config)
) -> None:
    """Run each checker (if it exposes a known entrypoint) inside moto."""

    cfg = import_module(CONFIG_MODULE)

    with mock_aws():
        _seed_fake_aws()
        regions = ["us-east-1"]

        for modname in _discover_checker_modules():
            entrypoint = _discover_entrypoint(modname)
            if entrypoint is None:
                # No conventional entrypoint; skip silently
                continue
            entrypoint(regions)

    # Validate everything we captured
    for row in captured_rows:
        _assert_row_schema_invariants(row)
        _assert_owner_id_safe(row["OwnerId"], fake_account_id, cfg.safely_text)
