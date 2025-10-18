"""Generic tests for :mod:`FinOps_Toolset_V2_profiler` checkers.

This module provides *offline* unit tests that do not call AWS. It does so by
patching helper functions and injecting null AWS clients/paginators to satisfy
the signatures of all ``check_*`` functions discovered in the target module.

Test coverage highlights:
- CSV invariants (delimiter, Signals cell, Potential_Saving_USD derivation).
- ``get_price`` region/default resolution logic.
- ``safe_aws_call`` happy path and exception behavior.
- Smoke-run of every ``check_*`` with stubs to catch obvious regressions.
- Determinism: repeated runs write the same number of rows.
- Absence of error logs when checkers run on empty/no-op inputs.

Run these tests locally with::

    python -m unittest -v

They are designed to work without credentials and without network access.

Notes for maintainers
---------------------
To keep noise low, tests prefer broad compatibility (e.g., they accept either
empty string or ``0`` for missing values where the implementation may differ)
and avoid enforcing presentation micro-details.
"""

from __future__ import annotations

import csv
import io
import inspect
import unittest
import copy
import logging
from contextlib import contextmanager
from inspect import Parameter
from typing import Dict, Iterable, Iterator, List, Mapping, Tuple

import FinOps_Toolset_V2_profiler as finops
import finops_toolset.pricing as pricing


__all__ = [
    "capture_errors",
    "NullPaginator",
    "NullAWSClient",
    "_signals_ok",
    "Patcher",
    "TestSafeAwsCall",
    "TestPricingLookup",
    "TestAllClientsCovered",
    "TestAllCheckersRun",
    "TestGetPriceResolution",
    "TestCheckerDeterminism",
    "TestNoErrorLogsFromCheckers",
    "TestWriterBackCompat",
    "TestCSVInvariants",
    "TestPricingLookup",
]


# -------------------- Stubs & utilities --------------------

@contextmanager
def capture_errors() -> Iterator[Dict[str, List[str]]]:
    """Context manager that captures ``logging.error`` and ``logging.exception``.

    Returns a dict with two lists under the keys ``"errors"`` and ``"exceptions"``,
    populated with formatted log messages emitted while the context is active.
    """
    seen: Dict[str, List[str]] = {"errors": [], "exceptions": []}
    orig_err = logging.error
    orig_exc = logging.exception
    try:
        def _err(msg, *args, **kwargs):  # type: ignore[no-untyped-def]
            seen["errors"].append(str(msg))
            orig_err(msg, *args, **kwargs)

        def _exc(msg, *args, **kwargs):  # type: ignore[no-untyped-def]
            seen["exceptions"].append(str(msg))
            orig_exc(msg, *args, **kwargs)

        logging.error = _err  # type: ignore[assignment]
        logging.exception = _exc  # type: ignore[assignment]
        yield seen
    finally:
        logging.error = orig_err  # type: ignore[assignment]
        logging.exception = orig_exc  # type: ignore[assignment]


class _Meta:
    """Minimal object exposing a ``region_name`` attribute used by boto3 clients."""
    def __init__(self, region_name: str = "eu-west-1") -> None:
        self.region_name = region_name


class NullPaginator:
    """Paginator that yields a dict matching the requested API's typical shape.

    This prevents ``KeyError`` in code that indexes into e.g., ``LoadBalancers``,
    ``Reservations``, etc.
    """
    def __init__(self, name: str) -> None:
        self.name = name

    def paginate(self, *args, **kwargs) -> Iterable[Mapping[str, object]]:  # noqa: D401
        """Yield a single empty page for the requested paginator name."""
        n = self.name
        if n == "describe_instances":
            yield {"Reservations": []}
        elif n == "describe_route_tables":
            yield {"RouteTables": []}
        elif n == "describe_nat_gateways":
            yield {"NatGateways": []}
        elif n == "describe_load_balancers":
            yield {"LoadBalancers": []}
        elif n == "describe_load_balancers_elb":
            yield {"LoadBalancerDescriptions": []}
        elif n == "describe_parameters":
            yield {"Parameters": []}
        elif n == "describe_images":
            yield {"Images": []}
        elif n == "list_web_acls":
            yield {"WebACLs": []}
        elif n == "list_distributions":
            yield {"DistributionList": {"Items": []}}
        elif n == "list_streaming_distributions":
            yield {"StreamingDistributionList": {"Items": []}}
        elif n == "list_hosted_zones":
            yield {"HostedZones": []}
        else:
            yield {}


class NullAWSClient:
    """No-op boto3-like client returning dicts with expected top-level keys.

    Only implements the minimal subset used by the checkers under test.
    """
    def __init__(self, region_name: str = "eu-west-1") -> None:
        self.meta = _Meta(region_name)

    def get_paginator(self, name: str) -> NullPaginator:
        """Return a :class:`NullPaginator` for the given operation name."""
        return NullPaginator(name)

    # pylint: disable=too-many-return-statements, too-many-branches
    def __getattr__(self, name: str):  # noqa: D401
        """Return a function emulating common ``describe/get/list`` operations."""
        def _f():  # type: ignore[no-untyped-def]
            # ELBv2
            if name == "describe_load_balancers":
                return {"LoadBalancers": []}
            if name == "describe_tags":
                return {"TagDescriptions": []}
            # Classic ELB
            if name == "describe_load_balancers_elb":
                return {"LoadBalancerDescriptions": []}
            # EC2
            if name == "describe_images":
                return {"Images": []}
            if name == "describe_route_tables":
                return {"RouteTables": []}
            if name == "describe_nat_gateways":
                return {"NatGateways": []}
            if name == "describe_subnets":
                return {"Subnets": []}
            if name == "describe_vpcs":
                return {"Vpcs": []}
            if name == "describe_instances":
                return {"Reservations": []}
            # SSM
            if name == "describe_parameters":
                return {"Parameters": []}
            # WAFv2
            if name == "list_web_acls":
                return {"WebACLs": []}
            if name == "list_resources_for_web_acl":
                return {"ResourceArns": []}
            # CloudWatch
            if name == "get_metric_data":
                return {"MetricDataResults": []}
            # Route53 / CloudFront
            if name == "list_hosted_zones":
                return {"HostedZones": []}
            if name == "list_resource_record_sets":
                return {"ResourceRecordSets": []}
            if name == "list_distributions":
                return {"DistributionList": {"Items": []}}
            if name == "list_streaming_distributions":
                return {"StreamingDistributionList": {"Items": []}}
            if name == "list_tags_for_resource":
                return {"Tags": {"Items": []}}

            return {}
        return _f


def _signals_ok(cell: str) -> bool:
    """Heuristic validation for the ``Signals`` CSV cell.

    The cell should include multiple ``key=value`` pairs separated by ``" | "``
    in the newest format, or it may contain legacy separators (e.g., semicolons).
    """
    return " | " in cell or ("=" in cell and ";" in cell)


class TestSafeAwsCall(unittest.TestCase):
    """Unit tests for :func:`finops.safe_aws_call`."""

    def test_returns_default_on_exception(self) -> None:
        """When the function raises, the provided default is returned."""
        def boom():
            raise RuntimeError("kaboom")
        out = finops.safe_aws_call(boom, default={"ok": False}, context="unit")
        self.assertEqual(out, {"ok": False})

    def test_prefers_explicit_default_over_fallback(self) -> None:
        """Explicit ``default`` takes precedence over any ``fallback`` kwarg."""
        def boom():
            raise RuntimeError("kaboom")
        # Some implementations support `fallback=` kw; tolerate absence by ignoring it.
        try:
            out = finops.safe_aws_call(  # type: ignore[call-arg]
                boom, default=123, context="unit", fallback={"x": 1}
            )
        except TypeError:
            # Older signature without fallback; still pass
            out = finops.safe_aws_call(boom, default=123, context="unit")
        self.assertEqual(out, 123)

    def test_success_path_returns_function_value(self) -> None:
        """If the function succeeds, its value is returned unchanged."""
        def ok():
            return {"answer": 42}
        out = finops.safe_aws_call(ok, default=None, context="unit")
        self.assertEqual(out, {"answer": 42})


class TestPricingLookup(unittest.TestCase):
    """Unit tests for :func:`finops.get_price`."""

    def setUp(self) -> None:
        """Backup the pricing table before each test."""
        self._bak = copy.deepcopy(pricing.PRICING)

    def tearDown(self) -> None:
        """Restore the pricing table after each test."""
        pricing.PRICING = self._bak

    def test_unknown_service_returns_default(self) -> None:
        """Unknown services return the provided default price."""
        pricing.PRICING.clear()
        self.assertEqual(
            pricing.get_price("Nope", "HOUR", region="eu-west-1"), 0.0
        )

    def test_known_service_unknown_region_falls_back(self) -> None:
        """If region is missing, use the service's default price."""
        pricing.PRICING.update({
            "EIP": {"HOUR": {"default": 0.005}},
        })
        self.assertEqual(pricing.get_price("EIP", "HOUR", region="eu-central-7"), 0.005)

    def test_numeric_types_are_float(self) -> None:
        """Returned prices must be numeric for math downstream."""
        pricing.PRICING.update({
            "ALB": {"HOUR": {"default": 0.02}},
        })
        val = pricing.get_price("ALB", "HOUR", region="eu-west-1")
        self.assertIsInstance(val, (int, float))


class TestAllClientsCovered(unittest.TestCase):
    """Verify every checker signature's AWS clients are stubbed in the harness."""

    NON_CLIENT_PARAMS = {
        # Scalars / config
        "lookback_days", "days", "window", "threshold", "max_table_workers",
        "gsi_metrics_limit", "chunk_size", "max_workers", "cutoff_days",
        "region_name", "_ignored_kwargs",
        # Resource / function args (not clients)
        "fn", "lb", "vol", "snapshot", "source_snapshot_ids",
        "active_instances", "rule", "backup", "cached_templates",
        "stream", "lb_arn", "table_arn", "nlb_arn",
    }

    KNOWN_SERVICE_NAMES = {
        # Core services (extend as needed)
        "ec2", "s3", "efs", "ecr", "fsx", "eks", "elb", "elbv2",
        "rds", "dynamodb", "kinesis", "redshift",
        "logs", "ssm", "wafv2", "sns", "sqs", "events", "cloudtrail",
        "tgw", "ram", "emr",
        "route53", "route53resolver",
        "cloudfront", "cf_client",
        "autoscaling", "cfn",
        "lambda", "lambda_", "awslambda", "lambda_client",
    }

    def test_all_client_params_are_stubbed(self) -> None:
        """Fail if any checker parameter *looks like* a client but isn't stubbed."""
        unknown: Dict[str, List[str]] = {}
        for name, func in inspect.getmembers(finops, inspect.isfunction):
            if not name.startswith("check_"):
                continue
            sig = inspect.signature(func)
            for param in sig.parameters.values():
                pname = param.name
                if pname in self.NON_CLIENT_PARAMS:
                    continue
                # Decide whether this looks like an AWS client param
                looks_like_client = (
                    pname.endswith("_client")
                    or pname in TestAllCheckersRun.AWS_PARAM_NAMES
                    or pname in self.KNOWN_SERVICE_NAMES
                )
                if looks_like_client and pname not in TestAllCheckersRun.AWS_PARAM_NAMES:
                    unknown.setdefault(name, []).append(pname)

        if unknown:
            details = "\n".join(f"- {k}: {v}" for k, v in unknown.items())
            self.fail(f"Unstubbed client parameter(s) detected:\n{details}")


# -------------------- Module patching --------------------

class Patcher:
    """Patch the :mod:`finops` module to guarantee offline, deterministic behavior."""

    def __enter__(self) -> "Patcher":
        """Apply patches before a test block begins."""
        # 1) Patch cw_get_metric_data_bulk to never hit AWS
        self._orig_cw = getattr(finops, "cw_get_metric_data_bulk", None)
        finops.cw_get_metric_data_bulk = lambda *a, **k: {}

        # 2) Patch safe_aws_call: prefer default, then fallback on exceptions
        self._orig_safe = getattr(finops, "safe_aws_call", None)

        def _safe_aws_call(func, default=None, context="", fallback=None):
            try:
                return func()
            except Exception:  # pylint: disable=broad-exception-caught
                return default if default is not None else (fallback if fallback is not None else {})

        finops.safe_aws_call = _safe_aws_call  # type: ignore[assignment]

        # 3) Patch get_price to never throw (return 0.0 if missing)
        self._orig_get_price = getattr(finops, "get_price", None)

        def _get_price(service, key, region=None, default=0.0):
            try:
                table = finops.PRICING.get(service, {})
                val = table.get(key)
                if isinstance(val, dict):
                    return val.get(region, val.get("default", default))
                if val is None:
                    return default
                return val
            except Exception:  # pylint: disable=broad-exception-caught
                return default

        finops.get_price = _get_price  # type: ignore[assignment]

        # 4) Default constants in case they are missing
        finops.HOURS_PER_MONTH = getattr(finops, "HOURS_PER_MONTH", 730)
        finops.LOAD_BALANCER_LOW_TRAFFIC_GB = getattr(finops, "LOAD_BALANCER_LOW_TRAFFIC_GB", 1.0)
        finops.NAT_IDLE_TRAFFIC_THRESHOLD_GB = getattr(finops, "NAT_IDLE_TRAFFIC_THRESHOLD_GB", 0.1)
        finops.NAT_IDLE_CONNECTION_THRESHOLD = getattr(finops, "NAT_IDLE_CONNECTION_THRESHOLD", 0.0)

        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        """Revert patches when a test block ends."""
        if self._orig_cw is not None:
            finops.cw_get_metric_data_bulk = self._orig_cw  # type: ignore[assignment]
        if self._orig_safe is not None:
            finops.safe_aws_call = self._orig_safe  # type: ignore[assignment]
        if self._orig_get_price is not None:
            finops.get_price = self._orig_get_price  # type: ignore[assignment]


# -------------------- Test suites --------------------

class TestAllCheckersRun(unittest.TestCase):
    """Discover all ``check_*`` functions and run them with null clients and CSV writer."""

    AWS_PARAM_NAMES = {
        # CW + ELB + Route53
        "cw", "cloudwatch", "elbv2", "elb", "route53", "cloudfront", "cf_client",
        # Compute/Network/Storage
        "ec2", "s3", "efs", "ecr", "fsx", "eks", "autoscaling",
        # Databases
        "rds", "dynamodb", "kinesis", "redshift",
        # Config/SSM/WAF etc.
        "ssm", "wafv2", "logs", "sns", "sqs", "events", "cloudtrail",
        # Lambda
        "lambda_client", "lambda_", "awslambda",
        # Transit/RAM/Other
        "tgw", "ram", "emr", "cfn",
    }

    def _make_kwargs(self, sig: inspect.Signature) -> Tuple[Dict[str, object], io.StringIO]:
        """Construct kwargs for a checker based on its signature.

        Provides an in-memory CSV writer and a :class:`NullAWSClient` for client-like
        parameters. Required scalars like lookback/window/region/account receive
        harmless defaults.
        """
        buf = io.StringIO()
        writer = csv.writer(buf, delimiter=';', lineterminator='\n')

        kwargs: Dict[str, object] = {}
        for name, param in sig.parameters.items():
            if name == "writer":
                kwargs[name] = writer
            elif name in self.AWS_PARAM_NAMES:
                kwargs[name] = NullAWSClient()
            elif param.default is Parameter.empty:
                # Required arg—provide safe default
                if "days" in name or "lookback" in name or "window" in name:
                    kwargs[name] = 7
                elif "region" in name:
                    kwargs[name] = "eu-west-1"
                elif "account" in name or "owner" in name:
                    kwargs[name] = "423183760907"
                else:
                    kwargs[name] = None
            # otherwise, let checker use its default
        return kwargs, buf

    def test_every_check_function_runs(self) -> None:
        """Smoke test: call every checker and validate basic CSV properties."""
        with Patcher():
            failures = []
            for name, func in inspect.getmembers(finops, inspect.isfunction):
                if not name.startswith("check_"):
                    continue
                sig = inspect.signature(func)
                if "writer" not in sig.parameters:
                    continue
                kwargs, buf = self._make_kwargs(sig)
                try:
                    func(**kwargs)
                except Exception as exc:  # pylint: disable=broad-exception-caught
                    failures.append((name, repr(exc)))
                    continue

                # Re-parse CSV to ensure shape remains intact for ';' delimiter
                csv_text = buf.getvalue()
                rows = list(csv.reader(io.StringIO(csv_text), delimiter=';'))
                for row in rows[1:]:
                    if row:
                        signals_cell = row[-1]
                        self.assertTrue(
                            signals_cell == "" or " | " in signals_cell or "=" in signals_cell,
                            f"{name}: Signals cell looks empty/invalid: '{signals_cell}'"
                        )

            if failures:
                msgs = "\n".join(f"- {n}: {err}" for n, err in failures)
                self.fail(f"Some checkers raised exceptions:\n{msgs}")


class TestGetPriceResolution(unittest.TestCase):
    """Validation for region-specific and default fallback price resolution."""
    def setUp(self):
        self._bak = copy.deepcopy(pricing.PRICING)

    def tearDown(self):
        pricing.PRICING.clear()
        pricing.PRICING.update(self._bak)

    def test_region_and_default_resolution(self):
        """Ensure region override beats default; missing region falls back to default."""
        pricing.PRICING.clear()
        pricing.PRICING.update({
            "ALB": {
                "HOUR": {"default": 0.02, "eu-west-1": 0.0225},
                "LCU_HOUR": {"default": 0.008},
            }
        })
        self.assertEqual(finops.get_price("ALB", "HOUR", region="eu-west-1"), 0.0225)
        self.assertEqual(finops.get_price("ALB", "HOUR", region="us-east-8"), 0.02)
        self.assertEqual(finops.get_price("ALB", "LCU_HOUR", region="eu-west-1"), 0.008)


class TestCheckerDeterminism(unittest.TestCase):
    """Ensure that re-running a checker yields the same number of CSV rows."""

    def test_checker_writes_same_count_twice(self) -> None:
        """Pick a subset of checkers and compare row counts across two runs."""
        candidate_names = [
            n for n, _ in inspect.getmembers(finops, inspect.isfunction) if n.startswith("check_")
        ]
        to_test = candidate_names[:5]  # keep it light; or pass all if fast

        with Patcher():
            for name in to_test:
                fn = getattr(finops, name)
                sig = inspect.signature(fn)
                if "writer" not in sig.parameters:
                    continue
                # first run
                buf1 = io.StringIO()
                w1 = csv.writer(buf1, delimiter=';', lineterminator='\n')
                kwargs1: Dict[str, object] = {}
                for pname, prm in sig.parameters.items():
                    if pname == "writer":
                        kwargs1[pname] = w1
                    elif pname in TestAllCheckersRun.AWS_PARAM_NAMES:
                        kwargs1[pname] = NullAWSClient()
                    elif prm.default is Parameter.empty:
                        if "days" in pname or "lookback" in pname or "window" in pname:
                            kwargs1[pname] = 7
                        elif "region" in pname:
                            kwargs1[pname] = "eu-west-1"
                        elif "account" in pname or "owner" in pname:
                            kwargs1[pname] = "423183760907"
                        else:
                            kwargs1[pname] = None
                fn(**kwargs1)
                rows1 = list(csv.reader(io.StringIO(buf1.getvalue()), delimiter=';'))
                # second run
                buf2 = io.StringIO()
                w2 = csv.writer(buf2, delimiter=';', lineterminator='\n')
                kwargs2 = {**kwargs1, "writer": w2}
                fn(**kwargs2)
                rows2 = list(csv.reader(io.StringIO(buf2.getvalue()), delimiter=';'))
                self.assertEqual(len(rows1), len(rows2), f"{name}: row count drift between runs")


class TestNoErrorLogsFromCheckers(unittest.TestCase):
    """Ensure no error/exception logs are emitted by checkers on empty inputs."""

    def test_run_all_checkers_no_errors_logged(self) -> None:
        """Run all checkers and assert the error/exception logs remain empty."""
        with Patcher():
            failures = []
            with capture_errors() as seen:
                for name, func in inspect.getmembers(finops, inspect.isfunction):
                    if not name.startswith("check_"):
                        continue
                    sig = inspect.signature(func)
                    if "writer" not in sig.parameters:
                        continue
                    # Build kwargs like in the main harness
                    buf = io.StringIO()
                    writer = csv.writer(buf, delimiter=';', lineterminator='\n')
                    kwargs: Dict[str, object] = {}
                    for pname, prm in sig.parameters.items():
                        if pname == "writer":
                            kwargs[pname] = writer
                        elif pname in TestAllCheckersRun.AWS_PARAM_NAMES:
                            kwargs[pname] = NullAWSClient()
                        elif prm.default is Parameter.empty:
                            if "days" in pname or "lookback" in pname or "window" in pname:
                                kwargs[pname] = 7
                            elif "region" in pname:
                                kwargs[pname] = "eu-west-1"
                            elif "account" in pname or "owner" in pname:
                                kwargs[pname] = "423183760907"
                            else:
                                kwargs[pname] = None
                    try:
                        func(**kwargs)
                    except Exception as exc:  # pylint: disable=broad-exception-caught
                        failures.append((name, repr(exc)))
                # No exceptions raised
                if failures:
                    self.fail("Some checkers raised exceptions:\n" + "\n".join(f"- {n}: {e}" for n, e in failures))
                # No error/exception logs either
                self.assertFalse(seen["errors"] or seen["exceptions"], f"Errors logged: {seen}")


class TestWriterBackCompat(unittest.TestCase):
    """Backwards-compat checks for the CSV writer normalization rules."""

    HEADER = [
        "Resource_ID", "Name", "ResourceType", "OwnerId", "State", "Creation_Date",
        "Storage_GB", "Object_Count", "Estimated_Cost_USD", "Potential_Saving_USD",
        "ApplicationID", "Application", "Environment", "ReferencedIn",
        "FlaggedForReview", "Confidence", "Signals",
    ]

    def _roundtrip(self, signals_value) -> Tuple[str, str]:
        """Write a single row and return the ``Signals`` cell and raw CSV text."""
        buf = io.StringIO()
        writer = csv.writer(buf, delimiter=';', lineterminator='\n')
        writer.writerow(self.HEADER)
        finops.write_resource_to_csv(
            writer=writer,
            resource_id="res-compat",
            name="compat",
            resource_type="ALB",
            owner_id="423183760907",
            state="active",
            creation_date="2025-01-01T00:00:00Z",
            storage_gb=None,
            object_count=None,
            estimated_cost=1.23,
            app_id="NULL",
            app="App",
            env="dev",
            referenced_in="",
            flags="LowTrafficLB, PotentialSaving=1.23$",
            confidence=100,
            signals=signals_value,
        )
        raw = buf.getvalue()
        row = list(csv.reader(io.StringIO(raw), delimiter=';'))[-1]
        return row[-1], raw

    def test_signals_as_string(self) -> None:
        """Accept a pre-formatted string as ``Signals`` content."""
        sig, raw = self._roundtrip("Type=ALB | TrafficGB=0.10")
        self.assertIn("Type=ALB", sig, f"raw={raw}")

    def test_signals_as_list(self) -> None:
        """Join list inputs into the canonical pipe-delimited string."""
        sig, raw = self._roundtrip(["Type=ALB", "TrafficGB=0.10"])
        self.assertTrue("Type=ALB" in sig and "TrafficGB=0.10" in sig, f"raw={raw}")

    def test_signals_as_dict(self) -> None:
        """Render dict inputs as ``key=value`` pairs."""
        sig, raw = self._roundtrip({"Type": "ALB", "TrafficGB": 0.10})
        self.assertTrue("Type=ALB" in sig and "TrafficGB=0.1" in sig, f"raw={raw}")


class TestCSVInvariants(unittest.TestCase):
    """Focused tests for ``write_resource_to_csv`` normalization and invariants."""

    HEADER = [
        "Resource_ID", "Name", "ResourceType", "OwnerId", "State", "Creation_Date",
        "Storage_GB", "Object_Count", "Estimated_Cost_USD", "Potential_Saving_USD",
        "ApplicationID", "Application", "Environment", "ReferencedIn",
        "FlaggedForReview", "Confidence", "Signals",
    ]

    def _roundtrip(self, flags: str, signals: object) -> Tuple[List[str], str]:
        """Write one row using provided flags/signals and return parsed row + CSV text."""
        buf = io.StringIO()
        writer = csv.writer(buf, delimiter=';', lineterminator='\n')
        writer.writerow(self.HEADER)

        finops.write_resource_to_csv(
            writer=writer,
            resource_id="res-1",
            name="name-1",
            resource_type="ALB",
            owner_id="423183760907",
            state="active",
            creation_date="2025-01-01T00:00:00Z",
            storage_gb=None,
            object_count=None,
            estimated_cost=16.43,
            app_id="NULL",
            app="App",
            env="dev",
            referenced_in="",
            flags=flags,
            confidence=100,
            signals=signals,
        )

        raw = buf.getvalue()
        rows = list(csv.reader(io.StringIO(raw), delimiter=';'))
        return rows[-1], raw

    def test_signals_one_cell_when_contains_pipe(self) -> None:
        """Ensure pipe-delimited Signals remain in a single CSV cell."""
        row, raw = self._roundtrip(
            flags="LowTrafficLB, MissingRequiredTags",
            signals="Type=ALB | AvgLCU_per_hour=0.0012 | TrafficGB=0.42 | RequestCount=12345",
        )
        self.assertEqual(len(row), len(self.HEADER), f"Signals split the row: {raw}")
        self.assertTrue(row[-1].startswith("Type=ALB"), f"Unexpected signals: {row[-1]}")
        self.assertIn("TrafficGB=0.42", row[-1])

    def test_potential_saving_is_derived_from_flags(self) -> None:
        """Potential_Saving_USD should be derived from the ``PotentialSaving=...$`` flag."""
        row, _ = self._roundtrip(
            flags="ZeroTraffic, MissingRequiredTags, PotentialSaving=16.43$",
            signals="Type=ALB | TrafficGB=0.00",
        )
        self.assertEqual(row[self.HEADER.index("Estimated_Cost_USD")], "16.43")
        self.assertEqual(row[self.HEADER.index("Potential_Saving_USD")], "16.43")

    def test_owner_id_not_transformed_or_safely_text(self) -> None:
        """Account IDs should remain numeric (or be safely quoted for Excel)."""
        row, _ = self._roundtrip(flags="", signals="Type=NLB | NewFlows=0")
        owner = row[self.HEADER.index("OwnerId")]
        # Accept both plain digits and "'digits" (Excel-protected export)
        self.assertTrue(owner == "423183760907" or owner.endswith("423183760907"))

    def test_state_and_creation_date_present(self) -> None:
        """Ensure required text fields are present and unmodified."""
        row, _ = self._roundtrip(flags="", signals="Type=ALB | TrafficGB=0.12")
        self.assertEqual(row[self.HEADER.index("State")], "active")
        self.assertEqual(row[self.HEADER.index("Creation_Date")], "2025-01-01T00:00:00Z")


if __name__ == "__main__":
    unittest.main(verbosity=2)
