"""
Generic tests for FinOps_Toolset_V2_profiler.py

- Discovers and runs all check_* functions using safe stubs (no AWS calls).
- Validates CSV invariants (Signals stays in one cell; Potential_Saving_USD derived from flags).
- Adapts to the real writer signature (no potential_saving_usd kw).

Run:
  python -m unittest -v
"""

import csv
import io
import inspect
import unittest
import copy
import logging
from contextlib import contextmanager

import FinOps_Toolset_V2_profiler as finops


# -------------------- Stubs & utilities --------------------

@contextmanager
def capture_errors():
    seen = {"errors": [], "exceptions": []}
    orig_err = logging.error
    orig_exc = logging.exception
    try:
        def _err(msg, *a, **k): seen["errors"].append(msg); orig_err(msg, *a, **k)
        def _exc(msg, *a, **k): seen["exceptions"].append(msg); orig_exc(msg, *a, **k)
        logging.error = _err
        logging.exception = _exc
        yield seen
    finally:
        logging.error = orig_err
        logging.exception = orig_exc


class _Meta:
    def __init__(self, region_name="eu-west-1"):
        self.region_name = region_name

class NullPaginator:
    """Paginator that yields a page-shaped dict matching the requested API, so code that indexes
    into keys like 'LoadBalancers' or 'Reservations' won't KeyError."""
    def __init__(self, name: str):
        self.name = name

    def paginate(self, *args, **kwargs):
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
        elif n == "list_distributions":
            yield {"DistributionList": {"Items": []}}
            return
        elif n == "list_streaming_distributions":
            yield {"StreamingDistributionList": {"Items": []}}
            return
        elif n == "list_hosted_zones":
            yield {"HostedZones": []}
            return

        else:
            yield {}

class NullAWSClient:
    """No-op client returning dicts with the keys most checkers index into."""
    def __init__(self, region_name="eu-west-1"):
        self.meta = _Meta(region_name)

    def get_paginator(self, name):
        return NullPaginator(name)

    # Common describe/get/list methods (non-paginated)
    def __getattr__(self, name):
        # Return a function that yields a dict with appropriate top-level keys
        def _f(*args, **kwargs):
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
            # CloudFront (non-paginated variants, just in case)
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
    """Heuristic: cell should include multiple key=value pairs separated by ' | '"""
    return " | " in cell or ("=" in cell and ";" in cell)  # tolerate legacy formats too


class TestAllClientsCovered(unittest.TestCase):
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

    def test_all_client_params_are_stubbed(self):
        unknown = {}
        for name, func in inspect.getmembers(finops, inspect.isfunction):
            if not name.startswith("check_"):
                continue
            sig = inspect.signature(func)
            for p in sig.parameters.values():
                param = p.name
                if param in self.NON_CLIENT_PARAMS:
                    continue
                # Decide whether this looks like an AWS client param
                looks_like_client = (
                    param.endswith("_client")
                    or param in TestAllCheckersRun.AWS_PARAM_NAMES
                    or param in self.KNOWN_SERVICE_NAMES
                )
                if looks_like_client and param not in TestAllCheckersRun.AWS_PARAM_NAMES:
                    unknown.setdefault(name, []).append(param)

        if unknown:
            details = "\n".join(f"- {k}: {v}" for k, v in unknown.items())
            self.fail(f"Unstubbed client parameter(s) detected:\n{details}")


# -------------------- Module patching --------------------

class Patcher:
    """Context manager that patches the finops module for the duration of tests."""
    def __enter__(self):
        # 1) Patch cw_get_metric_data_bulk to never hit AWS
        self._orig_cw = getattr(finops, "cw_get_metric_data_bulk", None)
        finops.cw_get_metric_data_bulk = lambda *a, **k: {}

        # 2) Patch safe_aws_call to accept fallback kw and always return default/fallback on error
        self._orig_safe = getattr(finops, "safe_aws_call", None)
        def _safe_aws_call(func, default=None, context="", fallback=None):
            try:
                return func()
            except Exception:
                # prefer explicit default; else fallback if provided; else {}
                return default if default is not None else (fallback if fallback is not None else {})
        finops.safe_aws_call = _safe_aws_call

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
            except Exception:
                return default
        finops.get_price = _get_price

        # 4) Default constants in case they are missing
        finops.HOURS_PER_MONTH = getattr(finops, "HOURS_PER_MONTH", 730)
        finops.LOAD_BALANCER_LOW_TRAFFIC_GB = getattr(finops, "LOAD_BALANCER_LOW_TRAFFIC_GB", 1.0)
        finops.NAT_IDLE_TRAFFIC_THRESHOLD_GB = getattr(finops, "NAT_IDLE_TRAFFIC_THRESHOLD_GB", 0.1)
        finops.NAT_IDLE_CONNECTION_THRESHOLD = getattr(finops, "NAT_IDLE_CONNECTION_THRESHOLD", 0.0)

        return self

    def __exit__(self, exc_type, exc, tb):
        if self._orig_cw is not None:
            finops.cw_get_metric_data_bulk = self._orig_cw
        if self._orig_safe is not None:
            finops.safe_aws_call = self._orig_safe
        if self._orig_get_price is not None:
            finops.get_price = self._orig_get_price


# -------------------- Test suites --------------------

class TestAllCheckersRun(unittest.TestCase):
    """Discover all check_* functions and run them with NullAWSClient + in-memory CSV writer."""

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

    def _make_kwargs(self, sig: inspect.Signature):
        """Build kwargs per checker: in-memory csv.writer + Null clients + harmless defaults."""
        buf = io.StringIO()
        writer = csv.writer(buf, delimiter=';', lineterminator='\n')

        kwargs = {}
        for name, param in sig.parameters.items():
            if name == "writer":
                kwargs[name] = writer
            elif name in self.AWS_PARAM_NAMES:
                kwargs[name] = NullAWSClient()
            elif param.default is inspect._empty:
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

    def test_every_check_function_runs(self):
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
                except Exception as e:
                    failures.append((name, repr(e)))
                    continue

                # Re-parse CSV to ensure shape remains intact for ';' delimiter
                csv_text = buf.getvalue()
                rows = list(csv.reader(io.StringIO(csv_text), delimiter=';'))
                for r in rows[1:]:
                    if len(r) > 0:
                        signals_cell = r[-1]
                        self.assertTrue(
                            signals_cell == "" or " | " in signals_cell or "=" in signals_cell,
                            f"{name}: Signals cell looks empty/invalid: '{signals_cell}'"
                        )

            if failures:
                msgs = "\n".join(f"- {n}: {err}" for n, err in failures)
                self.fail(f"Some checkers raised exceptions:\n{msgs}")


class TestGetPriceResolution(unittest.TestCase):
    def test_region_and_default_resolution(self):

        bak = copy.deepcopy(finops.PRICING)
        try:
            finops.PRICING.update({
                "ALB": {
                    "HOUR": {"default": 0.02, "eu-west-1": 0.0225},
                    "LCU_HOUR": {"default": 0.008}
                },
                "NAT": {
                    "HOUR": {"default": 0.065},
                    "GB_PROCESSED": {"default": 0.045}
                },
            })

            alb_hour_d = finops.get_price("ALB", "HOUR", region="eu-west-1")
            alb_hour_def = finops.get_price("ALB", "HOUR", region="us-east-8")
            lcu = finops.get_price("ALB", "LCU_HOUR", region="eu-west-1")

            self.assertEqual(alb_hour_d, 0.0225)
            self.assertEqual(alb_hour_def, 0.02)
            self.assertEqual(lcu, 0.008)
        finally:
            finops.PRICING = bak


class TestCheckerDeterminism(unittest.TestCase):
    def test_checker_writes_same_count_twice(self):
        candidate_names = [
            n for n, f in inspect.getmembers(finops, inspect.isfunction) if n.startswith("check_")
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
                kwargs1 = {}
                for p, prm in sig.parameters.items():
                    if p == "writer": kwargs1[p] = w1
                    elif p in TestAllCheckersRun.AWS_PARAM_NAMES: kwargs1[p] = NullAWSClient()
                    elif prm.default is inspect._empty:
                        if "days" in p or "lookback" in p or "window" in p: kwargs1[p] = 7
                        elif "region" in p: kwargs1[p] = "eu-west-1"
                        elif "account" in p or "owner" in p: kwargs1[p] = "423183760907"
                        else: kwargs1[p] = None
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
    def test_run_all_checkers_no_errors_logged(self):
        # Reuse the “AllCheckers” harness with our Patcher
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
                    kwargs = {}
                    for p, prm in sig.parameters.items():
                        if p == "writer": kwargs[p] = writer
                        elif p in TestAllCheckersRun.AWS_PARAM_NAMES: kwargs[p] = NullAWSClient()
                        elif prm.default is inspect._empty:
                            if "days" in p or "lookback" in p or "window" in p: kwargs[p] = 7
                            elif "region" in p: kwargs[p] = "eu-west-1"
                            elif "account" in p or "owner" in p: kwargs[p] = "423183760907"
                            else: kwargs[p] = None
                    try:
                        func(**kwargs)
                    except Exception as e:
                        failures.append((name, repr(e)))
                # No exceptions raised
                if failures:
                    self.fail("Some checkers raised exceptions:\n" + "\n".join(f"- {n}: {e}" for n, e in failures))
                # No error/exception logs either
                self.assertFalse(seen["errors"] or seen["exceptions"],
                                 f"Errors logged: {seen}")


class TestWriterBackCompat(unittest.TestCase):
    HEADER = [
        "Resource_ID","Name","ResourceType","OwnerId","State","Creation_Date",
        "Storage_GB","Object_Count","Estimated_Cost_USD","Potential_Saving_USD",
        "ApplicationID","Application","Environment","ReferencedIn",
        "FlaggedForReview","Confidence","Signals"
    ]

    def _roundtrip(self, signals_value):
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

    def test_signals_as_string(self):
        sig, raw = self._roundtrip("Type=ALB | TrafficGB=0.10")
        self.assertIn("Type=ALB", sig, f"raw={raw}")

    def test_signals_as_list(self):
        sig, raw = self._roundtrip(["Type=ALB", "TrafficGB=0.10"])
        # Depending on writer normalization, expect join with ' | ' or '; '
        self.assertTrue("Type=ALB" in sig and "TrafficGB=0.10" in sig, f"raw={raw}")

    def test_signals_as_dict(self):
        sig, raw = self._roundtrip({"Type": "ALB", "TrafficGB": 0.10})
        self.assertTrue("Type=ALB" in sig and "TrafficGB=0.1" in sig, f"raw={raw}")


class TestCSVInvariants(unittest.TestCase):
    """Focused tests for write_resource_to_csv normalization (Signals & PotentialSaving)."""

    HEADER = [
        "Resource_ID", "Name", "ResourceType", "OwnerId", "State", "Creation_Date",
        "Storage_GB", "Object_Count", "Estimated_Cost_USD", "Potential_Saving_USD",
        "ApplicationID", "Application", "Environment", "ReferencedIn",
        "FlaggedForReview", "Confidence", "Signals"
    ]

    def _roundtrip(self, flags, signals):
        # in-memory CSV with ';' to mimic your real output
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
            signals=signals
        )

        raw = buf.getvalue()
        rows = list(csv.reader(io.StringIO(raw), delimiter=';'))
        return rows[-1], raw

    def test_signals_one_cell_when_contains_pipe(self):
        row, raw = self._roundtrip(
            flags="LowTrafficLB, MissingRequiredTags",
            signals="Type=ALB | AvgLCU_per_hour=0.0012 | TrafficGB=0.42 | RequestCount=12345"
        )
        self.assertEqual(len(row), len(self.HEADER), f"Signals split the row: {raw}")
        self.assertTrue(row[-1].startswith("Type=ALB"), f"Unexpected signals: {row[-1]}")
        self.assertIn("TrafficGB=0.42", row[-1])

    def test_potential_saving_is_derived_from_flags(self):
        row, _ = self._roundtrip(
            flags="ZeroTraffic, MissingRequiredTags, PotentialSaving=16.43$",
            signals="Type=ALB | TrafficGB=0.00"
        )
        self.assertEqual(row[self.HEADER.index("Estimated_Cost_USD")], "16.43")
        self.assertEqual(row[self.HEADER.index("Potential_Saving_USD")], "16.43")

    def test_owner_id_not_transformed_or_safely_text(self):
        row, _ = self._roundtrip(
            flags="",
            signals="Type=NLB | NewFlows=0"
        )
        owner = row[self.HEADER.index("OwnerId")]
        # Accept both plain digits and "'digits" (Excel-protected export)
        self.assertTrue(owner == "423183760907" or owner.endswith("423183760907"))

    def test_state_and_creation_date_present(self):
        row, _ = self._roundtrip(
            flags="",
            signals="Type=ALB | TrafficGB=0.12"
        )
        self.assertEqual(row[self.HEADER.index("State")], "active")
        self.assertEqual(row[self.HEADER.index("Creation_Date")], "2025-01-01T00:00:00Z")


if __name__ == "__main__":
    unittest.main(verbosity=2)