import io
import csv
import pytest
from FinOps_Toolset_V2_profiler import write_resource_to_csv

@pytest.mark.benchmark
def test_writer_perf(benchmark):
    buf = io.StringIO()
    writer = csv.writer(buf, delimiter=";", lineterminator="\n")
    def run():
        write_resource_to_csv(
            writer=writer,
            resource_id="i-123",
            name="bench",
            resource_type="ALB",
            owner_id="000000000000",
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
            signals="Type=ALB | TrafficGB=0.10",
        )
    benchmark(run)