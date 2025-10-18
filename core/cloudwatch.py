from __future__ import annotations
from dataclasses import dataclass
from datetime import datetime
from typing import Dict, List, Iterable, Tuple, Optional

import boto3 #type: ignore
from botocore.config import Config #type: ignore
from botocore.exceptions import ClientError #type: ignore

# Pull SDK config if present
try:
    from finops_toolset.config import SDK_CONFIG
except Exception:
    SDK_CONFIG = Config(retries={"max_attempts": 10, "mode": "standard"})

# -------- Retry helper (local; or import from core/retry if you already have it)
def _aws_call(fn, *args, **kwargs):
    for attempt in range(5):
        try:
            return fn(*args, **kwargs)
        except ClientError as e:
            code = (e.response or {}).get("Error", {}).get("Code", "")
            if code in {"Throttling","ThrottlingException","RequestLimitExceeded"} or code.startswith("5"):
                import time
                time.sleep(min(2 ** attempt, 8))
                continue
            raise
        except Exception:
            import time
            time.sleep(min(2 ** attempt, 8))
    raise RuntimeError("AWS call failed after retries")

@dataclass
class MDQ:
    id: str
    namespace: str
    metric: str
    dims: List[dict]
    stat: str
    period: int

def build_mdq(id_hint: str, namespace: str, metric: str, dims: List[dict], stat: str, period: int) -> MDQ:
    return MDQ(id_hint, namespace, metric, dims, stat, period)

class CloudWatchBatcher:
    """Batches GetMetricData calls (<=500 metrics per request), handles pagination & retries."""
    def __init__(self, region: str, client: Optional = None):
        self.region = region
        self.cw = client or boto3.client("cloudwatch", region_name=region, config=SDK_CONFIG)
        self._mdqs: List[MDQ] = []

    def add(self, q: MDQ) -> None:
        self._mdqs.append(q)

    def extend(self, qs: Iterable[MDQ]) -> None:
        self._mdqs.extend(qs)

    def execute(self, start: datetime, end: datetime, scan_by: str = "TimestampDescending") -> Dict[str, List[Tuple[datetime, float]]]:
        if not self._mdqs:
            return {}
        out: Dict[str, List[Tuple[datetime, float]]] = {}
        # chunk by 500 queries
        for i in range(0, len(self._mdqs), 500):
            chunk = self._mdqs[i:i+500]
            queries = [{
                "Id": q.id,
                "MetricStat": {
                    "Metric": {"Namespace": q.namespace, "MetricName": q.metric, "Dimensions": q.dims},
                    "Period": q.period,
                    "Stat": q.stat,
                },
                "ReturnData": True,
            } for q in chunk]

            next_token = None
            while True:
                resp = _aws_call(self.cw.get_metric_data,
                                 MetricDataQueries=queries,
                                 StartTime=start,
                                 EndTime=end,
                                 ScanBy=scan_by,
                                 NextToken=next_token) if next_token else \
                       _aws_call(self.cw.get_metric_data,
                                 MetricDataQueries=queries,
                                 StartTime=start,
                                 EndTime=end,
                                 ScanBy=scan_by)
                for r in resp.get("MetricDataResults", []):
                    key = r["Id"]
                    ts = r.get("Timestamps") or []
                    vals = r.get("Values") or []
                    # pair & sort descending by timestamp
                    pairs = sorted(zip(ts, vals), key=lambda x: x[0], reverse=True)
                    out.setdefault(key, []).extend(pairs)
                next_token = resp.get("NextToken")
                if not next_token:
                    break
        return out

    @staticmethod
    def latest(series: List[Tuple[datetime, float]], default: float = 0.0) -> float:
        return float(series[0][1]) if series else default

    @staticmethod
    def sum(series: List[Tuple[datetime, float]]) -> float:
        return float(sum(v for _, v in series))
