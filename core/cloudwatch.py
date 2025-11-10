# finops_toolset/aws/cloudwatch.py
from __future__ import annotations
from dataclasses import dataclass
from datetime import datetime
import time
from typing import Dict, List, Tuple, Union, Any

import boto3 #type: ignore
from botocore.config import Config #type: ignore
from botocore.exceptions import ClientError #type: ignore

try:
    from finops_toolset.config import SDK_CONFIG
except Exception:
    SDK_CONFIG = Config(retries={"max_attempts": 10, "mode": "standard"})

# ---------- Retry helper ----------
def _aws_call(fn, *args, **kwargs):
    for attempt in range(5):
        try:
            return fn(*args, **kwargs)
        except ClientError as e:
            code = (e.response or {}).get("Error", {}).get("Code", "")
            if code in {"Throttling","ThrottlingException","RequestLimitExceeded"} or code.startswith("5"):

                time.sleep(min(2 ** attempt, 8))
                continue
            raise
        except Exception:
            time.sleep(min(2 ** attempt, 8))
    raise RuntimeError("AWS call failed after retries")

# ---------- MDQ model ----------
@dataclass
class MDQ:
    id: str
    namespace: str
    metric: str
    dims: List[dict]
    stat: str
    period: int

def build_mdq(id_hint: str, namespace: str, metric: str, dims: List[dict], stat: str, period: int) -> MDQ:
    """Factory kept for compatibility with call sites: returns an MDQ dataclass."""
    return MDQ(id_hint, namespace, metric, dims, stat, period)

MetricQuery = Union[MDQ, Dict[str, Any]]

def _sanitize_id(id_hint: str) -> str:
    s = "".join(ch if (ch.isalnum() or ch == "_") else "_" for ch in str(id_hint))
    if not s or not s[0].isalpha():
        s = "m_" + s
    return s[:255]

class CloudWatchBatcher:
    """
    Batches GetMetricData queries. Accepts MDQ *or* raw dicts.
    Now auto-sanitizes Ids internally and returns series keyed by the ORIGINAL id_hints.
    """
    def __init__(self, region: str, client=None):
        self.region = region
        self.cw = client or boto3.client("cloudwatch", region_name=region, config=SDK_CONFIG)
        self._mdqs: List[Dict[str, Any]] = []      # always stored as dicts shaped for GetMetricData
        self._idmap: Dict[str, str] = {}           # original_id_hint -> safe_id
        self._idmap_rev: Dict[str, str] = {}       # safe_id -> original_id_hint

    def add(self, q: Union[MDQ, Dict[str, Any]]) -> None:
        """Add a query. If q has an invalid Id, sanitize it and keep a mapping back to the original."""
        if isinstance(q, MDQ):
            orig = q.id
            safe = _sanitize_id(orig)
            d = {
                "Id": safe,
                "MetricStat": {
                    "Metric": {"Namespace": q.namespace, "MetricName": q.metric, "Dimensions": q.dims},
                    "Period": q.period,
                    "Stat": q.stat,
                },
                "ReturnData": True,
            }
        else:
            orig = q.get("Id") or "m_id"
            safe = _sanitize_id(orig)
            d = dict(q)
            d["Id"] = safe

        # record mapping only once per original id
        if orig not in self._idmap:
            self._idmap[orig] = safe
            self._idmap_rev[safe] = orig

        self._mdqs.append(d)

    def add_q(self, *, id_hint: str, namespace: str, metric: str, 
              dims: List[dict], stat: str, period: int) -> None:
        self.add({
            "Id": id_hint,  # we'll sanitize internally and map back
            "MetricStat": {
                "Metric": {"Namespace": namespace, "MetricName": metric, "Dimensions": dims},
                "Period": period,
                "Stat": stat,
            },
            "ReturnData": True,
        })

    def execute(self, start: datetime, end: datetime, scan_by: str = "TimestampDescending") -> Dict[str, List[Tuple[datetime, float]]]:
        """
        Executes in chunks (<=500 queries each).
        Returns: dict keyed by the ORIGINAL id_hint you added (not the sanitized Id).
        """
        if not self._mdqs:
            return {}

        out: Dict[str, List[Tuple[datetime, float]]] = {}
        for i in range(0, len(self._mdqs), 500):
            chunk = self._mdqs[i:i+500]

            next_token = None
            while True:
                kwargs = dict(MetricDataQueries=chunk, StartTime=start, EndTime=end, ScanBy=scan_by)
                if next_token:
                    kwargs["NextToken"] = next_token
                resp = _aws_call(self.cw.get_metric_data, **kwargs)

                for r in (resp.get("MetricDataResults") or []):
                    safe_id = r["Id"]
                    orig_id = self._idmap_rev.get(safe_id, safe_id)
                    ts = r.get("Timestamps") or []
                    vals = r.get("Values") or []
                    pairs = sorted(zip(ts, vals), key=lambda x: x[0], reverse=True)
                    out.setdefault(orig_id, []).extend(pairs)

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

