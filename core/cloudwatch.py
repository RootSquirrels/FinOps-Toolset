"""CloudWatch metric batching utilities.

This module provides a small wrapper around the CloudWatch `GetMetricData` API that:
- Splits large query sets into API-compliant chunks (<= 500 queries/request).
- Transparently paginates via `NextToken`.
- Retries on throttling with exponential backoff.
- Exposes two entry points used by the toolset:
  * CloudWatchBatcher.get_metric_data(**kwargs) -> dict (matches boto3 shape)
  * CloudWatchBatcher.run(queries, start, end, ...) -> List[MetricDataResults]
"""

from __future__ import annotations

from datetime import datetime
from time import sleep
from typing import Any, Dict, Iterable, Iterator, List, Mapping, MutableMapping, Optional

try:
    from botocore.client import BaseClient
    from botocore.exceptions import ClientError
except Exception as exc:  # pragma: no cover - import guard only
    raise RuntimeError("botocore is required for CloudWatch batching") from exc


# AWS limit for GetMetricData: max 500 MetricDataQueries per call.
_DEFAULT_CHUNK_SIZE = 500


def _chunked(seq: Iterable[Any], size: int) -> Iterator[List[Any]]:
    """Yield lists of up to `size` items from `seq`."""
    bucket: List[Any] = []
    for item in seq:
        bucket.append(item)
        if len(bucket) >= size:
            yield bucket
            bucket = []
    if bucket:
        yield bucket


def _merge_results(pages: Iterable[Mapping[str, Any]]) -> List[Mapping[str, Any]]:
    """Merge MetricDataResults across pages/chunks by Id, in timestamp order."""
    merged: Dict[str, MutableMapping[str, Any]] = {}
    for page in pages:
        for entry in page.get("MetricDataResults", []) or []:
            rid = entry.get("Id")
            if not rid:
                # Skip malformed entries
                continue
            current = merged.setdefault(rid, {"Id": rid, "Label": entry.get("Label", "")})
            # Merge values/timestamps preserving order (CloudWatch returns ascending if requested)
            vals = entry.get("Values", []) or []
            ts = entry.get("Timestamps", []) or []
            if vals:
                current.setdefault("Values", [])  # type: ignore[assignment]
                current.setdefault("Timestamps", [])  # type: ignore[assignment]
                current["Values"].extend(vals)  # type: ignore[index]
                current["Timestamps"].extend(ts)  # type: ignore[index]
            # Keep status if present
            status = entry.get("StatusCode")
            if status:
                current["StatusCode"] = status  # type: ignore[index]
    # Convert to list and ensure values/timestamps exist
    out: List[Mapping[str, Any]] = []
    for item in merged.values():
        item.setdefault("Values", [])         # type: ignore[call-arg]
        item.setdefault("Timestamps", [])     # type: ignore[call-arg]
        out.append(item)
    return out


class CloudWatchBatcher:
    """Batching wrapper for CloudWatch `GetMetricData`.

    Usage:
        cw = boto3.client("cloudwatch")
        batcher = CloudWatchBatcher(cw)

        # 1) boto3-compatible call, returns a dict with 'MetricDataResults'
        resp = batcher.get_metric_data(
            MetricDataQueries=[...],
            StartTime=start_dt,
            EndTime=end_dt,
            ScanBy="TimestampAscending",
        )

        # 2) Simplified call, returns just the MetricDataResults list
        results = batcher.run(queries, start_dt, end_dt)
    """

    def __init__(
        self,
        client: BaseClient,
        *,
        chunk_size: int = _DEFAULT_CHUNK_SIZE,
        max_retries: int = 2,
        backoff_seconds: float = 0.5,
    ) -> None:
        """Create a new batcher.

        Args:
            client: Boto3 CloudWatch client.
            chunk_size: Max queries per request (<= 500).
            max_retries: Retries on throttling errors per API call.
            backoff_seconds: Initial sleep before retry; doubled each attempt.
        """
        self._cw = client
        self._chunk_size = max(1, min(int(chunk_size), _DEFAULT_CHUNK_SIZE))
        self._max_retries = max(0, int(max_retries))
        self._backoff = float(backoff_seconds)

    def get_metric_data(self, **kwargs: Any) -> Dict[str, Any]:
        """Compatibility wrapper for `client.get_metric_data(**kwargs)`.

        This method accepts the same keyword args as boto3 and will:
          - Chunk `MetricDataQueries` into API-sized requests.
          - Paginate via `NextToken`.
          - Retry on throttling up to `max_retries`.

        Returns:
            dict: A dict containing `"MetricDataResults": [...]` and merged `"Messages"` if any.
        """
        queries: List[Dict[str, Any]] = list(kwargs.get("MetricDataQueries", []) or [])
        if not queries:
            # Delegate to the client if nothing to split (still supports pagination)
            return self._call_with_pagination(**kwargs)

        all_pages: List[Mapping[str, Any]] = []
        for chunk in _chunked(queries, self._chunk_size):
            page = self._call_with_pagination(MetricDataQueries=chunk, **_strip_queries(kwargs))
            all_pages.append(page)

        results = _merge_results(all_pages)

        # Merge Messages if present
        messages: List[Mapping[str, Any]] = []
        for p in all_pages:
            for m in p.get("Messages", []) or []:
                messages.append(m)

        out: Dict[str, Any] = {"MetricDataResults": results}
        if messages:
            out["Messages"] = messages
        return out

    def run(
        self,
        queries: List[Dict[str, Any]],
        start: datetime,
        end: datetime,
        *,
        scan_by: str = "TimestampAscending",
        **extra: Any,
    ) -> List[Mapping[str, Any]]:
        """Execute queries via `get_metric_data` and return just the results list.

        Args:
            queries: MetricDataQueries items.
            start: StartTime (UTC).
            end: EndTime (UTC).
            scan_by: "TimestampAscending" (default) or "TimestampDescending".
            **extra: Additional GetMetricData parameters (e.g., `LabelOptions`, `MaxDatapoints`).

        Returns:
            List of MetricDataResults.
        """
        resp = self.get_metric_data(
            MetricDataQueries=list(queries),
            StartTime=start,
            EndTime=end,
            ScanBy=scan_by,
            **extra,
        )
        return list(resp.get("MetricDataResults", []) or [])

    # ------------------------ internal helpers ------------------------

    def _call_with_pagination(self, **kwargs: Any) -> Dict[str, Any]:
        """Call `get_metric_data` handling pagination and throttling retries."""
        next_token: Optional[str] = None
        pages: List[Mapping[str, Any]] = []

        while True:
            call_kwargs = dict(kwargs)  # shallow copy per page
            if next_token:
                call_kwargs["NextToken"] = next_token

            page = self._retrying_get_metric_data(call_kwargs)
            pages.append(page)

            next_token = page.get("NextToken")
            if not next_token:
                break

        # If multiple pages, merge results for consistency
        if len(pages) == 1:
            return dict(pages[0])  # return original shape
        return {"MetricDataResults": _merge_results(pages), "Messages": self._merge_messages(pages)}

    def _retrying_get_metric_data(self, params: Mapping[str, Any]) -> Dict[str, Any]:
        """Call `client.get_metric_data` with throttling retries."""
        attempts = 0
        delay = self._backoff
        while True:
            try:
                return self._cw.get_metric_data(**params)  # type: ignore[call-arg]
            except ClientError as err:
                code = (err.response or {}).get("Error", {}).get("Code", "")
                if code not in {"Throttling", "ThrottlingException"} or attempts >= self._max_retries:
                    raise
            attempts += 1
            sleep(delay)
            delay *= 2.0  # simple exponential backoff

    @staticmethod
    def _merge_messages(pages: Iterable[Mapping[str, Any]]) -> List[Mapping[str, Any]]:
        """Collect Messages from multiple pages (best-effort, may be empty)."""
        out: List[Mapping[str, Any]] = []
        for p in pages:
            for m in p.get("Messages", []) or []:
                out.append(m)
        return out


def _strip_queries(kwargs: Mapping[str, Any]) -> Dict[str, Any]:
    """Return kwargs without `MetricDataQueries` for chunked calls."""
    out = dict(kwargs)
    out.pop("MetricDataQueries", None)
    return out
