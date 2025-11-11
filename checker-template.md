# Checker Template

This document is a **playbook + code skeleton** for adding a new cost checker to FinOps-Toolset.

Goals: **reliability**, **consistency**, **performance** in the orchestrator.

---

## Golden Rules

1) **Signature contract**
- First positional arg: `region: str`
- Everything else via kwargs (extracted with the standard helpers)
- One checker per saving/finding (small, composable functions)

2) **Use the shared helpers**
```python
from aws_checkers.common import (
    _logger,         # returns logging.Logger
    _signals_str,    # dict/list/str -> compact "k=v|k2=v2" string
    _to_utc_iso,     # datetime -> ISO-8601 UTC
)

from aws_checkers import config  # ACCOUNT_ID, WRITE_ROW, safe_price()
from core.retry import retry_with_backoff
# Constants (HOURS_PER_MONTH, thresholds, SDK config, etc.):
from finops_toolset import config as const
```

3) **Pricing lookups**
- Always call: `config.safe_price("Service", "KEY", default)`
- Ensure keys exist in `finops_toolset/pricing.py`

4) **CSV row writing**
- Always write via `config.WRITE_ROW(...)` (wired to orchestrator’s unified writer)
- Provide `signals`, `flags`, and an **explicit `confidence`** (0–100)

5) **CloudWatch metrics (if used)**
- Use the batcher: `CloudWatchBatcher(region, client=cloudwatch)`
- Queue with: `add_q(id_hint, namespace, metric, dims, stat, period)`
- Execute once: `execute(start, end)` → `{id_hint: [(ts, val), ...]}`

6) **Resilience**
- Decorate public checks with `@retry_with_backoff(exceptions=(ClientError,))`
- Catch broad exceptions **only** around `WRITE_ROW` and non-critical loops

7) **Style**
- Pylint/Ruff compliant (≤100 chars/line), typed, every function has a docstring

---

## File Layout

Create `aws_checkers/<service>.py`. Export checker functions named `check_<what>()`.

---

## Minimal Checker Skeleton

```python
\"\"\"Checkers: <ServiceName>.\"\"\"

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple

from botocore.client import BaseClient
from botocore.exceptions import ClientError

from aws_checkers.common import _logger, _signals_str, _to_utc_iso
from aws_checkers import config
from core.retry import retry_with_backoff

# Optional: CloudWatch
from core.cloudwatch import CloudWatchBatcher


# ---------------------------
# Extractors (standard form)
# ---------------------------
def _extract_writer_client(
    args: Tuple[Any, ...], kwargs: Dict[str, Any]
) -> Tuple[Any, BaseClient]:
    \"\"\"Extract (writer, client) from args/kwargs; raise if missing.\"\"\"
    writer = kwargs.get(\"writer\", args[0] if len(args) >= 1 else None)
    client = kwargs.get(\"client\", args[1] if len(args) >= 2 else None)
    if writer is None or client is None:
        raise TypeError(\"Expected 'writer' and 'client'\")
    return writer, client


def _extract_writer_cw_client(
    args: Tuple[Any, ...], kwargs: Dict[str, Any]
) -> Tuple[Any, BaseClient, BaseClient]:
    \"\"\"Extract (writer, cloudwatch, client) from args/kwargs; raise if missing.\"\"\"
    writer = kwargs.get(\"writer\", args[0] if len(args) >= 1 else None)
    cloudwatch = kwargs.get(\"cloudwatch\", args[1] if len(args) >= 2 else None)
    client = kwargs.get(\"client\", args[2] if len(args) >= 3 else None)
    if writer is None or cloudwatch is None or client is None:
        raise TypeError(\"Expected 'writer', 'cloudwatch' and 'client'\")
    return writer, cloudwatch, client


# ---------------------------
# Pricing helpers (optional)
# ---------------------------
def _price(service: str, key: str, default: float = 0.0) -> float:
    \"\"\"Return a numeric price via config.safe_price(service, key, default).\"\"\"
    try:
        return float(config.safe_price(service, key, default))  # type: ignore[arg-type]
    except Exception:  # pylint: disable=broad-except
        return float(default)


# ---------------------------
# Example: a metrics-based checker
# ---------------------------
@retry_with_backoff(exceptions=(ClientError,))
def check_example_underutilized_resources(  # noqa: D401
    region: str,
    *args: Any,
    logger: Optional[logging.Logger] = None,
    lookback_days: int = 14,
    threshold: float = 10.0,
    account_id: Optional[str] = None,
    run_id: Optional[str] = None,
    **kwargs: Any,
) -> List[Dict[str, Any]]:
    \"\"\"Flag <Service> resources with low utilization -> rightsizing candidates.\"\"\"
    log = _logger(kwargs.get(\"logger\") or logger)

    # Extract deps (strict, orchestrator-compatible)
    try:
        writer, cloudwatch, client = _extract_writer_cw_client(args, kwargs)
    except TypeError as exc:
        log.warning(\"[check_example_underutilized_resources] Skipping: %s\", exc)
        return []

    owner = str(account_id or config.ACCOUNT_ID or \"\")
    if not (owner and config.WRITE_ROW):
        log.warning(\"[check_example_underutilized_resources] Skipping: missing config.\")
        return []

    # 1) Enumerate resources (single pass)
    try:
        resources = client.list_something().get(\"Items\", [])  # type: ignore[attr-defined]
    except ClientError as exc:
        log.warning(\"[example] list failed: %s\", exc)
        return []

    if not resources:
        return []

    # 2) Batch CW queries (one execute)
    start = datetime.now(timezone.utc) - timedelta(days=lookback_days)
    end = datetime.now(timezone.utc)
    batch = CloudWatchBatcher(region, client=cloudwatch)

    ids: List[str] = []
    for idx, r in enumerate(resources):
        rid = r.get(\"Id\", f\"res-{idx}\")
        ids.append(rid)
        dims = [{\"Name\": \"ResourceId\", \"Value\": rid}]
        batch.add_q(
            id_hint=f\"util_{idx}\",
            namespace=\"AWS/<ServiceNS>\",
            metric=\"Utilization\",
            dims=dims,
            stat=\"Average\",
            period=3600,
        )

    series = batch.execute(start, end)  # { \"util_0\": [(ts, val), ...], ... }

    # 3) Summarize + compute savings
    HOURS_PER_MONTH = 730.0
    rows: List[Dict[str, Any]] = []

    for idx, r in enumerate(resources):
        rid = r.get(\"Id\", f\"res-{idx}\")
        name = r.get(\"Name\", rid)
        state = r.get(\"State\", \"unknown\")
        created_iso = _to_utc_iso(r.get(\"CreateTime\"))

        vals = [float(v) for _, v in series.get(f\"util_{idx}\", [])]
        avg = (sum(vals) / len(vals)) if vals else 0.0

        # Pricing example (replace with your service)
        hourly_now = _price(\"OpenSearch\", f\"INSTANCE_HOURLY.r6g.large.search\", 0.0)
        potential = HOURS_PER_MONTH * hourly_now if avg < threshold else 0.0

        # 4) Emit one normalized row
        flags = []
        if avg < threshold:
            flags.append(f\"Util<{threshold}%\")
        signals = _signals_str(
            {\"avg_util\": round(avg, 1), \"hourly\": round(hourly_now, 4)}
        )

        try:
            # type: ignore[call-arg]
            config.WRITE_ROW(
                writer=writer,
                resource_id=str(r.get(\"Arn\", rid)),
                name=name,
                owner_id=owner,                 # type: ignore[arg-type]
                resource_type=\"<ServiceType>\",
                region=region,
                state=state,
                creation_date=created_iso,
                estimated_cost=round(hourly_now * HOURS_PER_MONTH, 2) if hourly_now else 0.0,
                potential_saving=round(potential, 2) if potential > 0.0 else None,
                flags=flags,
                confidence=75 if potential > 0.0 else 60,
                signals=signals,
            )
        except Exception as exc:  # pylint: disable=broad-except
            log.warning(\"[example] write_row failed: %s\", exc)

        rows.append({\"id\": rid, \"potential\": potential})

    return rows
```

---

## Orchestrator Wiring

Always follow this shape:

```python
# in orchestrator
import aws_checkers.<service> as svc

run_check(
    profiler, \"check_example_underutilized_resources\",
    region, svc.check_example_underutilized_resources,
    writer=writer,
    client=clients[\"<boto-client-name>\"],
    cloudwatch=clients[\"cloudwatch\"],  # only if metrics-based
    # knobs: lookback_days=14, threshold=10.0
)
```

- **Never** change the orchestrator’s call style.
- New checks must accept `region` first and extract `writer`, clients from kwargs.

---

## Pricing Keys

- Add **only** the keys your checker needs to `finops_toolset/pricing.py`.
- Use canonical casing: `PRICING[\"Service\"][\"KEY\"]`
  - Examples: `\"RDS\" / \"INSTANCE_HOURLY.db.m5.large\"`, `\"APIGW\" / \"CACHE_HR.13.5\"`
- In code, always call: `config.safe_price(\"Service\", \"KEY\", default)`

**Guardrail test (already in suite):**
- `test_all_checkers.py` scans for `safe_price(...)` pairs and fails if missing.

---

## Logging & Errors

- Obtain logger via `_logger(kwargs.get(\"logger\") or logger)`
- **Do not** spam errors; prefer `log.warning` for recoverable issues
- Wrap **only** `WRITE_ROW` and **external list calls** in broad `except` to keep progress

---

## Performance Checklist

- Enumerate once → **batch** CloudWatch → summarize → write rows
- Chunk very large metric batches in `CloudWatchBatcher` (if needed)
- Return early when there’s nothing to do (empty lists, no metrics)

---

## Tests (additive)

1) **Signature/Orchestrator smoke test**
```python
def test_checker_invocation_contract(monkeypatch):
    from finops_toolset.checkers import config
    cap = type(\"W\", (), {\"rows\": [], \"writerow\": lambda self, r: self.rows.append(r)})()

    monkeypatch.setattr(config, \"ACCOUNT_ID\", \"123456789012\", raising=False)
    monkeypatch.setattr(config, \"WRITE_ROW\", lambda **kw: cap.writerow(kw), raising=False)

    class _StubClient:  # only methods your checker calls
        def list_something(self, **_): return {\"Items\": []}

    # Must not raise
    import aws_checkers.<service> as svc
    svc.check_example_underutilized_resources(
        \"us-east-1\", writer=cap, client=_StubClient(), cloudwatch=object()
    )
```

2) **Pricing sanity** (covered globally):
- Ensure `safe_price(\"Service\",\"KEY\")` returns a number > 0 for your keys.

3) **CloudWatch shape**:
- Monkeypatch `CloudWatchBatcher` in your module to return crafted series; assert one row is emitted with expected `signals/flags`.

---

## Naming & Flags

- `resource_type`: a short, stable type (`\"RDSInstance\"`, `\"APIGatewayStage\"`, etc.)
- `flags`: terse, comma-less tokens (`[\"Idle\", \"MultiAZ\"]`)
- `signals`: compact, **parseable** diagnostics via `_signals_str({\"k\": v, ...})`
- `confidence`: 50–95; increase when evidence is strong and false positives unlikely

---

## Common Pitfalls (avoid)

- ❌ Passing `writer`/clients positionally after `region`
- ❌ Calling pricing via flattened `\"service.key\"` strings
- ❌ Multiple CW `execute` calls per checker run
- ❌ Missing docstrings / exceeding 100-char lines
- ❌ New `safe_price` keys not added to the price map (tests will fail)

---

## PR Checklist

- [ ] New file under `aws_checkers/…`
- [ ] Functions have docstrings, type hints, ≤100 chars/line
- [ ] Uses `_logger`, `_signals_str`, `_to_utc_iso`, `config.safe_price`, `config.WRITE_ROW`
- [ ] Signature: `(region, *args, **kwargs)` with extractors
- [ ] One batched CloudWatch query (if needed)
- [ ] Pricing keys added to `finops_toolset/pricing.py`
- [ ] Tests: signature/orchestrator smoke + (optional) functional stub
- [ ] `ruff`, `pylint`, `pytest` all green
