"""
Policies-as-Code engine for the FinOps Toolset.

Purpose
-------
- Load a YAML policies file.
- Evaluate each rule against scanner CSV rows (no rescan).
- Emit a 'policy_actions.csv' for humans/automation and optionally
  an updated CSV where matching rows get extra flags so your existing
  CSV-driven remediator can act immediately.

Design
------
- Rules are declarative YAML with "target" + "when" + "then".
- "when" supports nested boolean logic: all/any/not and basic field ops.
- Fields can reference top-level CSV columns or nested "Signals.*".
- Actions define mode (warn|pr|remediate) and a remediation id + params.
- Scalable: stateless, streaming CSV evaluation; easy to extend predicates.
"""

# finops_toolset/policy/engine.py
from __future__ import annotations
import csv
import json
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

# Optional dependency: pyyaml (recommended)
try:
    import yaml
except Exception:
    yaml = None  # We'll support JSON policies as a fallback

# Pull CSV delimiter from central config if available
try:
    from finops_toolset.config import CSV_DELIMITER
except Exception:
    CSV_DELIMITER = ";"

# ---- Types ----

@dataclass
class PolicyAction:
    policy_id: str
    mode: str                 # "warn" | "pr" | "remediate"
    severity: str             # "P0".."P3"
    resource_type: str
    resource_id: str
    region: str
    owner: str
    remediation: str          # e.g., "logs.set_retention_days"
    params: Dict[str, Any] = field(default_factory=dict)
    reason: str = ""          # short why matched
    fix_snippet: str = ""     # optional CLI/IaC snippet

# ---- Utilities ----

FLAG_COL_CANDIDATES = ["Flags", "FlaggedForReview", "flagged_for_review"]
SIGNALS_COL_CANDIDATES = ["Signals", "signals"]

def _find_col(row: dict, candidates: List[str]) -> Optional[str]:
    lower = {k.lower(): k for k in row.keys()}
    for c in candidates:
        if c.lower() in lower:
            return lower[c.lower()]
    return None

def _parse_flags(raw: str) -> List[str]:
    if not raw:
        return []
    parts = re.split(r"[|,;]+", str(raw))
    return [p.strip() for p in parts if p.strip()]

def _parse_signals(raw: str) -> Dict[str, str]:
    if not raw:
        return {}
    out: Dict[str, str] = {}
    for tok in re.split(r"[|,]+", str(raw)):
        tok = tok.strip()
        if not tok or "=" not in tok:
            continue
        k, v = tok.split("=", 1)
        out[k.strip()] = v.strip()
    return out

def _get_region(row: dict, signals: Dict[str, str]) -> str:
    r = signals.get("Region") or signals.get("region") or ""
    if r:
        return r
    az = signals.get("AZ") or signals.get("AvailabilityZone") or ""
    if az and len(az) >= 2:
        return az[:-1]  # "eu-west-1a" -> "eu-west-1"
    return ""

def _get_owner(row: dict, signals: Dict[str, str]) -> str:
    # Heuristic: prefer explicit fields, then tags in Signals
    for k in ("Owner", "OwnerEmail", "OwnerId", "Application", "ApplicationID"):
        if row.get(k):
            return str(row[k])
    for k in ("owner", "application", "applicationid", "team"):
        if signals.get(k):
            return signals[k]
    return ""

def _get_field(row: dict, signals: Dict[str, str], flags: List[str], path: str) -> Any:
    """
    Resolve 'path' like "ResourceType", "Signals.Region", "Flags", "Estimated_Cost_USD".
    """
    if path == "Flags":
        return flags
    if path.startswith("Signals."):
        k = path.split(".", 1)[1]
        return signals.get(k)
    return row.get(path)

# ---- Condition evaluation ----

def _eval_pred(row: dict, signals: Dict[str, str], flags: List[str], cond: Dict[str, Any]) -> bool:
    """
    Supported forms:
      - {"field": "ResourceType", "eq": "S3Bucket"}
      - {"field": "Estimated_Cost_USD", "gte": 10}
      - {"field": "Flags", "contains_any": ["noretention", "retention=0"]}
      - {"field": "Signals.Region", "in": ["eu-west-1", "eu-west-3"]}
      - {"regex": {"field": "Name", "pattern": "^prod-"}}
    Boolean composition:
      - {"all": [ ...predicates... ]}
      - {"any": [ ...predicates... ]}
      - {"not": { ...predicate... }}
    """
    if "all" in cond:
        return all(_eval_pred(row, signals, flags, c) for c in cond["all"])
    if "any" in cond:
        return any(_eval_pred(row, signals, flags, c) for c in cond["any"])
    if "not" in cond:
        return not _eval_pred(row, signals, flags, cond["not"])

    # Leaf predicate
    if "regex" in cond and isinstance(cond["regex"], dict):
        leaf = cond["regex"]
        val = _get_field(row, signals, flags, leaf.get("field", "")) or ""
        patt = re.compile(str(leaf.get("pattern", "")))
        return bool(patt.search(str(val)))

    field = str(cond.get("field", ""))
    val = _get_field(row, signals, flags, field)

    if "exists" in cond:
        want = bool(cond["exists"])
        return (val is not None and val != "") if want else (val is None or val == "")

    if "eq" in cond:
        return str(val) == str(cond["eq"])
    if "neq" in cond:
        return str(val) != str(cond["neq"])
    if "in" in cond:
        return str(val) in [str(x) for x in cond["in"]]
    if "nin" in cond:
        return str(val) not in [str(x) for x in cond["nin"]]

    # numeric comparisons
    def _num(x) -> Optional[float]:
        try:
            return float(x)
        except Exception:
            return None

    if "gt" in cond:
        return (_num(val) is not None) and (_num(val) > float(cond["gt"]))
    if "gte" in cond:
        return (_num(val) is not None) and (_num(val) >= float(cond["gte"]))
    if "lt" in cond:
        return (_num(val) is not None) and (_num(val) < float(cond["lt"]))
    if "lte" in cond:
        return (_num(val) is not None) and (_num(val) <= float(cond["lte"]))

    # sequence contains helpers
    if "contains_any" in cond:
        hay = [s.lower() for s in (val if isinstance(val, list) else _parse_flags(str(val)))]
        needles = [str(x).lower() for x in cond["contains_any"]]
        return any(n in hay for n in needles)

    if "contains_all" in cond:
        hay = [s.lower() for s in (val if isinstance(val, list) else _parse_flags(str(val)))]
        needles = [str(x).lower() for x in cond["contains_all"]]
        return all(n in hay for n in needles)

    return False

# ---- Policy evaluation ----

def _load_policies(path: str) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as f:
        raw = f.read()
    if path.lower().endswith(".json") or yaml is None:
        return json.loads(raw)
    return yaml.safe_load(raw)

def evaluate_policies_for_csv(
    csv_path: str,
    policies_path: str,
    out_actions_csv: Optional[str] = None,
    out_updated_csv: Optional[str] = None,
) -> Dict[str, int]:
    """
    - Reads the scanner CSV.
    - For each row, evaluates rules.
    - Writes policy_actions.csv (one row per match) with mode/remediation/params, etc.
    - Optionally writes an *updated* CSV where matching rows get extra flags injected,
      so your CSV-driven remediator can act immediately.
    Return a summary dict (counts per mode).
    """
    policies = _load_policies(policies_path) or {}
    rules = policies.get("rules", [])
    defaults = policies.get("defaults", {})
    default_mode = (defaults.get("mode") or "warn").lower()
    default_sev = defaults.get("severity") or "P2"

    # Open readers/writers
    with open(csv_path, "r", encoding="utf-8") as fh:
        reader = csv.DictReader(fh, delimiter=CSV_DELIMITER)
        rows = list(reader)

    actions: List[PolicyAction] = []
    updated_rows: List[dict] = []

    # Determine Flags/Signals column names from first row
    fl_col = _find_col(rows[0], FLAG_COL_CANDIDATES) if rows else None
    sg_col = _find_col(rows[0], SIGNALS_COL_CANDIDATES) if rows else None

    for row in rows:
        flags = _parse_flags(row.get(fl_col or "", ""))
        signals = _parse_signals(row.get(sg_col or "", ""))
        rtype = row.get("ResourceType", "")
        rid = row.get("Resource_ID", row.get("ResourceId", ""))
        region = _get_region(row, signals)
        owner = _get_owner(row, signals)

        matched_new_flags: List[str] = []

        for rule in rules:
            # target match
            targets = [t.lower() for t in rule.get("target", [])]
            if targets and rtype.lower() not in targets:
                continue

            # predicate
            when = rule.get("when") or {}
            if not _eval_pred(row, signals, flags, when):
                continue

            # decision
            then = rule.get("then") or {}
            mode = (then.get("mode") or rule.get("mode") or default_mode).lower()
            severity = then.get("severity") or rule.get("severity") or default_sev
            remediation = then.get("remediation") or ""
            params = then.get("params") or {}
            reason = rule.get("description") or rule.get("id") or ""
            fix = (then.get("fix_snippet") or "").strip()

            actions.append(PolicyAction(
                policy_id=rule.get("id") or rule.get("name") or "<unnamed>",
                mode=mode,
                severity=severity,
                resource_type=rtype,
                resource_id=rid,
                region=region,
                owner=owner,
                remediation=remediation,
                params=params,
                reason=reason,
                fix_snippet=fix,
            ))

            # Optional: inject extra flags for your CSV-driven remediator
            add_flags = then.get("add_flags") or []
            for af in add_flags:
                if af not in flags and af not in matched_new_flags:
                    matched_new_flags.append(af)

        # Build updated row if requested
        if out_updated_csv:
            if matched_new_flags:
                merged = flags + matched_new_flags
                if fl_col:
                    row[fl_col] = ", ".join(merged)
                else:
                    row["Flags"] = ", ".join(merged)
            updated_rows.append(row)

    # Write actions CSV
    if out_actions_csv:
        with open(out_actions_csv, "w", newline="", encoding="utf-8") as fo:
            w = csv.writer(fo, delimiter=CSV_DELIMITER)
            w.writerow([
                "PolicyID","Mode","Severity","ResourceType","Resource_ID","Region","Owner",
                "Remediation","Params","Reason","FixSnippet"
            ])
            for a in actions:
                w.writerow([
                    a.policy_id, a.mode, a.severity, a.resource_type, a.resource_id, a.region, a.owner,
                    a.remediation, json.dumps(a.params, separators=(",",":")), a.reason, a.fix_snippet
                ])

    # Write updated CSV with flags merged
    if out_updated_csv:
        with open(out_updated_csv, "w", newline="", encoding="utf-8") as fu:
            w = csv.DictWriter(fu, fieldnames=rows[0].keys(), delimiter=CSV_DELIMITER)
            w.writeheader()
            for r in updated_rows:
                w.writerow(r)

    # Summary
    summary = {"warn":0,"pr":0,"remediate":0}
    for a in actions:
        if a.mode in summary:
            summary[a.mode] += 1
        else:
            summary[a.mode] = 1
    return summary

if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser(description="Evaluate FinOps policies against scanner CSV.")
    p.add_argument("--csv", required=True, help="Path to scanner CSV (e.g., cleanup_estimates.csv)")
    p.add_argument("--policies", required=True, help="policies.yml or .json")
    p.add_argument("--out-actions", default="policy_actions.csv", help="Output actions CSV")
    p.add_argument("--update-csv", default="", help="Optional output updated CSV with extra flags merged")
    args = p.parse_args()

    out_updated = args["update_csv"] if isinstance(args, dict) else (args.update_csv or None)
    summary = evaluate_policies_for_csv(
        csv_path=args.csv,
        policies_path=args.policies,
        out_actions_csv=args.out_actions,
        out_updated_csv=out_updated,
    )
    print("Policy evaluation summary:", summary)
