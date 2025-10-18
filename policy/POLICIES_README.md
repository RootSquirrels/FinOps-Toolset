# Policies-as-Code (FinOps Toolset)

This is the first scalable version of a **policies-as-code** framework that evaluates your scanner’s CSV and emits:
- a `policy_actions.csv` with **mode/severity/remediation** per matched rule;
- optionally an **updated CSV** where matching rows get extra **Flags** so your existing CSV-driven auto-remediator can act immediately.

## Files
- `finops_toolset/policy/engine.py` — policy loader & evaluator
- `policies.yml` — starter rules (CloudWatch Logs retention, S3 lifecycle, EBS/ENI cleanup, NAT advisory)

## Use
```bash
# Evaluate policies against a CSV and create actions + an updated CSV with extra flags
python -m finops_toolset.policy.engine \
  --csv cleanup_estimates.csv \
  --policies policies.yml \
  --out-actions policy_actions.csv \
  --update-csv cleanup_estimates.policy.csv
```

- `policy_actions.csv` columns: `PolicyID, Mode, Severity, ResourceType, Resource_ID, Region, Owner, Remediation, Params, Reason, FixSnippet`.
- If you passed `--update-csv`, new **Flags** are merged into the original CSV rows (e.g., `confidence=100`, `unattached`, `noretention`). You can then feed that CSV directly to your **CSV-driven auto-remediator**.

## Policy syntax (YAML)
Each rule has: `id`, optional `description`, `target`, `when`, and `then`.

- `target`: list of resource type aliases; compared against `ResourceType` (case-insensitive).
- `when`: nested boolean logic with operators:
  - `all`, `any`, `not`
  - Leaf predicates with `field` + one of: `eq`, `neq`, `in`, `nin`, `gt`, `gte`, `lt`, `lte`, `contains_any`, `contains_all`
  - `regex: { field: "Name", pattern: "^prod-" }`
  - `exists: true/false`
  - Fields can be top-level CSV columns or `Signals.<Key>` (e.g., `Signals.Region`).
- `then`: decision & outputs
  - `mode`: `warn | pr | remediate`
  - `severity`: e.g., `P2`
  - `remediation`: string identifier, e.g., `logs.set_retention_days`
  - `params`: free-form dict for the remediator/PR bot
  - `add_flags`: a list of flags injected into the CSV row (if `--update-csv` provided)
  - `fix_snippet`: optional snippet (CLI/IaC) for humans or PR descriptions

## Extending
- Add more operators in `_eval_pred` as needed (e.g., `startswith`).
- Add mapping from `remediation` → real PR templates or CLI commands in your PR bot.
- Consider adding a **policy pack** per team/OU and merge them at runtime.

## Requirements
- Standard library only; optional `pyyaml` for YAML support. If `pyyaml` is not installed, provide JSON policies instead.

## Integration flow
1. Run scanner → `cleanup_estimates.csv`
2. Run policy engine → `policy_actions.csv` and `cleanup_estimates.policy.csv`
3. Run CSV remediator on `cleanup_estimates.policy.csv` (dry-run, then execute)
4. (Optional) Create PRs/tickets from `policy_actions.csv`
