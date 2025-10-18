# AWS FinOps Toolset — Scanner, Dashboard & CSV-Driven Auto-Remediation

Find real, actionable AWS savings that native tools often miss.  
This toolkit scans your AWS estate, writes a **normalized CSV** of findings, ships a **single-file HTML dashboard**, and can **auto-remediate “easy wins”** directly from the CSV (no rescan).

---

## ⭐ Highlights

- **Broad coverage**: EC2 / EBS / ECR / EKS / Lambda / S3 / DynamoDB / RDS / ALB / NLB / CloudFront / KMS / WAFv2 / SSM / VPC & NAT …
- **Fast & scalable**: batched CloudWatch `GetMetricData` with internal ID sanitization; fewer calls, fewer throttles.
- **No-regression refactors**: S3 & Lambda keep original CSV fields (e.g., S3 bucket creation date, Lambda helper usage).
- **Clean CSV**: consistent schema with compact `Signals` and actionable `Flags` + optional `Confidence`.
- **Auto-remediation (CSV-driven)**: delete orphan ENIs/EIPs/EBS, set CW Logs retention, and remove empty S3 buckets — **from CSV only**, with dry-run by default.

---

## Repo layout

```
FinOps-Toolset/
├─ FinOps_Toolset_V2_profiler.py      # Orchestrator & profiler (scanner entrypoint)
├─ finops_dashboard.py                # Generates a single self-contained HTML report
├─ auto_remediations_from_csv.py      # CSV-driven auto-remediation (dry-run by default)
├─ test_all_checkers.py               # Unit harness for checkers + CSV invariants
├─ finops_toolset/
│  ├─ config.py                       # Regions, thresholds, feature toggles
│  ├─ pricing.py                      # Centralized price book (region-aware helpers)
│  └─ aws/
│     └─ cloudwatch.py                # CloudWatchBatcher (add_q, internal ID sanitization, helpers)
└─ requirements.txt
```

---

## Quickstart

### 1) Install
```bash
python -m venv .venv && source .venv/bin/activate    # Windows: .venv\Scripts\activate
pip install -r requirements.txt || pip install boto3 botocore pandas numpy plotly
```

### 2) Configure AWS credentials
Use environment variables, `~/.aws/credentials`, or SSO. Grant **read** for scanning; grant **write** only if you’ll run remediation.

### 3) Run the scanner
```bash
python FinOps_Toolset_V2_profiler.py
# writes cleanup_estimates.csv by default
```

### 4) Build the dashboard
```bash
python finops_dashboard.py cleanup_estimates.csv -o cleanup_dashboard.html --top 25
# open cleanup_dashboard.html locally or share it
```

### 5) (Optional) Auto-remediate from CSV — no rescan
Dry-run (safe):
```bash
python auto_remediations_from_csv.py cleanup_estimates.csv --do-eni --do-eip --do-cwl --do-ebs --do-s3
```
Apply changes:
```bash
python auto_remediations_from_csv.py cleanup_estimates.csv --execute --do-eni --do-eip --do-cwl --do-ebs --do-s3
```
Skip verification (trust CSV) for speed:
```bash
python auto_remediations_from_csv.py cleanup_estimates.csv --execute --do-ebs --do-s3 --no-verify
```

---

## CSV schema (normalized)

| Column                | Meaning                                                                                 |
|-----------------------|-----------------------------------------------------------------------------------------|
| `Resource_ID`         | ARN or unique identifier                                                                |
| `Name`                | Human-readable name (tag-based when available)                                          |
| `ResourceType`        | e.g., `EC2Instance`, `ALB`, `LambdaFunction`, `S3Bucket`, `KMSKey`                      |
| `OwnerId`             | AWS Account ID                                                                          |
| `State`               | Resource state                                                                          |
| `Creation_Date`       | ISO-8601                                                                                |
| `Storage_GB`          | Storage size (when applicable)                                                          |
| `Object_Count`        | e.g., S3 `NumberOfObjects`                                                               |
| `Estimated_Cost_USD`  | Monthly estimate (varies by resource; conservative where needed)                        |
| `Potential_Saving_USD`| Optional numeric estimate for obvious wins                                              |
| `ApplicationID`       | Tag value                                                                               |
| `Application`         | Tag value                                                                               |
| `Environment`         | Tag value                                                                               |
| `ReferencedIn`        | Owning stack / references (when detected)                                               |
| `Flags`               | Semicolon or pipe delimited flags                                                       |
| `Confidence`          | Optional 0–100 evidence score                                                           |
| `Signals`             | Compact diagnostics in a single cell: `k=v | k=v` (includes `Region` for dashboard/ops) |

**Signals conventions**  
- Must be **one cell**; `k=v` pairs joined by `|` (spaces optional).  
- Prefer `Region` to be present; if absent, tools will infer from AZ where possible.  
- Keep numeric values normalized (integers or fixed decimals).

---

## What the scanner actually checks (high level)

- **EC2**: idle instances (CPU/Net/Disk), monthly compute via `_ec2_hourly_price`, tagging hygiene.
- **ALB/NLB**: requests/processed bytes & LCU/NLCU hours; idle ALBs/NLBs flagged with `confidence=100`.
- **Lambda**: invokes helper checks (`check_large_package`, `check_low_traffic`, `check_error_rate`, `check_low_concurrency`, `check_version_sprawl`, ARM64 candidates); requests + GB-seconds cost.
- **S3**: size/objects (batched), lifecycle/versioning signals, stale data, big buckets, potential lifecycle savings; **keeps bucket creation date**.
- **DynamoDB**: provisioned vs consumed R/W CU, throttles, storage; low-utilization flags for PROVISIONED; optional GSI metrics capped by `_DDB_GSI_METRICS_LIMIT`.
- **EFS**: Standard/IA/Archive storage, IO, burst credits, lifecycle suggestions; **cost via `estimate_efs_cost`** including **mount targets**.
- **CloudFront**: requests/bytes, error rates, idle heuristic; `UsesDedicatedIPCustomSSL` flag for costly dedicated IP custom SSL.
- **KMS**: rotation status, enabled/disabled/pending deletion, last seen via CloudTrail (bounded), ~$1/key/mo cost; `RotationOff` & `NoRecentUseXd`.

> All checkers write rows through a **single CSV writer** to keep the schema consistent.

---

## Auto-remediation (from CSV)

**Script:** `auto_remediations_from_csv.py`  
**Safety model:** dry-run by default; only acts on rows with `confidence=100` and matching flags; verifies state unless `--no-verify`.

Supported actions:

| Type             | What it does                                         | Requires flags in CSV                                  |
|------------------|------------------------------------------------------|--------------------------------------------------------|
| ENI              | Delete **unattached** ENIs (opt. detach+delete)     | `confidence=100` + `unattached`/`orphaneni` (`detachable` for detach) |
| EIP              | Release **unassociated** EIPs                        | `confidence=100` + `unassociated`/`safe_release`       |
| CloudWatch Logs  | Put **retention policy** (default 30 days)           | `confidence=100` + `noretention` or `retention=0`      |
| EBS              | Delete **unattached** volumes                         | `confidence=100` + `unattached`/`available`            |
| S3               | Delete **empty** buckets (verifies versions/markers) | `confidence=100` + `emptybucket`/`empty_bucket`        |

Examples:
```bash
# Dry-run only ENI + EIP
python auto_remediations_from_csv.py cleanup_estimates.csv --do-eni --do-eip

# Execute all supported actions (still gated by flags & confidence)
python auto_remediations_from_csv.py cleanup_estimates.csv --execute --do-eni --do-eip --do-cwl --do-ebs --do-s3

# Trust the CSV (skip verification) for speed
python auto_remediations_from_csv.py cleanup_estimates.csv --execute --do-ebs --do-s3 --no-verify
```

---

## Configuration & pricing

- **Regions & thresholds**: `finops_toolset/config.py`  
  - `REGIONS`, S3/DDB/EFS/Lambda thresholds, lookbacks, CW periods, worker caps, etc.
- **Prices**: `finops_toolset/pricing.py`  
  - Call `get_price("SERVICE", "KEY")` or region-aware `get_price_r("SERVICE", "KEY", region, default)`.

**Tip:** prefer `get_price_r` where region differences exist (e.g., ALB/NLB, NAT). For internal instance pricing, use your existing `_ec2_hourly_price(instance_type, region)`.

---

## Performance & scale

- All CloudWatch reads go through **`CloudWatchBatcher`**:
  - Use `batch.add_q(id_hint=..., namespace=..., metric=..., dims=..., stat=..., period=...)`.
  - You can use **natural `id_hint`s** (with `-` or `.`); IDs are sanitized internally and mapped back.
  - Helpers: `CloudWatchBatcher.latest(series, default)` and `.sum(series)` keep call-sites clean.
- Reduce lookback windows & increase periods for faster runs.
- DynamoDB: `_DDB_META_WORKERS` controls Describe/Tags/TTL/PITR parallelism; `_DDB_GSI_METRICS_LIMIT` caps GSI metrics (set to `0` to skip).

---

## Architecture (short)

1. **Orchestrator** loops `REGIONS`, instantiates **regional clients**, and calls `check_*` functions.  
2. **Checkers** fetch metadata + batched metrics and write rows via a shared CSV writer.  
3. **Dashboard** reads the CSV and builds an interactive HTML (heatmaps, top findings, filters).  
4. **Auto-remediator** consumes the CSV and applies **only** safe, flagged actions.

---

## CI example (nightly with OIDC)

```yaml
name: FinOps Nightly
on:
  schedule: [{ cron: "15 2 * * *" }]
  workflow_dispatch: {}
permissions: { id-token: write, contents: read }
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with: { python-version: "3.11" }
      - uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: arn:aws:iam::<ACCOUNT_ID>:role/finops-readonly
          aws-region: eu-west-1
      - run: pip install -r requirements.txt || pip install boto3 botocore pandas numpy plotly
      - run: python FinOps_Toolset_V2_profiler.py
      - run: python finops_dashboard.py cleanup_estimates.csv -o cleanup_dashboard.html --top 25
      - run: python auto_remediations_from_csv.py cleanup_estimates.csv --do-eni --do-eip --do-cwl --do-ebs --do-s3
      - uses: actions/upload-artifact@v4
        with:
          name: finops-reports
          path: |
            cleanup_estimates.csv
            cleanup_dashboard.html
```

---

## IAM permissions

**Scanner (read-only):**  
`ec2:Describe*`, `elasticloadbalancing:Describe*`, `cloudwatch:GetMetricData`, `cloudwatch:GetMetricStatistics`,  
`s3:ListAllMyBuckets`, `s3:GetBucket*`, `lambda:List*`, `lambda:Get*`, `ecr:Describe*`, `eks:List*`, `eks:Describe*`,  
`rds:Describe*`, `dynamodb:ListTables`, `dynamodb:DescribeTable`, `kms:ListKeys`, `kms:DescribeKey`,  
`cloudfront:ListDistributions`, `wafv2:List*`, `ssm:DescribeParameters`

**Auto-remediation (write, per action):**  
- ENI: `ec2:DeleteNetworkInterface`, `ec2:DetachNetworkInterface`  
- EIP: `ec2:ReleaseAddress`, `ec2:DescribeAddresses`  
- CW Logs: `logs:PutRetentionPolicy`, `logs:DescribeLogGroups`  
- EBS: `ec2:DeleteVolume`, `ec2:DescribeVolumes`  
- S3: `s3:DeleteBucket`, `s3:ListBucket`, `s3:ListBucketVersions`, `s3:HeadBucket`

Scope to regions/accounts; consider tag guards like `DoNotDelete=true`.

---

## Troubleshooting

- **All zeros from CloudWatch metrics**  
  Use the batcher’s `add_q()`; it sanitizes IDs automatically. If you hand-craft `Id`s with dashes, `GetMetricData` returns nothing.
- **CloudFront metrics missing**  
  Make sure you pass a **us-east-1** CloudWatch client; CF metrics live there and require `Region="Global"` dimension.
- **“Unknown service ‘KMS’”**  
  Boto3 service names are **lower-case**: `boto3.client("kms")`, `boto3.client("cloudtrail")`, etc. Add a small guard: `kms.meta.service_model.service_name == "kms"`.
- **Throttling**  
  Shorten lookbacks, raise periods, or reduce per-service parallelism knobs (e.g., `_DDB_META_WORKERS`).

---

## Roadmap (next wins)

- CloudFront conservative pricing (requests + egress) behind a feature flag; add potential saving for Dedicated-IP SSL when idle.  
- DynamoDB on-demand (OD) compute estimation using OD RRU/WRU where volumes justify it.  
- “Golden CSV” tests per checker (stable fixtures, schema/assertions).  
- Additional auto-remediations (opt-in): idle ALBs/NLBs delete, KMS rotation enable where safe, EFS lifecycle set.

---

## Contributing

PRs welcome! Keep changes modular:
- Use the batcher (`add_q`) for all CW metrics.
- Don’t regress the CSV schema; add new signals/flags instead.
- Default to **conservative** pricing where behavior isn’t obvious.
- Include a unit test or a small fixture when adding a new checker.

---

## License

MIT
