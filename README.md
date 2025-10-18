# AWS FinOps Toolset — Scanner, Dashboard & Auto‑Remediation (CSV‑Driven)

This repository contains a pragmatic FinOps toolkit that surfaces **actionable AWS savings** (often missed by native tools), exports a normalized CSV, renders an **HTML dashboard**, and now **optionally auto‑remediates “easy” items** directly **from the CSV**.

---

## Highlights

- **Broad coverage** via `check_*` modules (EC2, EBS, ECR, EKS, DynamoDB, RDS, CloudFront, KMS, WAFv2, SSM, VPC/TGW, Lambda, S3…).
- **Fast CloudWatch reads** using batched `GetMetricData` and **selective deep‑dives** to avoid throttling.
- **Normalized CSV** with compact `Signals` and flags; dashboard is a single self‑contained HTML file.
- **S3 & Lambda revamps**: faster scans, more value flags, **no regressions** to CSV schema.
- **CSV‑driven auto‑remediation** (`auto_remediations_from_csv.py`) that fixes “easy wins” (confidence=100) **without rescanning AWS**.

---

## What’s in the repo?

- **`FinOps_Toolset_V2_profiler.py`** — main scanner/orchestrator, shared helpers (pricing, retries, CSV writer), built‑in profiler.
- **`finops_dashboard.py`** — one‑file HTML dashboard generator for the CSV export.
- **`auto_remediations_from_csv.py`** — **auto‑remediation from CSV** (no re‑scan). Handles ENIs, EIPs, CloudWatch Logs retention, EBS volumes, S3 empty buckets.
- **`test_all_checkers.py`** — unittest harness that discovers all `check_*` functions and validates CSV invariants.

---

## Quickstart

### 1) Install
```bash
python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt || pip install boto3 botocore pandas numpy plotly
```

### 2) Configure AWS credentials
Provide read‑only credentials via environment variables, `~/.aws/credentials`, or SSO. The scanner uses AWS paginators and `GetMetricData` across your selected regions.

### 3) Run the scanner
```bash
python FinOps_Toolset_V2_profiler.py
```
This iterates regions, runs each `check_*`, and writes a unified `;`‑delimited CSV (e.g., `cleanup_estimates.csv`).

### 4) Generate the dashboard
```bash
python finops_dashboard.py cleanup_estimates.csv -o cleanup_dashboard.html --top 25
```
This reads the CSV, infers Region from `Signals` when needed, and emits a single HTML file you can open locally or share.

### 5) (Optional) Auto‑remediate from CSV — **no re‑scan**
Dry‑run (safe default):
```bash
python auto_remediations_from_csv.py cleanup_estimates.csv --do-eni --do-eip --do-cwl --do-ebs --do-s3
```
Apply changes:
```bash
python auto_remediations_from_csv.py cleanup_estimates.csv --execute --do-eni --do-eip --do-cwl --do-ebs --do-s3
```
You can enable just specific actions; see options below.

---

## CSV schema (normalized)

| Column | Meaning |
|---|---|
| `Resource_ID` | ARN or unique identifier |
| `Name` | Human‑readable name |
| `ResourceType` | e.g., `ALB`, `LambdaFunction`, `S3Bucket`, `NetworkInterface` |
| `OwnerId` | AWS Account ID |
| `State` | Resource state |
| `Creation_Date` | ISO‑8601 |
| `Storage_GB` | Storage size (if applicable) |
| `Object_Count` | e.g., S3 `NumberOfObjects` |
| `Estimated_Cost_USD` | Monthly estimate |
| `Potential_Saving_USD` | Derived from flags like `PotentialSaving=123.45$` |
| `ApplicationID`, `Application`, `Environment` | Tag‑based ownership |
| `ReferencedIn` | Owning stack or links if detected |
| `FlaggedForReview`/`Flags` | Comma/pipe/semicolon list of flags |
| `Confidence` | Optional 0–100 evidence score |
| `Signals` | Compact diagnostics in one cell (`k=v | k=v`) |

> The dashboard expects `Signals` to remain a single cell; Region can be inferred from `Signals["Region"]` or AZ‑to‑region fallback.

---

## S3 & Lambda — refactor notes

### S3 buckets
- Batched `GetMetricData` per region for `BucketSizeBytes` (Standard/IA/Glacier) and `NumberOfObjects` (AllStorageTypes).
- **No regression**: `Creation_Date` from `list_buckets`; uses your last‑modified helper on significant buckets.
- Selective deep checks (lifecycle/versioning) only for large/expensive buckets to avoid API caps.
- Value flags: `NoLifecycleToColderTiers`, `VersioningWONoncurrentExpiration`, `StaleData>Xd`, `EmptyBucket`, `BigBucket` + `PotentialSaving=…$`.

### Lambda functions
- Paged & batched CloudWatch metric queries with a minimal set; concurrency derived when helpful.
- **No regression**: rule checks invoked via your `LAMBDA_CHECKS` registry (includes `check_large_package`) plus `check_layers` / `check_version_sprawl`; cost via `estimate_lambda_cost`.
- Same creation date field and CSV writer.

---

## Auto‑remediation (CSV‑driven)

**File:** `auto_remediations_from_csv.py` — acts only on what the scanner already found.  
**Defaults:** dry‑run; explicit opt‑in per resource type; lightweight verification before changes.

### Supported actions
| Type | What it does | Required CSV flags (examples) |
|---|---|---|
| ENI | Delete **unattached** network interfaces. Optional **detach+delete** when explicitly flagged. | `confidence=100` + `unattached`/`orphaneni`/`safedelete` (and `detachable` for detach path) |
| EIP | Release **unassociated** Elastic IPs. | `confidence=100` + `unassociated`/`unused`/`safe_release` |
| CloudWatch Logs | Set **retention policy** (default 30 days) when missing. | `confidence=100` + `noretention` or `retention=0` (optional `retention=30`) |
| EBS | Delete **unattached** volumes. | `confidence=100` + `unattached`/`available`/`safedelete` |
| S3 | Delete **empty** buckets (also checks versions/delete markers if `--verify`). | `confidence=100` + `emptybucket`/`empty_bucket`/`safedelete` |

> The module reads **Region** from `Signals` (`Region=...`). If absent, it tries AZ→region (e.g., `eu-west-1a` → `eu-west-1`) or falls back to your default AWS region.

### Common CLI patterns
Dry‑run specific actions:
```bash
# Only ENI and EIP
python auto_remediations_from_csv.py cleanup_estimates.csv --do-eni --do-eip
```
Execute everything (only rows with correct flags and confidence=100 are touched):
```bash
python auto_remediations_from_csv.py cleanup_estimates.csv --execute --do-eni --do-eip --do-cwl --do-ebs --do-s3
```
ENI detach+delete (for rows flagged as detachable):
```bash
python auto_remediations_from_csv.py cleanup_estimates.csv --execute --do-eni --allow-detach
```
Trust CSV 100% (skip verification calls for speed):
```bash
python auto_remediations_from_csv.py cleanup_estimates.csv --execute --do-ebs --do-s3 --no-verify
```

### Safety model
- **Confidence gate**: only rows with `confidence=100` (or equivalent) are eligible.
- **Verify by default**: lightweight `describe/*` or `list*` double‑checks the CSV before changes. Use `--no-verify` to skip.
- **Opt‑in per type**: nothing runs unless you pass `--do-eni`, `--do-eip`, etc.
- **Idempotent operations**: all calls use AWS DryRun when not executing.

---

## GitHub Actions (nightly, with OIDC)

Example workflow to run the scanner and attach artifacts; you can add remediation in a second step if desired.

```yaml
name: FinOps Nightly
on:
  schedule: [{ cron: "15 2 * * *" }]
  workflow_dispatch: {}
permissions:
  id-token: write   # OIDC
  contents: read
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with: { python-version: "3.11" }
      - name: Configure AWS (OIDC)
        uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: arn:aws:iam::<ACCOUNT_ID>:role/finops-readonly
          aws-region: eu-west-1
      - name: Install deps
        run: |
          python -m pip install --upgrade pip
          pip install -r requirements.txt || pip install boto3 botocore pandas numpy plotly
      - name: Run scanner + dashboard
        run: |
          python FinOps_Toolset_V2_profiler.py
          python finops_dashboard.py cleanup_estimates.csv -o cleanup_dashboard.html --top 25
      - name: (Optional) CSV-driven auto-remediation (dry-run)
        run: |
          python auto_remediations_from_csv.py cleanup_estimates.csv --do-eni --do-eip --do-cwl --do-ebs --do-s3
      - name: Upload artifacts
        uses: actions/upload-artifact@v4
        with:
          name: finops-reports
          path: |
            cleanup_estimates.csv
            cleanup_dashboard.html
          retention-days: 14
```

> To execute real changes in CI, add `--execute` to the remediation step and ensure the assumed role allows the necessary write actions below.

---

## IAM permissions

**Scanner (read‑only baseline):**
- `ec2:Describe*`, `elasticloadbalancing:Describe*`, `cloudwatch:GetMetricData`, `cloudwatch:GetMetricStatistics`
- `s3:ListAllMyBuckets`, `s3:GetBucket*`
- `lambda:List*`, `lambda:Get*`
- `ecr:Describe*`, `eks:List*`, `eks:Describe*`, `rds:Describe*`, `dynamodb:ListTables`, `dynamodb:DescribeTable`
- `kms:ListKeys`, `kms:DescribeKey`, `cloudfront:ListDistributions`, `wafv2:List*`, `ssm:DescribeParameters`

**Auto‑remediation (write, only for enabled actions):**
- ENI: `ec2:DeleteNetworkInterface`, `ec2:DetachNetworkInterface`
- EIP: `ec2:ReleaseAddress`, `ec2:DescribeAddresses`
- CW Logs: `logs:PutRetentionPolicy`, `logs:DescribeLogGroups`
- EBS: `ec2:DeleteVolume`, `ec2:DescribeVolumes`
- S3: `s3:DeleteBucket`, `s3:ListBucket`, `s3:ListBucketVersions`, `s3:HeadBucket`

Scope by region/account and consider tag‑based conditions (e.g., block resources with `DoNotDelete=true`).

---

## Tests

```bash
python -m unittest -v
```
The harness stubs AWS calls, runs all `check_*`, and validates CSV invariants (shape, derived saving, single‑cell `Signals`).

---

## Troubleshooting

- **Throttling / rate limits**: scanner batches `GetMetricData` and gates heavy checks; reduce threaded sections or shorten lookback windows if needed.  
- **Region missing**: ensure checkers include `Signals["Region"]`; the dashboard and auto‑remediator will infer from AZ if necessary.  
- **Dashboard size**: use `--cdn` to avoid embedding Plotly if you need a smaller HTML.

---

## License

MIT
