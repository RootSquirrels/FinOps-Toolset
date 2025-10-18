# AWS FinOps Toolset — Cost-Saving Checkers & HTML Dashboard

This repository contains a pragmatic FinOps toolkit that surfaces **actionable, non‑obvious AWS savings** that native tools (Trusted Advisor, Compute Optimizer, etc.) often miss. It scans popular services, estimates potential monthly savings, and exports a normalized CSV you can turn into an interactive **HTML dashboard**.

---

## Highlights

- **Broad coverage** of services (EC2, EBS, ECR, EKS, DynamoDB, Kinesis, RDS, CloudFront, KMS, WAFv2, SSM, VPC/TGW… and more).
- **Fast, batched CloudWatch reads** (via `GetMetricData`) and selective deep-dives to avoid throttling.
- **Normalized CSV** with derived `Potential_Saving_USD`, confidence, and compact “Signals” for diagnostics.
- **Interactive dashboard** (`finops_dashboard.py`) that visualizes savings by resource type and region, with click‑to‑filter charts.
- **Built‑in profiler** to time each checker and export per‑check timings.
- **S3 & Lambda refactors** (added here) that reduce metric calls while adding higher‑value flags and keeping CSV compatibility.

> The dashboard generator usage and CSV schema are documented inline in the code and tests. fileciteturn19file10 fileciteturn19file6

---

## What’s in the box?

- **`FinOps_Toolset_V2_profiler.py`** — the main scanner and checkers, plus pricing constants, retry/backoff, CSV writer, and a simple profiler. It orchestrates “check_*” functions across regions and writes a consolidated CSV. fileciteturn19file14 fileciteturn19file11 fileciteturn19file18
- **`finops_dashboard.py`** — a one‑file HTML dashboard generator for the CSV export (Plotly‑based, self‑contained by default). fileciteturn19file10
- **`test_all_checkers.py`** — a lightweight test harness that discovers every `check_*` function, runs them with Null AWS stubs, and asserts CSV invariants. Run with `python -m unittest -v`. fileciteturn19file19

---

## Quickstart

### 1) Install deps

```bash
python -m venv .venv && source .venv/bin/activate  # on Windows: .venv\Scripts\activate
pip install boto3 botocore pandas numpy plotly
```

### 2) Configure AWS credentials

Provide read‑only credentials (env vars, `~/.aws/credentials`, or SSO). The tool uses paginated `describe/*` and CloudWatch `GetMetricData` across your selected regions.

### 3) Run the scanner

```bash
python FinOps_Toolset_V2_profiler.py
```

The script iterates your configured regions and runs each checker (see the `run_check(...)` calls), exporting a unified CSV (default name referenced in the code comments). fileciteturn19file14 fileciteturn19file15

### 4) Generate the dashboard

```bash
python finops_dashboard.py cleanup_estimates.csv -o cleanup_dashboard.html --top 25
```

- Reads your `;`‑delimited CSV.
- Adds Region if missing by parsing Signals.
- Outputs a single HTML file that you can open locally or share. fileciteturn19file10 fileciteturn19file3

---

## CSV schema

The writer normalizes rows into this schema (derived columns are handled automatically): fileciteturn19file18 fileciteturn19file12

| Column | Meaning |
|---|---|
| `Resource_ID` | ARN or unique identifier |
| `Name` | Human‑readable name |
| `ResourceType` | e.g., `ALB`, `LambdaFunction`, `S3Bucket` |
| `OwnerId` | AWS Account ID |
| `State` | Resource state |
| `Creation_Date` | ISO‑8601 |
| `Storage_GB` | Storage size (if applicable) |
| `Object_Count` | e.g., S3 `NumberOfObjects` |
| `Estimated_Cost_USD` | Monthly estimate |
| `Potential_Saving_USD` | Auto‑derived from `flags` like `PotentialSaving=123.45$` |
| `ApplicationID`, `Application`, `Environment` | Tag‑based ownership |
| `ReferencedIn` | Links or owning stack if detected |
| `FlaggedForReview` | Comma‑separated hints |
| `Confidence` | 0–100 evidence score (optional) |
| `Signals` | Compact diagnostics (`k=v | k=v`) kept in **one cell** |

> The tests assert that Signals remain in one cell and that `Potential_Saving_USD` is derived from flags. fileciteturn19file6

---

## S3 & Lambda

### S3 buckets
- **Batched metrics**: one `GetMetricData` batch per region for `BucketSizeBytes` (Standard/IA/Glacier) and `NumberOfObjects` (AllStorageTypes).  
- **No regression**: `Creation_Date` comes from `list_buckets`, and we use your **last‑modified helper** on significant buckets.
- **Selective deep checks**: lifecycle + versioning only for large/pricey buckets to avoid API caps.
- **Value flags**: `NoLifecycleToColderTiers`, `VersioningWONoncurrentExpiration`, `StaleData>Xd`, `EmptyBucket`, `BigBucket`, plus `PotentialSaving=…$` where applicable.

### Lambda functions
- **Batched CloudWatch** per page of functions using helper builders (`build_mdq`, `_cw_id_safe`), with minimal metric set (Invocations, Errors, Duration, Concurrency/PCU). fileciteturn19file9 fileciteturn19file17
- **No regression**: we **do not** inline checks; we **call your helper registry** `LAMBDA_CHECKS` (which includes `check_large_package`) and use `check_layers` / `check_version_sprawl`. Cost estimation uses your `estimate_lambda_cost`. fileciteturn19file17
- **CSV compatibility**: same creation date field (`LastModified`), same writer, same flags behavior.

---

## How it works (design notes)

- **One checker per service**: Each `check_*` function writes zero or more rows via a unified CSV helper that normalizes flags, signals, and potential saving. The tests auto‑discover and run all `check_*` functions. fileciteturn19file18 fileciteturn19file8
- **API hygiene**: Paginators everywhere, parallelism only where safe (e.g., ECR repo scans in a thread pool), and heavy lookups gated to large/expensive candidates. fileciteturn19file13
- **Dashboard**: Plotly charts (savings by type, region heatmap, top findings) with click‑to‑filter interactions; generates a single HTML file. fileciteturn19file3
- **Profiler**: Each run logs durations and writes a CSV/summary for the slowest checks. (See orchestrator section near the `run_check(...)` calls.) fileciteturn19file14

---

## Running tests

```bash
python -m unittest -v
```

The harness stubs AWS calls, runs all `check_*` functions, and validates CSV invariants (shape, derived potential saving, Signals cell). It also checks determinism across repeated runs. fileciteturn19file1 fileciteturn19file4

---

## Extending the toolset

1. **Add a checker**: create `def check_service_xyz(writer, <clients...>, **kwargs):` that appends rows with `write_resource_to_csv(...)`. fileciteturn19file18  
2. **Register it**: call it from the orchestrator loop alongside other `run_check(...)` calls. fileciteturn19file14  
3. **Expose Signals**: include right‑sized signals; the dashboard infers Region if missing. fileciteturn19file0

---

## IAM permissions (read‑only baseline)

- `ec2:Describe*`, `elasticloadbalancing:Describe*`, `cloudwatch:GetMetricData`, `cloudwatch:GetMetricStatistics`, `s3:ListAllMyBuckets`, `s3:GetBucket*`, `lambda:List*`, `lambda:Get*`, `ecr:Describe*`, `eks:List*`, `eks:Describe*`, `rds:Describe*`, `dynamodb:ListTables/DescribeTable`, `kms:ListKeys/DescribeKey`, `cloudfront:ListDistributions`, `wafv2:List*`, `ssm:DescribeParameters`, etc.  
Grant on a read‑only role or scope via IAM Access Analyzer as needed.

---

## Troubleshooting

- **Throttling / rate‑limits**: The tool batches `GetMetricData` and gates deep checks, but if you still hit caps, reduce concurrency in threaded sections (e.g., ECR worker pool) or shorten lookback windows. fileciteturn19file13
- **CSV missing Region**: The dashboard will attempt to extract Region from Signals; ensure your checkers populate `Signals["Region"]` where possible. fileciteturn19file0
- **Dashboard too large**: Use `--cdn` to avoid embedding Plotly and shrink the HTML size. fileciteturn19file0

---

## License


