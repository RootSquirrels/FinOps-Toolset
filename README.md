# AWS FinOps Toolset — Cost-Saving Checkers & HTML Dashboard

This repository contains a pragmatic FinOps toolkit that surfaces **actionable, non‑obvious AWS savings** that native tools (Trusted Advisor, Compute Optimizer, etc.) often miss. It scans popular services, estimates potential monthly savings, and exports a normalized CSV you can turn into an interactive **HTML dashboard**.

---

## Highlights

- **Broad coverage** of services (EC2, EBS, ECR, EKS, DynamoDB, Kinesis, RDS, CloudFront, KMS, WAFv2, SSM, VPC/TGW, and more).  
- **Fast, batched CloudWatch reads** (`GetMetricData`) and selective deep‑dives to avoid throttling.  
- **Normalized CSV** with derived `Potential_Saving_USD` and compact `Signals` for diagnostics.  
- **Interactive dashboard** (`finops_dashboard.py`) that visualizes savings by resource type and region, with **click‑to‑filter** charts.  
- **Built‑in profiler** (in the main runner) that times each checker and reports slow spots.  
- **S3 & Lambda refactors** reduce metric calls while adding higher‑value flags, with **no CSV regressions**.

---

## What’s in the repo?

- **`FinOps_Toolset_V2_profiler.py`** — main scanner/orchestrator, shared helpers (pricing, retries, CSV writer), and a lightweight profiler.  
- **`finops_dashboard.py`** — one‑file HTML dashboard generator for the CSV export.  
- **`test_all_checkers.py`** — unittest harness that discovers all `check_*` functions and validates CSV invariants.

---

## Quickstart

### 1) Install
```bash
python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install boto3 botocore pandas numpy plotly
```

### 2) Configure AWS credentials
Supply read‑only credentials via environment variables, `~/.aws/credentials`, or SSO. The tool reads across your selected regions using paginated `describe/*` and CloudWatch `GetMetricData`.

### 3) Run the scanner
```bash
python FinOps_Toolset_V2_profiler.py
```
This iterates regions, runs each `check_*` function, and writes a unified `;`‑delimited CSV.

### 4) Generate the dashboard
```bash
python finops_dashboard.py cleanup_estimates.csv -o cleanup_dashboard.html --top 25
```
- Reads the CSV, infers Region if missing from `Signals`, and emits a single HTML file you can open locally or share.

---

## CSV schema (normalized)

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
| `Potential_Saving_USD` | Derived from flags like `PotentialSaving=123.45$` |
| `ApplicationID`, `Application`, `Environment` | Tag‑based ownership |
| `ReferencedIn` | Owning stack or links if detected |
| `FlaggedForReview` | Comma‑separated hints |
| `Confidence` | 0–100 evidence score (optional) |
| `Signals` | Compact diagnostics in one cell (`k=v | k=v`) |

---

## S3 & Lambda — refactor notes

### S3 buckets
- **Batched metrics**: one `GetMetricData` batch per region for `BucketSizeBytes` (Standard/IA/Glacier) and `NumberOfObjects` (AllStorageTypes).  
- **No regression**: `Creation_Date` comes from `list_buckets`, and the **last‑modified helper** is used on significant buckets.  
- **Selective deep checks**: lifecycle and versioning only for large/pricey buckets to avoid API caps.  
- **Value flags**: `NoLifecycleToColderTiers`, `VersioningWONoncurrentExpiration`, `StaleData>Xd`, `EmptyBucket`, `BigBucket`, plus `PotentialSaving=…$` when applicable.

### Lambda functions
- **Batched CloudWatch** per page of functions using helper builders, with a minimal metric set.  
- **No regression**: all rule checks are invoked via your helper registry `LAMBDA_CHECKS` (includes `check_large_package`) and `check_layers` / `check_version_sprawl`. Cost estimation uses your `estimate_lambda_cost`.  
- **CSV‑compatible**: same creation date (`LastModified`), CSV writer, and flag format.

---

## How it works (design)

- **One checker per service**: each `check_*` writes rows via a unified CSV writer that normalizes flags, signals, and potential saving.  
- **API hygiene**: paginators everywhere; parallelism only where safe; heavyweight lookups gated to likely‑savings candidates.  
- **Dashboard**: Plotly charts (savings by type, region heatmap, top findings) with click‑to‑filter interactions; outputs a single HTML file.  
- **Profiler**: each run logs durations and writes a concise per‑checker timing summary.

---

## Tests

```bash
python -m unittest -v
```
The harness stubs AWS calls, runs all `check_*` functions, and validates CSV invariants (shape, derived saving, Signals cell). It also checks determinism across repeated runs.

---

## Extending

1. **Add a checker**: create `def check_service_xyz(writer, <clients...>, **kwargs):` and write rows via `write_resource_to_csv(...)`.  
2. **Register** it in the orchestrator loop next to other checks.  
3. **Expose Signals**: include right‑sized signals; the dashboard can infer Region from them if needed.

---

## IAM permissions (read‑only baseline)

- `ec2:Describe*`, `elasticloadbalancing:Describe*`, `cloudwatch:GetMetricData`, `cloudwatch:GetMetricStatistics`  
- `s3:ListAllMyBuckets`, `s3:GetBucket*`  
- `lambda:List*`, `lambda:Get*`  
- `ecr:Describe*`, `eks:List*`, `eks:Describe*`, `rds:Describe*`, `dynamodb:ListTables`, `dynamodb:DescribeTable`  
- `kms:ListKeys`, `kms:DescribeKey`, `cloudfront:ListDistributions`, `wafv2:List*`, `ssm:DescribeParameters`

Grant on a read‑only role and restrict by region/account as appropriate.

---

## Troubleshooting

- **Throttling / rate limits**: the tool batches `GetMetricData` and gates deep checks. If you still hit caps, reduce concurrency in threaded sections or shorten lookback windows.  
- **CSV missing Region**: ensure your checkers populate `Signals["Region"]` when possible; the dashboard will also attempt to infer it.  
- **Dashboard file too large**: use `--cdn` to avoid embedding Plotly and shrink the HTML output.

---

## License

MIT