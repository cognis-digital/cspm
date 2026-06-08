# Demo 01 — Basic CSPM scan

This demo runs CSPM against a small, realistic cloud config export
(`account_export.json`) representing one AWS-style account you own. It mixes
clean and misconfigured resources so the report shows a range of severities.

## What's in the export

- **buckets**
  - `prod-static-assets` — intentionally public CDN origin (will still flag; verify).
  - `customer-backups` — **public-read-write** with no encryption (CRITICAL).
  - `app-logs` — private but missing versioning/logging (LOW).
- **security_groups**
  - `sg-web` — 80/443 open to the world (fine; only non-standard ports flag MEDIUM).
  - `sg-db` — PostgreSQL (5432) and SSH (22) open to `0.0.0.0/0` (CRITICAL).
  - `sg-legacy` — all protocols/ports open to the world (CRITICAL).
- **iam_users**
  - `deploy-bot` — two active access keys, one 140 days old.
  - `alice-admin` — admin with console access and **no MFA** (CRITICAL).
- **iam_policies**
  - `legacy-allow-all` — `Action:*` on `Resource:*` (HIGH).

## Run it

```sh
# Human-readable table
python -m cspm scan demos/01-basic/account_export.json

# Machine-readable JSON for pipelines
python -m cspm scan demos/01-basic/account_export.json --format json

# Shareable self-contained HTML report (the tool's UI)
python -m cspm scan demos/01-basic/account_export.json --format html -o report.html
```

The process exits non-zero when findings at or above `--fail-on`
(default `LOW`) are present — handy as a CI gate.
