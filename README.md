# Cloud Security Posture Scanner

A lightweight Python static-analysis tool for identifying common security posture issues in Terraform configuration before infrastructure changes reach production.

The project is intentionally focused on a small set of high-signal AWS controls rather than pretending to be a complete HCL or cloud-security platform. It demonstrates security-control validation, severity-based findings, remediation guidance, posture metrics, automated testing, and CI enforcement.

## What it detects

| Rule | Severity | Control |
|---|---|---|
| CSPM-001 | Critical | Public S3 bucket ACL |
| CSPM-002 | Critical | World-accessible security-group ingress |
| CSPM-003 | Critical | Publicly accessible RDS database |
| CSPM-004 | High | RDS storage encryption disabled |
| CSPM-005 | High | Wildcard IAM permissions |
| CSPM-006 | Critical | Likely hardcoded credentials/secrets |
| CSPM-007 | Medium | EC2 instance assigned a public IP |
| CSPM-008 | High | CloudTrail logging disabled |
| CSPM-009 | High | S3 encryption explicitly disabled |

## Why this project

Security posture management is largely about continuously evaluating infrastructure against security controls, producing actionable findings, measuring posture, and preventing risky changes from shipping. This project models that workflow on Terraform code.

## Quick start

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python -m pytest -q
```

Scan the intentionally vulnerable example:

```bash
python -m posture_scanner examples/insecure --json reports/insecure.json --fail-on none
```

Scan the secure example and fail CI if a high/critical issue appears:

```bash
python -m posture_scanner examples/secure --fail-on high
```

## Example output

```text
Posture score: 0/100
Findings: 8
  LOW      0
  MEDIUM   1
  HIGH     3
  CRITICAL 4

[CRITICAL] CSPM-002 World-accessible security group ingress
  Resource: aws_security_group.admin
  Evidence: Security group allows world-accessible ingress to all or administrative ports
  Fix: Restrict ingress CIDRs to explicitly trusted networks and minimize exposed ports.
```

The exact score/count above may change as rules are added; use the CLI output as the source of truth.

## Security metrics

Each scan produces:

- total findings
- findings by severity
- findings by control/rule
- a simple 0–100 posture score based on weighted finding severity

The score is intentionally transparent and deterministic; it is a project metric, not a claim of compliance with a specific industry framework.

## CI enforcement

`.github/workflows/ci.yml` runs the unit tests and scans the secure Terraform fixture on every push and pull request. The CLI can return a non-zero exit status when findings meet a configurable severity threshold, which lets it act as a lightweight security gate in CI.

## Docker

```bash
docker build -t posture-scanner .
docker run --rm posture-scanner examples/insecure --fail-on none
```

## Project structure

```text
posture_scanner/
  cli.py       # CLI + JSON reporting
  models.py    # finding/severity model
  parser.py    # targeted Terraform resource-block extraction
  rules.py     # security controls
  scanner.py   # rule execution + posture metrics
examples/
  insecure/    # intentionally vulnerable Terraform
  secure/      # remediated Terraform
 tests/
  test_scanner.py
```

## Design notes

This is a targeted static analyzer, not a full Terraform/HCL interpreter. It evaluates supported resource patterns directly from Terraform source and avoids claiming full semantic understanding of modules, variable interpolation, provider defaults, or generated plans. A production-grade extension would parse Terraform plan JSON, resolve modules, map findings to a formal control framework, and integrate cloud-provider APIs for runtime posture validation.

## Possible extensions

- parse `terraform show -json` output for plan-aware analysis
- add CIS/AWS control mappings
- SARIF output for GitHub code scanning
- suppression files with documented risk acceptance
- baseline/diff mode for pull requests
- trend metrics across commits
