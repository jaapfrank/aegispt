# Active Task

## Title

Cloud-Native Identity & Attack Path Graphing

## Promoted From

`codex/tasks/backlog-300-cloud-native-attack-path-graphing.json`

## Goal

Integrate Cloud (AWS/Azure/GCP) IAM vulnerabilities directly into the attack graph. Show how a web vulnerability (like SSRF extracting EC2 metadata) directly links to Cloud Lateral Movement (like assuming an overly permissive IAM role). This closes the gap between AppSec and CloudSec.

## Scope

Remediation logic, attack graphing, and continuous execution.

## Constraints

- Do not implement until this package is the single active task in NEXT_TASK.md.
- Ensure these features generate measurable, provable evidence such as a retest log or a drift report rather than just UI dashboards.
- Do not create runtime self-modification or uncontrolled plugin installation.
- Do not build a complete new cloud security posture management tool from scratch.

## Validation

- `python3 scripts/validate_backlog_tasks.py`
- `pytest api/tests/`

## Acceptance

- AI successfully identifies choke-points in an attack graph.
- Micro-scanner can replay an exact finding payload and verify a fix.
- Drift detection accurately spots differences between two runs on the same target.
- Cloud IAM findings map visually to traditional network/web findings.
