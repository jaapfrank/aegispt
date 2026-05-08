# Active Task

## Title

One-Click 'Proof of Resolution' Micro-Scanner

## Promoted From

`codex/tasks/backlog-298-one-click-proof-of-resolution.json`

## Goal

Close the remediation loop instantly. When a developer marks a finding as "Fixed" in Jira or the UI, AegisPT must spin up a hyper-targeted "micro-scan". It extracts the exact payload and context from the original evidence and re-fires only that specific test against the exact endpoint to verify the fix in seconds, automatically closing the SLA.

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
