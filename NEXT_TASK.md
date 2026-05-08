# Active Task

## Title

Continuous Exposure Drift Detection

## Promoted From

`codex/tasks/backlog-299-continuous-exposure-drift-detection.json`

## Goal

For scheduled continuous pentests, the AI must compare the current context document and findings against the previous run. It flags "Drift" such as "A new port 8080 opened since yesterday" or "The React version downgraded". This alerts the SOC to shadow IT or unauthorized changes before an attacker finds them.

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
