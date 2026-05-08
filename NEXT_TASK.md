# Active Task

## Title

AI Choke-Point Remediation Advisor: Breaking the attack chain

## Promoted From

`codex/tasks/backlog-297-ai-choke-point-remediation-advisor.json`

## Goal

Go beyond just listing attack paths. Implement an AI engine that analyzes the entire attack graph and identifies "Choke Points" - the single cheapest or fastest remediation action that breaks the most attack paths. For example: "Instead of patching these 12 internal servers, fixing this 1 exposed Active Directory credential breaks 90% of the paths to Domain Admin".

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
