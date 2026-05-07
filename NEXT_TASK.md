# Active Task

## Title

Runner capability metadata: each runner declares prerequisites, signal triggers, blockers, risk, cost, expected evidence, and follow-up tools

## Promoted From

`codex/tasks/backlog-258-runner-capability-metadata.json`

## Goal

Implement the active backlog package `codex/tasks/backlog-258-runner-capability-metadata.json` so AegisPT has machine-readable runner capability metadata for the adaptive planner.

## Scope

Implement the active backlog package `codex/tasks/backlog-258-runner-capability-metadata.json`.

Expected slice:

- add capability metadata for all registered runners
- load runner capability metadata through a registry/service that the planner can query later
- expose runner capabilities through the required API endpoint
- keep metadata additive and informational
- ensure sqlmap metadata requires concrete injectable parameter or SQL error evidence, not PHP+MySQL alone
- preserve existing runner logic, run profiles, dispatch behavior, approvals, scope, ROE, credentials, runtime binding, reports, provenance, and kill switch

## Constraints

- Do not implement until this file is the single active task.
- Work only on runner capability metadata and the metadata registry/API.
- Do not change runner execution logic.
- Do not change run profiles or dispatch.
- Do not bypass pack registry, validation, approval, deployment, runtime binding, scope, ROE, credentials, or kill switch.
- Keep the existing manual/wizard path intact.

## Validation

- `python3 scripts/validate_backlog_tasks.py`
- `source .venv/bin/activate && python -m pytest api/tests/ -q`
- `git diff --check`

## Acceptance

- All registered runners have capability metadata.
- RunnerRegistry loads all metadata at startup.
- `GET /api/v1/runners/capabilities` returns the loaded metadata.
- sqlmap triggers require concrete parameter or SQL error evidence, not PHP+MySQL alone.
- JWT metadata lists JWT response/token signals as primary triggers.
- Deserialization metadata lists Java indicators as primary triggers.
- No regression in existing runner tests.
