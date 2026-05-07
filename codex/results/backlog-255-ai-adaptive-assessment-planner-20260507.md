# backlog-255 Evidence-driven Adaptive Assessment Planner

Date: 2026-05-07

## Summary

Implemented a deterministic assessment planner that reads the existing `SignalProfile` and the registered runner capability metadata, then produces operator-reviewed `RUN`, `WAIT`, `SKIP`, and `NEEDS_APPROVAL` decisions per runner. The planner does not create runners and does not dispatch work autonomously.

## Behavior Proof

- `GET /api/v1/runs/{run_id}/assessment-plan` returns a plan with runner decisions, confidence, matched/missing signals, risk tier, approval count, estimated minutes, expected evidence, and a one-sentence reason.
- `RunRead.assessment_plan` exposes the same deterministic plan to Mission Control.
- `POST /api/v1/runs/{run_id}/assessment-plan/queue` queues only operator-approved plan items through the existing registered-runner queue and blocks pending approval gates, existing task queues, intrusive runners, invalid runners, and non-RUN items unless explicitly operator-overridden from WAIT.
- `sqlmap` remains `WAIT` when only PHP/CMS/login-form hints exist and no `injectable_parameter` or `sql_error_pattern` signal exists.
- `jwt-probe` is `SKIP` when JWT signals are absent.
- `deserialization-probe` is `SKIP` when Java/JSESSIONID/serialized-cookie signals are absent.
- Intrusive runners always produce `NEEDS_APPROVAL`.

## UI Proof

Temporary current-code server: `http://127.0.0.1:8020/app/`

Playwright acceptance rendered the Mission Control assessment plan panel with `RUN`, `WAIT`, and `SKIP` columns, confirmed a JWT-backed runner recommendation, and checked no horizontal overflow at:

- 1440 px: `codex/results/backlog-255-assessment-planner-1440-20260507.png`
- 1024 px: `codex/results/backlog-255-assessment-planner-1024-20260507.png`
- 768 px: `codex/results/backlog-255-assessment-planner-768-20260507.png`
- 375 px: `codex/results/backlog-255-assessment-planner-375-20260507.png`

Structured Playwright proof: `codex/results/backlog-255-assessment-planner-playwright-20260507.json`

## Validation

- `python3 scripts/validate_backlog_tasks.py` passed before implementation.
- Prerequisite check passed: `DONE_LOG.md` contains completed backlog-256 and completed backlog-258.
- `source .venv/bin/activate && python -m pytest api/tests/test_assessment_planner.py -q` passed.
- `source .venv/bin/activate && python -m pytest api/tests/test_assessment_chain.py api/tests/test_runs.py api/tests/test_assessment_planner.py -q` passed.
- `source .venv/bin/activate && python -m pytest api/tests/ -q` passed with exit code 0.
- `node --check --input-type=module < ui/assets/modules/mission-control.js` passed.
- Playwright acceptance passed on 1440, 1024, 768, and 375 px.

## Boundary Notes

- Existing manual wizard and fixed-chain paths were preserved.
- Runner registry, approval gates, scope, ROE, credentials, provenance, reports, runtime binding, and kill-switch boundaries were not bypassed.
- No live public or customer target was contacted; UI acceptance used a temporary local database and an inert example URL in approved scope metadata only.
