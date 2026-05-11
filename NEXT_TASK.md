# Active Task

## Title

Test and Scan Tooling Readiness Gate

## Goal

Add a safe, deterministic tooling readiness gate for stronger local testing and scanning coverage without running live target scans.

## Scope

- React v2 visual and accessibility testing.
- API contract fuzzing against local FastAPI fixtures.
- SAST, dependency, and secret scan readiness.
- ZAP automation isolation.

## Constraints

- Do not run live public target scans.
- Do not expand scope, materialize credentials, approve proposals, mutate runtime gates, or bypass kill-switch behavior.
- Treat active DAST as optional and separately approval-gated; default to local fixtures and readiness checks.
- Do not auto-fix breaking dependency upgrades.

## Source Package

`codex/tasks/backlog-335-test-scan-tooling-readiness-gate.json`

## Required Reading

- `CURRENT_STATE.md`
- `DECISIONS.md`
- `TASK_QUEUE.md`
- `DONE_LOG.md`
- `TESTING_POLICY.md`
- `codex/results/react-v2-dashboard-readiness-and-tooling-audit-20260511.md`

## Validation

- `python3 scripts/validate_backlog_tasks.py`
- `.venv/bin/pytest`
- `cd ui-v2 && npm run build`
- `cd ui-v2 && npm run test:e2e`
- `cd ui-v2 && npm run lint`
- `.venv/bin/ruff check .`
- `git diff --check`

## Acceptance

- Tool readiness checks are deterministic and local-safe.
- ZAP and Semgrep readiness blockers found during the 2026-05-11 audit are handled or recorded operator-visibly.
- React v2 coverage gains a meaningful accessibility or visual guard.
- Dependency and secret scan commands produce review-only artifacts.
- Active release gates remain green.
