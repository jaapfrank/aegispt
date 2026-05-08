# Backlog 303 - Goal-Oriented CTF Reasoning Mode

Date: 2026-05-08

## Scope

Implemented backend/API support for explicit operator objectives on `ai_loop` runs only.

## Behavior

- Added `POST /api/v1/runs/{run_id}/assessment-loop/goal`.
- Stores a normalized operator objective under `Run.configuration_json.ai_assessment_loop.goal_oriented_reasoning`.
- Records an `assessment_loop_goal_oriented_reasoning` AgentReasoning row with no direct work dispatch.
- Builds a bounded hypothesis path from the objective using only registered runners, approved scope targets, context-document evidence, and existing approval/ROE/kill-switch metadata.
- `advance_assessment_loop()` now prefers stored goal-oriented steps when present, while still queueing passive work through `Task` and active/intrusive work through reviewable `AgentProposal` records.
- Rationale ledger entries include the goal-oriented source metadata for selected actions.

## Safety Boundaries

- Available only when the run is explicitly configured with `run_mode=ai_loop`.
- Objective registration dispatches no work.
- Each hypothesis step carries `registered_runner_required`, `scope_enforced`, `roe_enforced`, `approval_gates_bypassed=false`, and `kill_switch_still_authoritative=true`.
- Active and intrusive steps remain proposal-only until the existing approval flow allows execution.
- Data-layer checks prefer controlled proof and canary evidence wording; session-related paths use session exposure risk language.
- Manual wizard and fixed-chain flows are not replaced.

## Validation

- `python3 scripts/validate_backlog_tasks.py` passed before implementation.
- `pytest api/tests/test_assessment_loop.py -q` passed: 8 passed.
- `python3 -m compileall -q api/app/services/assessment_loop.py api/app/routers/runs.py api/app/schemas/runs.py` passed.
- Initial `pytest api/tests/` with system Python failed during collection because `pypdf` was not installed in that interpreter.
- `.venv/bin/python -m pytest api/tests/` passed: 537 passed, 4 warnings.

## UI / Live Runtime

The active package has `must_not_touch: ["ui-v2/"]`; no UI files were changed. `ui-v2` and Playwright validation were therefore not required for this backend/API/runtime slice.

## Remaining Proof Gaps

- No live local Gruyere multi-step autonomous benchmark was executed in this slice.
- No live worker-dispatched multi-iteration goal run against WebGoat, DVWA, Gruyere, or an AD lab was executed.
- These gaps are tracked in `extra_tests.md` XT-033 and `risico.md` R-025.
