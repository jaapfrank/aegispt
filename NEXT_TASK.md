# Active Task

## Title

AI Loop Soft Retry on Parse / Decision Failure Instead of Hard Stop (Phase 3 day 2)

## Goal

When the picker returns `None` (parse fail, empty text, or unrecoverable hop loop exit), `advance_assessment_loop` currently sets `status=stopped` with reason `no_registered_runner_candidate` and halts the run. Replace this with bounded soft retry (max 2 attempts with fresh per-call backoff) so a single bad output does not kill an otherwise healthy run.

## Scope

- Modify `api/app/services/assessment_loop.py:advance_assessment_loop` to detect parse-fail / None-candidate distinctly from genuine exhaustion.
- On parse-fail or empty picker output: retry up to 2 times with the same context.
- On exhaustion (no candidate after retries): THEN set `status=stopped` with descriptive reason `picker_retry_exhausted` (distinguishable from `no_registered_runner_candidate`).
- Retry attempts visible in `loop_state.retries_this_advance` so operator can see retry history.

## Constraints

- Retry logic only. Do NOT change tool definitions, the schema, or the system prompt.
- Hard cap retries per advance at 2. Beyond that, mark loop stopped with descriptive reason.
- Each retry attempt must increment a counter visible in loop_state so the operator can see retry history. No infinite loops.
- Must NOT touch: `workers/runners/`, `workers/orchestration/`, picker tool definitions, the system prompt body.

## Source Package

`codex/tasks/backlog-381-loop-soft-retry-on-failure.json`

## Reference

- `api/app/services/assessment_loop.py:advance_assessment_loop` + `_claude_select_next_action`
- `docs/AGENT_SYSTEM_MAP.md` section 2 (Known issues — "Loop stops hard on first parse failure, no soft retry")
- #330 added structured outputs to eliminate JSON parse failures; #331 hardens against the residual transient failures (network blip on http_fetch, momentary credit pause, etc.)

## Validation

- `python3 scripts/validate_backlog_tasks.py`
- `.venv/bin/pytest api/tests/test_assessment_loop_soft_retry.py api/tests/test_assessment_loop.py`
- `python3 -m compileall -q api`
- `.venv/bin/ruff check api/app/services/assessment_loop.py`
- `git diff --check`
- Acceptance: 1 fail + 1 success per advance → loop continues; 3 fails per advance → loop sets `retry_exhausted` reason after the third attempt.
