# Active Task

> **Read first:** [`SESSION_PROMPT.md`](SESSION_PROMPT.md) — kickoff discipline for AegisPT sessions (forbidden patterns, required_checks, live-acceptance gate, DONE-definitie). De regels daar overschrijven Claude's instinct.

## Title

exec_plan iterative refinement loop — bounded re-prompt on empty/malformed/failed plan; raises picker max_tokens 1024 → 4096 (sprint mythos-foundation, task 3 of 5; subsumes backlog-391)

## Goal

Today when Claude emits an `exec_plan` with `steps=[]` or a plan whose JSON is truncated (`max_tokens=1024` cuts it mid-string) or whose step assertion fails at runtime, the loop logs 'rejected' and falls through to a single-tool pick. Claude is never told WHY his plan failed and never given a chance to refine. This task adds a bounded refinement loop (max 3 attempts per advance) where each failed attempt feeds back to Claude: `{previous_plan, failure_reason, current_evidence_state, runner_observed_responses_so_far}`. As part of the same task, the picker call's `max_tokens` is raised from 1024 to 4096 so the model has room to write a real multi-step plan body. This subsumes backlog-391 (max_tokens raise) which is closed as part of this task.

## Baseline anchor

backlog-406 baseline (2026-05-19): all 5 targets at 0/0/0/0/0/0. backlog-402 (just landed) added `observed_paths` + `attack_candidates` to target_intel emit — but the system still produces 0 dispatches because the Claude picker repeatedly fails. backlog-403 fixes the picker mechanics so Claude's choices actually land.

## Scope

Two coordinated edits in `api/app/services/assessment_loop.py`:

1. `_claude_select_next_action` raises `max_tokens` to 4096 in the `messages.create` call.
2. New wrapper `_call_exec_plan_with_refinement(...)` that wraps the exec_plan dispatch path: on (a) empty `plan.steps`, (b) malformed plan JSON, (c) `exec_plan_rejected` runner outcome from a prior step in the same advance, re-call Claude with a refinement prompt containing `previous_plan_attempt`, `failure_reason`, and `runner_evidence_summary` and accept the refined plan. Bounded at `EXEC_PLAN_MAX_REFINEMENTS = 2` (initial + 2 refinements = 3 attempts total). On exhaustion: log INFO 'exec_plan refinement exhausted after N attempts' and fall back to the existing single-tool pick path.

## Constraints

- Per `SESSION_PROMPT.md` §2 forbidden: no per-target conditionals, no pre-baked path/payload registries, no claiming DONE on green unit tests alone.
- Per `feedback_no_prescriptive_recipes`: refinement prompt must NOT seed concrete fix templates ("try is_admin=True" etc.). Generic only: "your previous plan had failure_reason=X; revise to address it".
- Bounded refinement: hard cap at `EXEC_PLAN_MAX_REFINEMENTS = 2` (3 total attempts per advance). No nested loops, no unbounded retry on transient failures.
- Feedback context bounded: refinement prompt includes only previous plan body (truncated to last 500 chars), failure_reason (1 sentence), runner_evidence_summary (existing helper, capped at 1000 chars). No accumulation across advances.
- Scope creep guard: 2 coordinated edits only. Do NOT change the structured-output schema (#330). Do NOT change exec_plan runner step execution semantics. Do NOT change auto_queue_active dispatch (backlog-404's territory).

## Source Package

`codex/tasks/backlog-403-exec-plan-iterative-refinement.json`

## Reference

- Backlog-406 baseline + backlog-402 after-402 reports in `docs/validation/`
- Live run `3e2cfa5b` empirical evidence (DONE_LOG.md): "Claude said EXEC_PLAN plan_name=admin-takeover-via-leaked-creds steps=0", "exec_plan rejected — empty or malformed plan body", "picker JSON parse failed despite structured-output schema; err=Unterminated string starting at: line 1 column 1158"
- Memory: [[feedback_live_proof_before_done]], [[feedback_live_proof_must_be_diverse_real_targets]]
- Subsumes: backlog-391 (Picker max_tokens raise) — close on DONE

## Validation

- `python3 scripts/validate_backlog_tasks.py`
- `.venv/bin/pytest api/tests/test_assessment_loop_structured_outputs.py api/tests/test_assessment_loop_soft_retry.py api/tests/test_exec_plan_refinement.py`
- `python3 -m compileall -q api`
- `.venv/bin/ruff check api/app/services/assessment_loop.py`
- `git diff --check`
- `.venv/bin/pytest tests/test_multi_target_validation_grep_guard.py` (must still pass)
- Live: API restart → harness `--phase after-403` on the 5 targets → ≥1 successful exec_plan dispatch with ≥2 steps + log shows refinement firing on ≥1 occasion. Verifiable via `/tmp/aegispt-api.log` grep for `picker recovered after N retry` / `exec_plan refined after N attempt`.
