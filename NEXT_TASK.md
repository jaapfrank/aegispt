# Active Task

> **Read first:** [`SESSION_PROMPT.md`](SESSION_PROMPT.md) — kickoff discipline for AegisPT sessions (forbidden patterns, required_checks, live-acceptance gate, DONE-definitie). De regels daar overschrijven Claude's instinct.

## Title

Single dispatch authority on autonomous-intrusive runs — Claude becomes THE picker; next_best_action_selector + auto_queue gated on `autonomous_intrusive_allowed=True` (sprint mythos-foundation, task 4 of 5)

## Goal

Today three parallel dispatch engines compete on every autonomous-intrusive advance: (1) `auto_queue_active` / `auto_queue_passive` rules in `workers/orchestration/tasks.py` queue capability tasks based on signal triggers, (2) `next_best_action_selector` (deterministic rule-based) wraps every pick in `selector_decision='APPROVAL'`, and (3) the Claude picker via `_call_picker_with_exec_plan_refinement` (now hardened by backlog-403). On the after-402 harness run, runs persisted in `status=queued` with `tasks=[]` because the Claude picker never fired — auto_queue + selector were running first and producing APPROVAL-wrapped proposals that the harness's polling loop didn't satisfy.

This task makes the Claude picker THE picker for `run.autonomous_intrusive_allowed=True` runs: auto_queue is skipped, selector emits suggestions for Claude to consume (not competing APPROVAL proposals). Operator-supervised runs (flag=False) keep all 3 engines unchanged.

## Baseline anchor

- backlog-406 baseline: 5/5 targets at 0/0/0/0/0/0 (5 runs all status=queued with tasks=0)
- backlog-402 after-402: same 0/0/0/0/0/0 on harness metrics; observed_paths emit proven via direct invocation only
- backlog-403 (just landed): code-level refinement loop ready; live picker firing requires THIS task

backlog-404 closes the chicken-egg.

## Scope

Three coordinated edits across api/app/services + workers/orchestration:

1. `api/app/services/assessment_loop.py` — audit every `selector_decision='APPROVAL'` write-site (currently 2: lines ~2381 and ~3540 per grep). When `run.autonomous_intrusive_allowed=True`, replace APPROVAL with direct dispatch. The selector's top suggestions become INPUTS to the Claude picker prompt (new helper `_collect_selector_suggestions(run, scope) -> list[dict]`), not competing proposals.
2. `workers/orchestration/tasks.py` — audit `auto_queue_active` / `auto_queue_passive` call sites. When `run.autonomous_intrusive_allowed=True`, skip auto-queue dispatch and emit a single audit AgentReasoning row stating "auto-queue skipped (autonomous-intrusive mode); Claude picker is sole dispatch authority".
3. `api/app/services/ai_agent.py` — `select_next_best_action_for_run` callers also gate on the flag.

## Constraints

- Per SESSION_PROMPT §2 forbidden: no per-target conditionals, no pre-baked path/payload registries, no claiming DONE on green unit tests alone.
- `non_autonomous_path_preserved`: for runs with autonomous_intrusive_allowed=False (operator-supervised default), behavior is UNCHANGED — APPROVAL wrappers fire, auto_queue runs, selector emits proposals. The bypass strictly opens autonomous behavior, never closes operator-supervised behavior.
- `approval_path_still_exists`: approval workflow code stays intact for the non-autonomous case. Not removing approvals — only skipping them when the operator explicitly opted into autonomous-intrusive.
- Existing `autonomous_intrusive_allowed` column is the sole gate — no new flag introduced.
- Scope creep guard: 3 coordinated edits at the documented sites only.

## Source Package

`codex/tasks/backlog-404-single-dispatch-authority-on-autonomous-intrusive.json`

## Reference

- backlog-402 after-402 report (`docs/validation/sprint-2026-mythos-foundation-2026-05-19-after-402.md`) — empirical evidence that runs stay in status=queued with 0 tasks
- backlog-403 DONE_LOG entry — refinement loop ready, picker hardened
- Live run `3e2cfa5b` empirical baseline: 14/14 AgentReasoning rows with `next_best_action_selector_used=True` + `selector_decision='APPROVAL'`
- Memory: [[feedback_live_proof_before_done]], [[feedback_live_proof_must_be_diverse_real_targets]], [[feedback_intrusive_pivot_approval]]
- #336 fixed the planner-level bypass; this task is the matching dispatch-layer fix

## Validation

- `python3 scripts/validate_backlog_tasks.py`
- `.venv/bin/pytest api/tests/test_assessment_loop_dispatch_authority.py api/tests/test_assessment_loop.py api/tests/test_assessment_planner.py`
- `python3 -m compileall -q api workers`
- `.venv/bin/ruff check api/app/services/ workers/orchestration/`
- `.venv/bin/pytest tests/test_multi_target_validation_grep_guard.py` (must still pass)
- `git diff --check`
- Live: API restart → harness `--phase after-404` on the 5 targets → ≥1 target shows non-zero on claude_picks AND at least one Task row with `decision_source='ai_loop_claude_picker'` AND 0 AgentReasoning rows with `selector_decision='APPROVAL'` on the autonomous-intrusive runs. Regression check: a non-autonomous control run still produces APPROVAL-wrapped proposals.
