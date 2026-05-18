# Active Task

## Title

assessment_planner respects run.autonomous_intrusive_allowed; stop gating exec_plan when operator opted-in (live-reliability fix 1 of 3)

## Goal

The assessment_planner statically marks every intrusive-tier capability as `NEEDS_APPROVAL` — even when the run has `autonomous_intrusive_allowed=True`. This blocks the AI picker from queuing the `exec_plan` / `impacket` / `metasploit` / `netexec` / `credential_attacks` / file-upload-RCE chains the Mythos design depends on.

Empirically confirmed on live Gruyere 2026-05-18 (run `9f951a0f` against `https://google-gruyere.appspot.com/<instance>/`): 24 picker reasonings, 0 `exec_plan` picks, picker falls back to random residual tools (`ai-shell` / `c2-ingest` / `graphql-command-injection` / `iot-default-creds`), stops at `max_iterations_reached`, **0/17 known Gruyere classes found** despite the target being the best-trained one in the project.

## Scope

- Single-file fix in `api/app/services/assessment_planner.py`.
- Thread `run.autonomous_intrusive_allowed` from `build_assessment_plan_for_run` into `_score_capability`.
- When intrusive-tier AND `autonomous_intrusive_allowed=True`, the decision falls through the SAME evidence-driven logic as active/passive (RUN if triggers match, WAIT if weak, SKIP if blockers).
- Only when intrusive-tier AND NOT allowed do we still emit `NEEDS_APPROVAL`.
- Update `_decision_sentence` to drop "Controlled proof work needs the explicit approval gate" for the allowed-intrusive path.

## Constraints

- Single-function refactor + tests only. Do NOT add new capability tiers, do NOT change `INTRUSIVE_TIERS` set membership, do NOT modify the system prompt's intrusive-tier block (it's already correct), do NOT touch `workers/runners` or `workers/orchestration`.
- Preserve approval path: when `autonomous_intrusive_allowed=False`, `NEEDS_APPROVAL` semantics must remain unchanged.
- Audit trail: every plan item that runs an intrusive runner under the auto-allowed path must carry an audit-event field documenting `autonomous_intrusive_allowed=True` so post-hoc reviewers can see which decisions used the bypass.
- Must NOT touch: `_AI_PICKER_SYSTEM_PROMPT` (already correctly describes the allowed-intrusive case), `INTRUSIVE_TIERS` set membership, `approval_workflows.py` / `approvals.py`, `workers/runners/`, `workers/orchestration/`.

## Source Package

`codex/tasks/backlog-398-planner-respects-intrusive-allowed.json`

## Reference

- `api/app/services/assessment_planner.py` — `_score_capability` lines 277-279 (the root-cause lines), `build_assessment_plan_for_run` line 371 (where `run` is already accessible)
- `api/app/services/assessment_loop.py` line 838-856 — the system-prompt block that correctly tells Claude intrusive is open; this task makes the planner consistent with that prompt
- Live Gruyere run `9f951a0f` — 24 `AgentReasoning` records, last 4 carry the templated "Controlled proof work needs the explicit approval gate" text from the planner

## Validation

- `python3 scripts/validate_backlog_tasks.py`
- `.venv/bin/pytest api/tests/test_assessment_planner.py api/tests/test_assessment_loop.py`
- `python3 -m compileall -q api`
- `.venv/bin/ruff check api/app/services/assessment_planner.py`
- `git diff --check`
