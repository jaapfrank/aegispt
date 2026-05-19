# backlog-260 AI Continuous Assessment Loop

Date: 2026-05-07

## Scope

Implemented a backend/API-only AI assessment loop controller. No production UI files were changed for this task because the operator UI is being rebuilt in `ui-v2`.

## Behavior

- Added `GET /api/v1/runs/{run_id}/assessment-loop` to expose current AssessmentState:
  - target type and approved targets
  - inventory snapshot and SignalProfile counts
  - findings, tested task paths, open AI proposals, active loop tasks
  - loop counters, stuck threshold, and latest NextAction
- Added `POST /api/v1/runs/{run_id}/assessment-loop/iterate` to create one bounded observe-decide-execute iteration.
- NextAction records include exact `tool`, `target`, `params`, `tier`, `reasoning`, `confidence`, `follow_up_hints`, expected evidence, and approval metadata.
- URL targets seed with `httpx`, CIDR/IP targets seed with `nmap`, and domain targets can seed with `easm-discover` without creating a fixed assessment chain.
- Passive/low-impact zero-approval loop actions create queued tasks only through existing registered runner task records; no direct dispatch occurs.
- Active and intrusive actions create pending `AgentProposal` records only; execution still requires the existing proposal approval flow.
- The loop refuses to advance while the selected run has pending approvals or loop tasks are still queued/running.
- Stuck detection stops after the configured no-new-signal threshold.
- Maximum iteration count is capped at 20 by default.
- State is stored under `run.configuration_json.ai_assessment_loop` and preserves `manual_chain_alternative_preserved=true` and `fixed_phase_chains_replaced_globally=false`.

## Files

- `api/app/services/assessment_loop.py`
- `api/app/routers/runs.py`
- `api/app/schemas/runs.py`
- `api/tests/test_assessment_loop.py`
- `codex/results/backlog-260-ai-continuous-assessment-loop-20260507.md`
- `CURRENT_STATE.md`
- `DONE_LOG.md`
- `NEXT_TASK.md`
- `TASK_QUEUE.md`
- `codex/tasks/archived-old-ui/backlog-264-findings-attack-path-grouped-view.json`
- `codex/tasks/archived-old-ui/backlog-265-ai-assessment-narrative-report.json`

## Validation

- `python3 scripts/validate_backlog_tasks.py` passed before implementation with exactly one active task.
- Prerequisite check: `inputs.prerequisite_backlog` starts with `REQUIRES:` and `DONE_LOG.md` contains completed backlog-248, backlog-256, backlog-258, and backlog-205.
- `source .venv/bin/activate && python -m pytest api/tests/test_assessment_loop.py -q` passed.
- `source .venv/bin/activate && python -m pytest api/tests/test_assessment_planner.py api/tests/test_ai_agent_reasoning.py::test_ai_proposal_approval_is_auditable_and_queues_follow_up_task api/tests/test_runs.py::test_autonomous_profile_defaults_run_flags_on_create -q` passed.
- `source .venv/bin/activate && python -m compileall -q api/app/services/assessment_loop.py api/app/routers/runs.py api/app/schemas/runs.py api/tests/test_assessment_loop.py` passed.
- `source .venv/bin/activate && python -m pytest api/tests/ -q` passed with warnings only.
- `cd ui-v2 && npm run build` passed for the existing React v2 scaffold after minimal type/lint cleanup; Vite reported only a large chunk warning.
- `cd ui-v2 && npm run lint` passed for the existing React v2 scaffold.
- Post-promotion `python3 scripts/validate_backlog_tasks.py` passed with 228 queued task packages and exactly one active task.

## Scope Exceptions

- `http://127.0.0.1:8000` was not relevant for this backend/API-only slice because no browser UI or served runtime asset changed.
- The original task package referenced old Mission Control/UI acceptance and `ui/tests/test_ai_loop_chain_acceptance.py`; UI implementation is explicitly out of scope and that test file is not present in the repo. This slice instead adds backend API coverage for loop state, NextAction shape, passive queueing, active proposal gating, CIDR seeding, stuck detection, and max-iteration enforcement.
- Old UI follow-up tasks backlog-264 and backlog-265 were archived under `codex/tasks/archived-old-ui/` per the user's instruction that old UI work should be removed because the UI will be rebuilt. `NEXT_TASK.md` now promotes the React v2 foundation.

## Evidence

- Tests prove URL-scope ai_loop runs seed a passive `httpx` NextAction and queue a task with `queued_not_dispatched` provenance.
- Tests prove active `auth-flow` evidence creates a pending review-only proposal and no task before approval.
- Tests prove CIDR-scope ai_loop runs seed `nmap` without creating a fixed-phase chain.
- Tests prove no-new-signal stuck detection stops at threshold 3.
- Tests prove maximum 20 iterations is enforced.
