# Active Task

## Title

Adaptive execution waves: run tools in evidence-driven batches, re-evaluate after each wave, update plan based on new signals

## Promoted From

`codex/tasks/backlog-259-adaptive-execution-waves.json`

## Goal

Implement the active backlog package `codex/tasks/backlog-259-adaptive-execution-waves.json` so adaptive assessments run in operator-approved evidence waves, update SignalProfile after each wave, and re-plan WAIT runners without autonomous launch.

## Scope

Implement the active backlog package `codex/tasks/backlog-259-adaptive-execution-waves.json`.

Expected slice:

- model bounded adaptive execution waves after recon and planner output
- update SignalProfile with new evidence after each completed wave
- re-score WAIT runners against the updated SignalProfile
- show promoted WAIT-to-RUN runners as new operator-review proposals
- show Mission Control wave progress
- enforce the maximum wave limit and approval gate for each wave
- keep intrusive runners behind their existing explicit gates

## Constraints

- Do not implement until this file is the single active task.
- Prerequisites are hard-gated: backlog-255, backlog-256, and backlog-258 must be complete in `DONE_LOG.md`.
- Waves are re-planning passes, not autonomous execution.
- Each wave requires operator approval before launching.
- WAIT promotions are proposals, not auto-dispatched work.
- Maximum 5 waves per engagement.
- Do not bypass runner registry, approval gates, provenance, reports, runtime binding, scope, ROE, credentials, or kill switch.
- Do not create new runners.
- Do not change intrusive approval gates.

## Validation

- `python3 scripts/validate_backlog_tasks.py`
- `source .venv/bin/activate && python -m pytest api/tests/ -q`
- `git diff --check`

## Acceptance

- Wave completion updates SignalProfile with new evidence.
- WAIT runners are re-scored after each wave.
- Promoted runners appear as new proposals for operator approval.
- Mission Control shows wave progress.
- Maximum 5 waves is enforced.
- Each wave requires approval.
- SKIP decisions persist unless contradicted by new evidence.
- Existing chain and planner tests do not regress.
