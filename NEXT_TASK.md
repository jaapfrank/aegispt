# Active Task

## Title

Chain phase visibility in Mission Control: show current phase, next phase, approval requirement, and phase history clearly

## Promoted From

`codex/tasks/backlog-208-chain-phase-visibility-mission-control.json`

## Goal

Assessment chain execution is already implemented with phase definitions, auto-advance, and approval gating, but operators cannot clearly see the current phase, what comes next, what requires approval, or why a chain is waiting. Mission Control needs a phase progress strip for chain runs, including completed phases, the current phase, pending approval state, and a single existing phase-approval action.

## Scope

Implement the active backlog package `codex/tasks/backlog-208-chain-phase-visibility-mission-control.json`.

Expected slice:

- render existing assessment-chain phase data in Mission Control
- show a horizontal phase bar for chain runs
- highlight the current phase
- show completed phases with a green/completed state and duration when available
- show pending approval phases with an amber/waiting state and an `Approve Phase N` action
- show a concise summary card when a phase is pending approval
- hide the phase bar for non-chain runs

## Constraints

- Render existing chain phase data only.
- Do not change chain phase logic in `api/app/services/assessment_chain.py`.
- Do not change phase approval gating.
- Do not change run dispatch logic.
- Do not add new chain types or a chain-definition editor.
- Do not bypass scope, ROE, approval, validation, deployment, runtime binding, credentials, or kill switch.
- No runtime self-modification.
- No uncontrolled plugin installation.

## Validation

- `python3 scripts/validate_backlog_tasks.py`
- `source .venv/bin/activate && python -m pytest api/tests/test_health.py -q`
- `git diff --check`

## Acceptance

- Mission Control shows a phase progress bar when the active run is part of an assessment chain.
- Completed phases show green/completed state and duration where data is available.
- Pending-approval phase shows amber/waiting state and an `Approve Phase N` button.
- Approve button triggers the existing phase approval endpoint.
- Phase bar is hidden when the selected run is not part of a chain.
- E2E Mission Control behavior does not regress.
