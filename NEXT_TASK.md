# Active Task

## Title

Mission Control empty state: replace large whitespace and fragmented panels with a single focused onboarding card

## Promoted From

`codex/tasks/backlog-202-mission-control-empty-state-layout.json`

## Goal

Improve Mission Control empty states so no-engagement context shows one focused onboarding card, engagement-without-run context shows useful ready-state panel messages, and run-backed Mission Control behavior remains unchanged.

## Scope

Implement the active backlog package `codex/tasks/backlog-202-mission-control-empty-state-layout.json`.

Expected slice:

- update Mission Control empty-state rendering in `ui/assets/modules/mission-control.js`
- when no engagement exists, collapse the fragmented panels and show one centred `Start Mission Intake` onboarding card
- when an engagement exists but no run has started, keep the main panels visible with contextual ready-state messages
- hide lower Mission Control panels when no run data exists
- keep active-run Mission Control rendering unchanged

## Constraints

- Do not implement until this file is the single active task.
- Change only empty-state rendering.
- Do not change Mission Control behavior when a run is active.
- Do not change run dispatch or cancellation logic.
- Do not change backend APIs.
- Do not add new panel types beyond the focused empty-state slice.
- Do not bypass pack registry, validation, approval, deployment, runtime binding, scope, ROE, credentials, or kill switch.
- No runtime self-modification.
- No uncontrolled plugin installation.

## Validation

- `python3 scripts/validate_backlog_tasks.py`
- `source .venv/bin/activate && python -m pytest api/tests/test_health.py -q`
- `git diff --check`

## Acceptance

- No-engagement Mission Control shows a single focused CTA card.
- Engagement-without-run Mission Control shows contextual ready-state messages without large whitespace.
- Active-run Mission Control remains unchanged.
- Bottom panels are hidden when no run data exists.
- E2E tests pass.
