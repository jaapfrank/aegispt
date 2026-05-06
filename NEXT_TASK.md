# Active Task

## Title

Remove 'Complete Assessment Wizard' CTA from wizard screen itself and from active-run screens

## Promoted From

`codex/tasks/backlog-201-complete-assessment-wizard-cta-everywhere.json`

## Goal

Scope the topbar `Complete Assessment Wizard` CTA so it appears only when it helps first-run setup and is hidden when the operator is already in the wizard or already has run context.

## Scope

Implement the active backlog package `codex/tasks/backlog-201-complete-assessment-wizard-cta-everywhere.json`.

Expected slice:

- find the current topbar CTA rendering path in `ui/assets/app.js`
- hide the CTA when the active screen is `wizard`
- hide the CTA when a run is queued or running
- hide the CTA when engagements with runs exist
- keep it visible on the Dashboard only when no engagements exist or first-run setup genuinely needs intake

## Constraints

- Do not implement until this file is the single active task.
- Only change the visibility condition of the CTA.
- Do not change topbar layout.
- Do not change wizard navigation.
- Do not change backend APIs.
- Do not bypass pack registry, validation, approval, deployment, runtime binding, scope, ROE, credentials, or kill switch.
- No runtime self-modification.
- No uncontrolled plugin installation.

## Validation

- `python3 scripts/validate_backlog_tasks.py`
- `source .venv/bin/activate && python -m pytest api/tests/test_health.py -q`
- `git diff --check`

## Acceptance

- CTA is hidden on the wizard screen.
- CTA is hidden when a run is queued or running.
- CTA is hidden when engagements with runs exist.
- CTA is visible on Dashboard when no engagements exist.
- E2E tests pass.
