# Active Task

## Title

Remove 'Mandatory' from wizard heading: wizard is no longer a mandatory gate since backlog-58

## Promoted From

`codex/tasks/backlog-166-wizard-heading-mandatory-removal.json`

## Goal

Update wizard-facing copy so the wizard is presented as the recommended mission intake path, not a mandatory gate. Since backlog-58 implemented free navigation, the wizard heading must not say `Mandatory Assessment Wizard`. The word `mandatory` should remain only where it is legitimately describing ROE or authorization requirements.

## Scope

Implement the active backlog package `codex/tasks/backlog-166-wizard-heading-mandatory-removal.json`.

Expected slice:

- update the wizard screen heading in `ui/index.html` from `Mandatory Assessment Wizard` to `Assessment Wizard` or `Mission Intake`
- verify the sidebar/nav label for the wizard does not say `Mandatory Wizard`
- update any rendered wizard copy from `ui/assets/modules/wizard.js` or `ui/assets/app.js` that calls the wizard itself mandatory
- preserve legitimate mandatory ROE/authorization gate language

## Constraints

- Keep Prompt 1 and Prompt 2 intact.
- Do not bypass approval gates, pack registry, validation, deployment, or runtime binding.
- No runtime self-modification.
- Do not install uncontrolled plugins.
- Do not change wizard step logic or validation.
- Do not change navigation gating logic.
- Do not change backend APIs.
- Do not redesign the wizard flow.
- Do not remove mandatory wording from real ROE or authorization gate contexts.

## Validation

- `python3 scripts/validate_backlog_tasks.py`
- `source .venv/bin/activate && python -m pytest api/tests/test_health.py -q`
- `git diff --check`
- `grep -i 'mandatory wizard\|mandatory assessment wizard' ui/index.html`
- Focused wizard E2E/smoke coverage proving the heading copy is clear and the wizard still opens

## Acceptance

- Wizard screen heading does not include `Mandatory`.
- Sidebar/nav wizard label does not say `Mandatory Wizard`.
- Wizard rendered copy does not describe the wizard flow itself as mandatory.
- ROE and authorization text that is genuinely mandatory remains intact.
- No regression in wizard E2E tests.
