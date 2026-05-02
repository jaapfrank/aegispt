# Active Task

## Title

Shorten wizard step indicator labels to prevent wrapping and improve scannability

## Promoted From

`codex/tasks/backlog-167-wizard-step-labels-shorten.json`

## Goal

Shorten the wizard step indicator labels so they fit cleanly on standard viewports and scan quickly. The step order, step count, validation, and wizard data model must remain unchanged.

## Scope

Implement the active backlog package `codex/tasks/backlog-167-wizard-step-labels-shorten.json`.

Expected slice:

- update `WIZARD_STEPS` display labels in `ui/assets/modules/constants.js`
- replace verbose labels such as `Assessment/Scope Type`, `Credentials Test / Access`, `Safety / Limits`, and `Review / Confirm`
- use short labels such as `Type`, `Scope`, `Access`, `Profile`, `Modules`, `Safety`, and `Confirm`
- preserve all wizard step keys, order, validation, and flow behavior

## Constraints

- Keep Prompt 1 and Prompt 2 intact.
- Do not bypass approval gates, pack registry, validation, deployment, or runtime binding.
- No runtime self-modification.
- Do not install uncontrolled plugins.
- Do not change wizard step logic.
- Do not change wizard step order.
- Do not change wizard validation or launch behavior.
- Do not change backend APIs.
- Do not redesign the stepper visual component.

## Validation

- `python3 scripts/validate_backlog_tasks.py`
- `source .venv/bin/activate && python -m pytest api/tests/test_health.py -q`
- `git diff --check`
- Focused wizard E2E/smoke coverage proving the short labels render and the wizard still opens/flows
- Manual/browser check that the stepper does not wrap at a 1280px viewport

## Acceptance

- No wizard step label exceeds 12 characters.
- All wizard step labels are short, clear, and enterprise-appropriate.
- Stepper renders without wrapping on a 1280px viewport.
- Wizard functionality and step order are unchanged.
- No regression in wizard E2E tests.
