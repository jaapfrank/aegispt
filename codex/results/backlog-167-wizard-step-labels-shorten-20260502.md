# Backlog 167 - Wizard Step Label Shortening Validation

Date: 2026-05-02

## Scope

Active task: `backlog-167-wizard-step-labels-shorten`

The wizard step indicator labels must be short enough to scan quickly and avoid wrapping on a 1280px viewport. The wizard step order, logic, validation, and data model must remain unchanged.

## Findings And Change

- `ui/assets/modules/constants.js` already defined `WIZARD_STEPS` as:
  - `Type`
  - `Scope`
  - `Access`
  - `Profile`
  - `Modules`
  - `Safety`
  - `Confirm`
- No long legacy labels were found in the scoped files:
  - `Assessment/Scope Type`
  - `Credentials Test / Access`
  - `Safety / Limits`
  - `Review / Confirm`
- No product-code label change was required.
- Added focused smoke coverage in `ui/tests/test_operator_console_smoke_e2e.py`:
  - imports `WIZARD_STEPS` from the live frontend module
  - verifies the exact seven short labels
  - verifies all labels are 12 characters or shorter
  - opens Advanced Configuration at 1280px
  - verifies the rendered advanced step buttons stay on one row and do not overflow

## Validation Evidence

- `python3 scripts/validate_backlog_tasks.py`
  - Passed with exactly one active task before completion.
- `source .venv/bin/activate && python -m pytest api/tests/test_health.py -q`
  - Failed before tests completed because pytest global capture teardown raised the known host-level `FileNotFoundError`.
- `source .venv/bin/activate && python -m pytest -s -q api/tests/test_health.py`
  - Passed.
- `source .venv/bin/activate && python -m pytest -s -q ui/tests/test_operator_console_smoke_e2e.py::test_wizard_advanced_step_labels_are_short_and_do_not_wrap`
  - Passed.
- `source .venv/bin/activate && python -m pytest -s -q ui/tests/test_mockup_port_e2e.py::test_exact_mockup_port_tiles_sidebar_stepper_and_cinema`
  - Passed.
- `rg -n "Assessment/Scope Type|Credentials Test / Access|Safety / Limits|Review / Confirm" ui/assets/modules/constants.js ui/assets/modules/wizard.js ui/index.html || true`
  - Returned no matches.
- Live browser check against `http://127.0.0.1:8000/app/` at `1280x900`
  - Confirmed labels `Type`, `Scope`, `Access`, `Profile`, `Modules`, `Safety`, `Confirm`.
  - Confirmed the six visible Advanced Configuration step buttons share the same `y` coordinate and have no overflow.
- `git diff --check`
  - Passed before admin updates.

## Remaining Risk

- The exact normal-capture health command remains blocked by the known local pytest capture teardown issue; the health tests themselves pass with `-s`.
- This slice intentionally does not redesign the wizard stepper or change the separate 4-step guided intake progress copy.
