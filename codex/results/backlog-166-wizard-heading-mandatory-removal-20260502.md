# Backlog 166 - Wizard Heading Mandatory Removal Validation

Date: 2026-05-02

## Scope

Active task: `backlog-166-wizard-heading-mandatory-removal`

The wizard is the recommended mission intake path, not a mandatory navigation gate. The UI must not describe the wizard itself as mandatory, while legitimate ROE/authorization mandatory language remains allowed.

## Findings And Change

- `ui/index.html` already rendered the wizard heading as `What do you want to test?`.
- `ui/index.html`, `ui/assets/modules/wizard.js`, and `ui/assets/app.js` did not contain `Mandatory Assessment Wizard`, `Mandatory Wizard`, or other wizard-flow mandatory copy.
- No product copy change was required.
- Added focused smoke coverage in `ui/tests/test_operator_console_smoke_e2e.py` to prevent regression:
  - the wizard screen heading must not contain `mandatory`
  - the sidebar wizard label must stay `Intake`, not `Mandatory Wizard`
  - the rendered wizard screen must not contain `mandatory wizard` / `mandatory assessment wizard`

## Validation Evidence

- `python3 scripts/validate_backlog_tasks.py`
  - Passed with exactly one active task before completion.
- `source .venv/bin/activate && python -m pytest api/tests/test_health.py -q`
  - Failed before tests completed because pytest global capture teardown raised the known host-level `FileNotFoundError`.
- `source .venv/bin/activate && python -m pytest -s -q api/tests/test_health.py`
  - Passed.
- `source .venv/bin/activate && python -m pytest -s -q ui/tests/test_operator_console_smoke_e2e.py::test_wizard_heading_is_recommended_intake_not_mandatory_gate`
  - Passed.
- `source .venv/bin/activate && python -m pytest -s -q ui/tests/test_mockup_port_e2e.py::test_exact_mockup_port_tiles_sidebar_stepper_and_cinema`
  - Passed.
- `grep -iE 'mandatory wizard|mandatory assessment wizard' ui/index.html || true`
  - Returned no matches.
- `curl --max-time 5 -fsS http://127.0.0.1:8000/app/ | rg "What do you want to test\\?|Mandatory Assessment Wizard|Mandatory Wizard|nav-wizard|screen-wizard"`
  - Confirmed live HTML contains `What do you want to test?` and no mandatory wizard heading.
- `git diff --check`
  - Passed before admin updates.

## Remaining Risk

- The exact normal-capture health command remains blocked by the known local pytest capture teardown issue; the health tests themselves pass with `-s`.
- This slice intentionally does not redesign the wizard flow or change ROE/authorization gate wording.
