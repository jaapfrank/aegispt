# Backlog 165 - View Agents Button Intent Validation

Date: 2026-05-02

## Scope

Active task: `backlog-165-view-agents-button-danger-class`

The Mission Control header `View Agents` action is navigation-only and must not use destructive/danger styling. The destructive `Kill Run` action must keep danger styling.

## Changes

- `ui/index.html`
  - Kept `mission-view-agents` as `action ghost`.
  - Set the visible label to `View Agents ->`.
  - Preserved `data-nav-screen="agents"`.
- `ui/tests/test_operator_console_smoke_e2e.py`
  - Added focused smoke coverage for the Mission Control header action intent contract.
  - Verifies all `screen-head` navigation buttons avoid `.danger`.
  - Verifies `Kill Run` remains `.danger`.
  - Verifies `View Agents` navigates to the Agents screen.

## Validation Evidence

- `python3 scripts/validate_backlog_tasks.py`
  - Passed with exactly one active task before completion.
- `source .venv/bin/activate && python -m pytest api/tests/test_health.py -q`
  - Failed before tests completed because pytest global capture teardown raised the known host-level `FileNotFoundError`.
- `source .venv/bin/activate && python -m pytest -s -q api/tests/test_health.py`
  - Passed.
- `source .venv/bin/activate && python -m pytest -s -q ui/tests/test_operator_console_smoke_e2e.py::test_mission_control_header_button_intent_classes`
  - Passed.
- `source .venv/bin/activate && python -m pytest -s -q ui/tests/test_mockup_port_e2e.py::test_exact_mockup_port_tiles_sidebar_stepper_and_cinema`
  - Passed.
- `curl --max-time 5 -fsS http://127.0.0.1:8000/app/ | rg "mission-view-agents|View Agents|Live Agents|mission-kill-run"`
  - Confirmed live HTML contains `mission-view-agents` with `action ghost`, `View Agents ->`, and `mission-kill-run` with `action danger`.
- `git diff --check`
  - Passed before admin updates.

## Remaining Risk

- The exact normal-capture health command remains blocked by the known local pytest capture teardown issue; the health tests themselves pass with `-s`.
- This slice intentionally does not reorder Mission Control actions or redesign the header; backlog-172 remains queued for broader header order/intent polish.
