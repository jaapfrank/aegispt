# Backlog 172 Result - Mission Control Header Buttons

Date: 2026-05-02

## Task

`backlog-172-mission-control-header-buttons-reorder`

Mission Control header: fix button order, intents, and styling for operational clarity.

## Outcome

The product source already matched the requested Mission Control header order and button intent styling:

- `Kill Run` renders first with `action danger`
- `Start Queued Checks` renders second with `action primary`
- `View Findings` renders third with `action primary`
- `View Agents` renders fourth with `action ghost`
- `Cinema Mode` renders fifth with `action ghost`

No `ui/index.html` product edit was required. The safe implementation was to add focused Playwright regression coverage so this operator-facing order and styling cannot silently regress.

## Files Changed

- `ui/tests/test_operator_console_smoke_e2e.py`
  - extended `test_mission_control_header_button_intent_classes` to assert the exact Mission Control header action order
  - added class assertions for `Start Queued Checks`, `View Findings`, and `Cinema Mode`

## Validation

- `python3 scripts/validate_backlog_tasks.py`
  - passed before implementation with `193` queued task packages and exactly one active task
- `python3 -m py_compile ui/tests/test_operator_console_smoke_e2e.py`
  - passed
- `source .venv/bin/activate && python -m pytest -s -q ui/tests/test_operator_console_smoke_e2e.py::test_mission_control_header_button_intent_classes`
  - passed
- `source .venv/bin/activate && python -m pytest -s -q ui/tests/test_operator_console_smoke_e2e.py::test_cinema_elapsed_uses_terminal_timestamps_without_redrawing_shell ui/tests/test_operator_console_smoke_e2e.py::test_mission_control_header_button_intent_classes`
  - passed
- `source .venv/bin/activate && python -m pytest -q api/tests/test_health.py`
  - not green: local pytest capture teardown still raises `_pytest/capture.py FileNotFoundError`
- `source .venv/bin/activate && python -m pytest -s -q api/tests/test_health.py`
  - passed
- `curl -fsS http://127.0.0.1:8000/app/ | sed -n '125,140p'`
  - confirmed the live static HTML has the expected Mission Control action order and classes
- `python3 scripts/validate_backlog_tasks.py && git diff --check`
  - passed before administration

## Residual Risk

- The exact no-`-s` health pytest command still fails in this local shell because of the known pytest capture issue; the same health tests pass with `-s`.
- This slice intentionally did not change button handlers, Mission Control JavaScript, run cancellation behavior, backend APIs, or broader layout.
