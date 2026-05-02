# Backlog 178 History Empty State Evidence

Date: 2026-05-02

## Scope

Implemented `codex/tasks/backlog-178-history-screen-empty-state.json`.

The change is limited to History & Comparison UI rendering and focused UI coverage:

- zero completed runs now show a one-sentence empty state and a `Go to Mission Control` action
- one completed run now shows a single-run summary and disables/explains comparison
- two or more completed runs still use the existing `compareRuns()` delta path

No backend APIs, new data fetching, pack registry, approval gates, deployment, runtime binding, or run delta computation were changed.

## Files

- `ui/assets/modules/explorer-history.js`
- `ui/tests/test_operator_console_smoke_e2e.py`
- `ui/tests/test_operator_console_e2e.py`
- `DONE_LOG.md`
- `CURRENT_STATE.md`
- `NEXT_TASK.md`

## Validation

- `python3 scripts/validate_backlog_tasks.py`
  - passed before implementation
  - result: `193 queued task packages mapped one-to-one, and NEXT_TASK.md contains exactly one active task`
- `curl -fsS http://127.0.0.1:8000/health/live`
  - passed
  - result: healthy JSON
- `node --input-type=module --check < ui/assets/modules/explorer-history.js`
  - passed
- `python3 -m py_compile ui/tests/test_operator_console_smoke_e2e.py ui/tests/test_operator_console_e2e.py`
  - passed
- `source .venv/bin/activate && python -m pytest ui/tests/test_operator_console_smoke_e2e.py::test_history_empty_single_and_two_completed_run_states_are_guided -q`
  - not green; hit the known local `_pytest/capture.py FileNotFoundError`
- `source .venv/bin/activate && python -m pytest -s -q ui/tests/test_operator_console_smoke_e2e.py::test_history_empty_single_and_two_completed_run_states_are_guided ui/tests/test_operator_console_e2e.py::test_reports_use_verified_hash_label_and_history_empty_state_is_guided`
  - passed
- `source .venv/bin/activate && python -m pytest api/tests/test_health.py -q`
  - not green; hit the known local `_pytest/capture.py FileNotFoundError`
- `source .venv/bin/activate && python -m pytest -s -q api/tests/test_health.py`
  - passed
- live Playwright browser acceptance against `http://127.0.0.1:8000/app/`
  - passed
  - proof line: `live_history_acceptance=ok`
- `python3 scripts/validate_backlog_tasks.py`
  - passed after promoting backlog-179
  - result: `193 queued task packages mapped one-to-one, and NEXT_TASK.md contains exactly one active task`
- `git diff --check`
  - passed

## Live Acceptance Proof

The live browser check injected safe local UI state only and verified:

- zero completed runs: `0 of 0 completed runs visible`, disabled comparison explanation, empty-state sentence, and visible `Go to Mission Control` action
- one completed run: single-run summary visible, comparison explanation title exactly `Complete a second run to compare posture changes.`, disabled baseline select, and one run card
- two completed runs: two run cards, `Current vs baseline`, visible inventory delta, and no disabled comparison panel

## Residual Risk

- The exact no-`-s` pytest health and focused UI commands still fail in the local host capture layer; equivalent checks pass with capture disabled.
- This task does not redesign History, add filtering concepts beyond completed-run guidance, change backend run status semantics, or alter delta math.
