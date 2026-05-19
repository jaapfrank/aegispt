# Backlog 175 Result - Topbar Stats Chip Labels

Date: 2026-05-02

## Task

`backlog-175-topbar-stats-chips-label-clarity`

Fix topbar stats chips: label ambiguity and redundant subtitle labels.

## Outcome

The older redundant topbar labels (`ENGAGEMENTS · DOSSIERS`, `RUNS · MISSIONS`, and `OPEN ITEMS · BASELINE`) are absent from the current product UI source. The active topbar count/status chip is the run status chip, and it now renders as a simple count-plus-noun label:

- running tasks: `N Running Task(s)`
- queued tasks: `N Queued Task(s)`
- active queued/running run without task counts: `1 Active Run`

The chip keeps the existing topbar layout and data sources. A `data-testid="topbar-run-status-label"` hook was added for focused regression coverage.

## Files Changed

- `ui/assets/app.js`
  - changed topbar run-status copy from lowercase verb phrases such as `2 running` / `1 queued` to clear count-plus-noun labels
  - removed profile-name fallback copy from the status chip in favor of `1 Active Run`
  - added a focused test id for the status label
- `ui/tests/test_operator_console_smoke_e2e.py`
  - added smoke coverage proving the visible topbar status chip uses a simple `N Noun` label, has no mid-dot separator, does not contain `DOSSIERS`, `MISSIONS`, or `BASELINE`, and renders at least 11px

## Validation

- `python3 scripts/validate_backlog_tasks.py`
  - passed before implementation with `193` queued task packages and exactly one active task
- `curl -fsS http://127.0.0.1:8000/health/live`
  - returned healthy JSON
- `node --input-type=module --check < ui/assets/app.js`
  - passed
- `python3 -m py_compile ui/tests/test_operator_console_smoke_e2e.py`
  - passed
- `source .venv/bin/activate && python -m pytest -s -q ui/tests/test_operator_console_smoke_e2e.py::test_topbar_status_chip_labels_are_simple_and_readable`
  - passed
- `source .venv/bin/activate && python -m pytest -s -q ui/tests/test_live_system_audit_2026_05_01.py::test_topbar_stats_chips_no_redundant_labels`
  - passed
- `source .venv/bin/activate && python -m pytest -s -q ui/tests/test_operator_console_smoke_e2e.py::test_application_shell_has_no_repeated_marketing_subtitle ui/tests/test_operator_console_smoke_e2e.py::test_topbar_status_chip_labels_are_simple_and_readable ui/tests/test_operator_console_smoke_e2e.py::test_topbar_actor_identity_is_read_only_and_settings_backed`
  - passed
- `rg -n "ENGAGEMENTS · DOSSIERS|RUNS · MISSIONS|OPEN ITEMS · BASELINE|DOSSIERS|MISSIONS|BASELINE" ui/assets ui/index.html`
  - returned no product-source matches
- live Playwright browser acceptance against `http://127.0.0.1:8000/app/`
  - rendered `topbar_status_text=1 Running Task`
  - measured `font_size=12.48`
  - confirmed no mid-dot separator and no redundant suffix words
- `source .venv/bin/activate && python -m pytest api/tests/test_health.py -q`
  - not green: local pytest capture teardown still raises `_pytest/capture.py FileNotFoundError`
- `source .venv/bin/activate && python -m pytest -s -q api/tests/test_health.py`
  - passed
- `python3 scripts/validate_backlog_tasks.py`
  - passed before administration
- `git diff --check`
  - passed before administration

## Residual Risk

- The exact no-`-s` health pytest command still fails in this local shell because of the known pytest capture issue; the same health tests pass with `-s`.
- This slice intentionally did not change engagement/run/finding data fetching, backend APIs, topbar layout structure, or chip navigation behavior.
