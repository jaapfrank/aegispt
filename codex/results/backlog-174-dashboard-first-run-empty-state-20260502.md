# Backlog 174 Result - Dashboard First-Run Empty State

Date: 2026-05-02

## Task

`backlog-174-dashboard-first-run-empty-state`

Dashboard first-run empty state: guide new operators with one actionable message instead of a blank screen.

## Outcome

The zero-engagement Dashboard now renders an intentional first-run empty state instead of the previous multi-card onboarding/quick-action layout:

- welcome heading: `Welcome to AegisPT`
- one-line product description: `Create a scoped assessment to collect evidence, track findings, and produce reports.`
- single primary CTA: `Start Your First Assessment`
- CTA uses the existing `data-nav-screen="wizard"` navigation binding
- muted truthful zero-state stats: `0 Active Runs`, `0 Open Findings`, `0 Engagements`

Populated Dashboard rendering and setup checklist logic were not changed.

## Files Changed

- `ui/assets/modules/dashboard.js`
  - added `renderFirstRunEmptyState()`
  - updated the zero-engagement `renderEmptyDashboard()` path to use the new single-CTA empty state
- `ui/assets/styles.css`
  - added scoped first-run empty-state and zero-stat styling
  - added responsive stacking for zero-stat tiles
- `ui/tests/test_operator_console_smoke_e2e.py`
  - updated the zero-engagement Dashboard smoke test to verify the empty state, CTA, zero stats, absence of old onboarding/checklist rendering, and CTA navigation to Wizard

## Validation

- `python3 scripts/validate_backlog_tasks.py`
  - passed before implementation with `193` queued task packages and exactly one active task
- `curl -fsS http://127.0.0.1:8000/health/live`
  - returned healthy JSON
- `node --input-type=module --check < ui/assets/modules/dashboard.js`
  - passed
- `python3 -m py_compile ui/tests/test_operator_console_smoke_e2e.py`
  - passed
- `source .venv/bin/activate && python -m pytest -s -q ui/tests/test_operator_console_smoke_e2e.py::test_dashboard_zero_engagement_renders_first_run_empty_state`
  - passed
- `source .venv/bin/activate && python -m pytest -s -q ui/tests/test_operator_console_smoke_e2e.py::test_dashboard_zero_engagement_renders_first_run_empty_state ui/tests/test_operator_console_smoke_e2e.py::test_dashboard_setup_checklist_dismiss_persists_in_settings ui/tests/test_operator_console_smoke_e2e.py::test_dashboard_activity_feed_renders_human_readable_audit_items`
  - passed
- `source .venv/bin/activate && python -m pytest api/tests/test_health.py -q`
  - not green: local pytest capture teardown still raises `_pytest/capture.py FileNotFoundError`
- `source .venv/bin/activate && python -m pytest -s -q api/tests/test_health.py`
  - passed
- live Playwright browser acceptance against `http://127.0.0.1:8000/app/`
  - desktop zero-engagement Dashboard empty state rendered
  - CTA navigated to Wizard
  - old first-run onboarding/checklist did not render in the zero-engagement empty state
  - narrow viewport check measured `mobile_body_width=390 scroll_width=390`, with no horizontal overflow
- `python3 scripts/validate_backlog_tasks.py`
  - passed before administration
- `git diff --check`
  - passed before administration

## Residual Risk

- The exact no-`-s` health pytest command still fails in this local shell because of the known pytest capture issue; the same health tests pass with `-s`.
- This slice intentionally did not rebuild populated Dashboard rendering, alter setup checklist persistence, change backend APIs, or change navigation structure.
