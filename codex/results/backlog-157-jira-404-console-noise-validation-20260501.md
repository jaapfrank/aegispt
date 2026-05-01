# Backlog 157 - Jira 404 Console Noise Validation

Date: 2026-05-01

## Scope

Fixed the Findings drawer Jira configuration lookup so an unconfigured Jira integration does not issue a known-404 request on every drawer render. The drawer still shows the existing "Configure Jira in Settings" guidance, and a configured Jira base URL still allows the engagement-scoped Jira configuration fetch and handoff controls to work.

## Files Changed

- `ui/assets/modules/findings.js`
- `ui/tests/test_operator_console_smoke_e2e.py`

## Browser Acceptance

- Added `test_findings_jira_unconfigured_does_not_fetch_missing_integration`.
  - Sets cached operator settings with an empty `integrations.jira_base_url`.
  - Installs a route that would record any Jira integration GET.
  - Renders the selected finding drawer.
  - Confirms the drawer shows "Configure Jira in Settings".
  - Confirms no `/api/v1/engagements/*/integrations/jira` request was made.

- Added `test_findings_jira_configured_fetch_still_enables_handoff`.
  - Sets cached operator settings with `https://jira.example.test`.
  - Confirms one Jira integration GET is made.
  - Confirms the `Push to Jira` control becomes visible.

## Validation

Passed:

- `python3 scripts/validate_backlog_tasks.py`
- `source .venv/bin/activate && python -m pytest -s -q ui/tests/test_operator_console_smoke_e2e.py::test_findings_jira_unconfigured_does_not_fetch_missing_integration ui/tests/test_operator_console_smoke_e2e.py::test_findings_jira_configured_fetch_still_enables_handoff ui/tests/test_operator_console_smoke_e2e.py::test_findings_jira_handoff_button_creates_badge`
- `source .venv/bin/activate && python -m pytest -s -q api/tests/test_health.py`
- `source .venv/bin/activate && python -m pytest -s -q api/tests/test_integrations.py`
- `git diff --check`

Not claimed green:

- Exact required command `source .venv/bin/activate && python -m pytest api/tests/test_health.py -q` hit the known local pytest capture failure: `FileNotFoundError` in `_pytest/capture.py`. The same health tests passed with `-s`.
- GitHub Actions `ci` remains red because the full `pytest` workflow currently reports broad pre-existing failures, including AI provider status and stale UI-flow expectations. `validation-matrix` is green.

## Remaining Risk

This slice only removes missing-Jira console noise from the Findings drawer and preserves configured Jira handoff behavior. It does not redesign Jira Settings, fix broader full-suite GitHub failures, or alter Jira API semantics.
