# Backlog 168 - Complete Assessment Wizard CTA Scoping

Date: 2026-05-02

## Summary

The `Complete Assessment Wizard` CTA is now scoped to useful intake moments instead of appearing during run review. The topbar CTA is visible on the Wizard screen and on Dashboard when no run context exists. It is hidden on Mission Control, Findings, Reports, and History when a selected run, dashboard active run, or mission run list is present.

The sidebar `Intake` navigation remains available, so operators can intentionally return to the wizard without being pushed there by a prominent CTA while reviewing active or completed mission work.

## Implementation

- Added explicit run-context detection for the wizard-completion CTA in `ui/assets/app.js`.
- Rendered the CTA only through the existing `topbar-nav` slot, without changing wizard steps, run dispatch, cancellation, backend APIs, pack registry, approval gates, deployment, or runtime binding.
- Added minimal styling for the topbar CTA in `ui/assets/styles.css`.
- Added focused Playwright smoke coverage proving:
  - CTA visible on Wizard with no run context.
  - CTA visible on Dashboard with no run context.
  - CTA click opens Wizard.
  - CTA hidden on Mission Control, Findings, Reports, and History when a running run exists.
  - Sidebar `Intake` remains reachable.

## Narrow Safety Choice

The task package text mentioned gating on `state.selectedRun` being absent or in a terminal state, while the concrete acceptance criteria require the CTA to be hidden for queued, running, and complete run contexts. I followed the concrete user-facing acceptance criteria and hid the CTA on the listed review screens whenever run context exists.

## Validation

- `python3 scripts/validate_backlog_tasks.py` passed.
- `source .venv/bin/activate && python -m pytest api/tests/test_health.py -q` failed with the known local pytest capture teardown `FileNotFoundError`; this is not a health assertion failure.
- `source .venv/bin/activate && python -m pytest -s -q api/tests/test_health.py` passed.
- `source .venv/bin/activate && python -m pytest -s -q ui/tests/test_operator_console_smoke_e2e.py::test_complete_assessment_wizard_cta_is_scoped_to_missing_run_context` passed.
- `source .venv/bin/activate && python -m pytest -s -q ui/tests/test_mockup_port_e2e.py::test_lan_wizard_routes_private_cidr_to_discovery_lane` passed.
- Live Playwright acceptance against `http://127.0.0.1:8000/app/` passed.
- `git diff --check` passed.

## Remaining Risk

- The exact no-`-s` health pytest command still hits the pre-existing local pytest capture teardown.
- This slice intentionally does not redesign topbar/navigation structure, wizard step logic, dispatch, cancellation, or backend behavior.
