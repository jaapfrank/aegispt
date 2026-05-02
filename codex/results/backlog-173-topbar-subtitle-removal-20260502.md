# Backlog 173 Result - Topbar Subtitle Removal

Date: 2026-05-02

## Task

`backlog-173-topbar-subtitle-too-verbose`

Shorten or remove the repeated topbar/hero subtitle:

`Guided, evidence-first assessment operations across wizard-driven setup, live mission control, adaptive pack governance, evidence replay, and report delivery.`

## Outcome

The current product source already had the long application-shell subtitle removed. No replacement tagline was present and no dashboard-only tagline was added. The topbar remains a compact single-row operator control surface.

No `ui/index.html` or `ui/assets/styles.css` product edit was required. The safe implementation was to add focused Playwright regression coverage proving:

- the long subtitle is absent while navigating representative rendered screens
- the desktop topbar remains within the required compact height range

## Files Changed

- `ui/tests/test_operator_console_smoke_e2e.py`
  - added `test_application_shell_has_no_repeated_marketing_subtitle`
  - the test visits Dashboard, Wizard, Mission Control, Live Agents, Findings, Reports, History, and Settings
  - the test asserts the long subtitle is absent from rendered body text
  - the test asserts desktop topbar height remains between `48` and `56` px

## Validation

- `python3 scripts/validate_backlog_tasks.py`
  - passed before implementation with `193` queued task packages and exactly one active task
- `curl -fsS http://127.0.0.1:8000/health/live`
  - returned healthy JSON
- `python3 -m py_compile ui/tests/test_operator_console_smoke_e2e.py`
  - passed
- `source .venv/bin/activate && python -m pytest -s -q ui/tests/test_operator_console_smoke_e2e.py::test_application_shell_has_no_repeated_marketing_subtitle`
  - passed
- `source .venv/bin/activate && python -m pytest api/tests/test_health.py -q`
  - not green: local pytest capture teardown still raises `_pytest/capture.py FileNotFoundError`
- `source .venv/bin/activate && python -m pytest -s -q api/tests/test_health.py`
  - passed
- `rg -n "Guided, evidence-first assessment operations|adaptive pack governance|evidence replay, and report delivery|Penetration testing operations platform" ui/index.html ui/assets/styles.css ui/assets/modules`
  - returned no matches
- `curl -fsS http://127.0.0.1:8000/app/ | rg -n "Guided, evidence-first|adaptive pack governance|evidence replay, and report delivery|topbar|screen-dashboard"`
  - showed topbar/dashboard HTML and no long subtitle matches
- live Playwright browser acceptance against `http://127.0.0.1:8000/app/`
  - visited the representative screens
  - confirmed the long subtitle is absent
  - measured `topbar_height=48`

## Residual Risk

- The exact no-`-s` health pytest command still fails in this local shell because of the known pytest capture issue; the same health tests pass with `-s`.
- This slice intentionally did not redesign the topbar, move copy into Settings/About, or alter screen headings/navigation/backend behavior because the long subtitle was already absent.
