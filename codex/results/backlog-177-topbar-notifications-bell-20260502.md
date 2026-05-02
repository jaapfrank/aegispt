# backlog-177 topbar notifications bell validation

## Outcome

The product topbar already followed the preferred safe option for this task: the redundant notifications bell is absent, and the gear button is the only topbar control that navigates to Settings.

This slice adds a stronger regression guard so the topbar cannot silently regain a second Settings shortcut:

- `topbar-notifications` must be absent.
- `aria-label="Notifications"` must be absent.
- `aria-label="Open notification settings"` must be absent.
- the topbar must contain exactly one `[data-nav-screen="settings"]` control.
- `topbar-settings` must remain visible and open Settings.

No topbar product DOM, Settings screen content, navigation gating, backend API, notification backend, approval gate, pack registry, deployment, or runtime binding behavior changed.

## Browser acceptance

Live browser acceptance against `http://127.0.0.1:8000/app/` passed with:

- `live_topbar_settings_destinations=1`
- `bell_present=0`
- `settings_reachable=1`

## Validation

- `python3 scripts/validate_backlog_tasks.py` passed before implementation with `193` queued task packages and exactly one active task.
- `curl -fsS http://127.0.0.1:8000/health/live` returned healthy JSON.
- `python3 -m py_compile ui/tests/test_operator_console_smoke_e2e.py` passed.
- `source .venv/bin/activate && python -m pytest -s -q ui/tests/test_operator_console_smoke_e2e.py::test_topbar_notifications_placeholder_is_removed_and_settings_still_opens ui/tests/test_operator_console_smoke_e2e.py::test_operator_console_fast_navigation_smoke` passed.
- Live Playwright browser acceptance passed.
- `source .venv/bin/activate && python -m pytest api/tests/test_health.py -q` failed with the known local `_pytest/capture.py FileNotFoundError`; this is not claimed green.
- `source .venv/bin/activate && python -m pytest -s -q api/tests/test_health.py` passed.
- `python3 scripts/validate_backlog_tasks.py` passed after promoting backlog-178.
- `git diff --check` passed.

## Residual risk

- This task chose the narrow preferred option, removing/guarding the redundant bell. It does not introduce a real notification event panel or backend notification delivery.
- The exact no-`-s` health pytest command remains subject to the known local `_pytest/capture.py FileNotFoundError`; the same health tests are rerun with `-s` for truthful local health evidence.
