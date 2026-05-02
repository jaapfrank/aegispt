# backlog-170 Actor Input Identity Display

## Result

Completed backlog-170. The topbar actor area is now a read-only identity display pill: it shows the current operator name, role badge, and an avatar initial derived from the actor name. The hidden/editable `#actor-input` was removed from the topbar.

Actor identity changes now route through Settings > Instance via `instance.operator_display_name`. Saving that setting updates localStorage-backed actor state, keeps the existing `X-Actor` API fallback contract, and refreshes the topbar display without changing approval gate logic or backend RBAC behavior.

Mission Control approval guidance now points operators to Settings > Instance when a second approval requires a different actor.

## Files Changed

- `ui/index.html`
- `ui/assets/app.js`
- `ui/assets/modules/settings.js`
- `ui/assets/modules/mission-control.js`
- `ui/assets/styles.css`
- `ui/tests/test_operator_console_smoke_e2e.py`
- `ui/tests/test_operator_console_e2e.py`
- `CURRENT_STATE.md`
- `DONE_LOG.md`
- `NEXT_TASK.md`

## Validation

- `python3 scripts/validate_backlog_tasks.py` passed before implementation with 193 queued task packages and exactly one active task.
- `source .venv/bin/activate && python -m pytest -s -q ui/tests/test_operator_console_smoke_e2e.py::test_topbar_actor_identity_is_read_only_and_settings_backed` passed.
- `source .venv/bin/activate && python -m pytest -s -q ui/tests/test_operator_console_e2e.py::test_pending_approval_run_can_be_approved_from_mission_control ui/tests/test_operator_console_e2e.py::test_pending_approval_run_guides_actor_switch_for_second_approver ui/tests/test_operator_console_e2e.py::test_first_run_onboarding_prefills_wizard_defaults` passed.
- `source .venv/bin/activate && python -m pytest -s -q api/tests/test_auth_and_roe_gate.py::test_x_actor_fallback_still_works_with_deprecation_warning` passed.
- `source .venv/bin/activate && python -m pytest -q api/tests/test_health.py` hit the known local `_pytest/capture.py FileNotFoundError` during capture teardown and is not claimed green.
- `source .venv/bin/activate && python -m pytest -s -q api/tests/test_health.py` passed.
- `curl -fsS http://127.0.0.1:8000/health/live` returned healthy JSON.
- `curl -fsS http://127.0.0.1:8000/app/ | rg -n "actor-input|topbar-actor-pill|actor-display"` confirmed the live HTML contains `topbar-actor-pill` and `actor-display` and no `actor-input`.
- `git diff --check` passed before administration.

## Residual Risk

- The exact no-`-s` health pytest command still fails in this shell because of the known pytest capture tempfile issue; the health tests pass with capture disabled.
- This slice intentionally does not implement full login/auth/RBAC or change approval gate API rules.
- Live browser acceptance used isolated Playwright app servers for mutable Settings flows to avoid changing the currently running local instance.
