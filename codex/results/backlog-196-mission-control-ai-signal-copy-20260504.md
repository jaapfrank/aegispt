# backlog-196 Mission Control AI Signal Copy Validation

## Result

Completed. Mission Control AI Signal no longer exposes developer-facing labels such as `DETERMINISTIC MODE`, `BUILD LANE`, `PROVIDER`, `SIGNALS`, or `REPAIRS` in the operator panel.

## Product Truth

- The no-run AI Signal state now shows one clean operator message: `Select a run to see AI analysis.`
- The AI workbench heading is now `AI Review Workspace`.
- Internal labels were replaced with operator-facing language:
  - `Provider` -> `AI connection`
  - `Signals` -> `Recent reviews`
  - `Repairs` -> `Repair suggestions`
  - `Build-lane handoff` -> `Review handoff`
- Incoming older workbench payload labels/messages are sanitized before rendering, so stale backend payloads do not reintroduce developer copy.
- This was a UI-copy slice only. AI data fetching, backend APIs, approval gates, pack lifecycle, deployment, runtime binding, scope enforcement, credential gates, and kill-switch behavior were not changed.

## Files Changed

- `ui/assets/modules/mission-control.js`
- `ui/tests/test_operator_console_smoke_e2e.py`
- `CURRENT_STATE.md`
- `DONE_LOG.md`
- `NEXT_TASK.md`
- `codex/results/backlog-196-mission-control-ai-signal-copy-20260504.md`

## Validation

- `python3 scripts/validate_backlog_tasks.py` passed before implementation with exactly one active task.
- `source .venv/bin/activate && python -m pytest ui/tests/test_operator_console_smoke_e2e.py::test_mission_control_ai_signal_provider_badge_and_live_text ui/tests/test_operator_console_smoke_e2e.py::test_mission_control_ai_signal_select_run_when_chatgpt_connected_without_run ui/tests/test_operator_console_smoke_e2e.py::test_mission_control_ai_signal_connect_chatgpt_when_provider_disconnected_without_run -q` passed.
- `source .venv/bin/activate && python -m pytest ui/tests/test_operator_console_e2e.py::test_ai_signal_provider_disabled_state_is_static_and_readable -q` passed.
- `source .venv/bin/activate && python -m pytest api/tests/test_health.py -q` passed.
- `curl --fail --silent --max-time 5 http://127.0.0.1:8000/health/live` passed.
- Live Playwright safe acceptance against `http://127.0.0.1:8000/app/` passed with synthetic connected/no-run AI state and confirmed the clean no-run message plus absence of the forbidden developer labels.

## Remaining Risk

- This task intentionally did not change AI runtime behavior or backend AI signal payload generation.
- Browser acceptance covered the focused Mission Control AI Signal states required for this task, not a full enterprise UX audit.
