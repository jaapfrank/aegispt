# backlog-161 AI Signal Global ChatGPT No-Run Validation - 2026-05-01

## Result

Completed backlog-161 `Fix Mission Control AI Signal showing Connect ChatGPT on initial load when ChatGPT is globally connected`.

Mission Control now reads the existing engagement-scoped ChatGPT OAuth status during `refreshSelectedEngagement()` and stores it in `state.chatgptOAuthStatus`. The AI Signal panel uses that global status only when no run is selected, so a globally connected ChatGPT provider renders `ChatGPT connected` with `Select a run to view AI Signal` instead of sending operators to Settings.

Run-specific AI Signal behavior remains driven by the selected run's guidance, insights, live stream, and provider status. When ChatGPT OAuth is configured but not connected, the panel still shows the `Connect ChatGPT in Settings` action. No backend endpoint, provider flow, approval gate, runtime behavior, or pack flow was added.

## Files

- `ui/assets/app.js`
- `ui/assets/modules/mission-control.js`
- `ui/index.html`
- `ui/tests/test_operator_console_smoke_e2e.py`
- `CURRENT_STATE.md`
- `DONE_LOG.md`
- `NEXT_TASK.md`
- `codex/results/backlog-161-ai-signal-global-chatgpt-no-run-validation-20260501.md`

## Validation

- `python3 scripts/validate_backlog_tasks.py` passed before implementation: `Backlog validation passed: 187 queued task packages mapped one-to-one, and NEXT_TASK.md contains exactly one active task.`
- `node --input-type=module --check < ui/assets/app.js` passed.
- `node --input-type=module --check < ui/assets/modules/mission-control.js` passed.
- `source .venv/bin/activate && python -m pytest ui/tests/test_operator_console_smoke_e2e.py -s -q -k "ai_signal"` passed.
- `source .venv/bin/activate && python -m pytest ui/tests/test_operator_console_e2e.py -s -q -k "ai_signal_provider_disabled_state"` initially exposed a connected/disconnected copy regression, then passed after the disabled state was restored to the ChatGPT connection action contract.
- `source .venv/bin/activate && python -m pytest api/tests/test_health.py -q` hit the known local `_pytest/capture.py FileNotFoundError` before assertions and is not claimed green.
- `source .venv/bin/activate && python -m pytest api/tests/test_health.py -s -q` passed.
- `curl --max-time 5 -fsS http://127.0.0.1:8000/health/live` returned healthy JSON.
- Live Playwright acceptance against `http://127.0.0.1:8000/app/` passed for both no-run states:
  - connected global ChatGPT OAuth: `ChatGPT connected` and `Select a run to view AI Signal`, with no `Connect ChatGPT in Settings`
  - disconnected global ChatGPT OAuth: `Connect ChatGPT in Settings` remains enabled
- `git diff --check` passed before and after documentation/promotion updates.
- `python3 scripts/validate_backlog_tasks.py` passed after promotion to backlog-162: `Backlog validation passed: 187 queued task packages mapped one-to-one, and NEXT_TASK.md contains exactly one active task.`

## Residual Risk

- The exact no-`-s` health pytest command remains blocked by the local pytest capture cleanup issue.
- This slice fixes the initial Mission Control AI Signal state only. It does not change ChatGPT OAuth authorization, AI Signal generation, repair actions, or finding enrichment behavior.
