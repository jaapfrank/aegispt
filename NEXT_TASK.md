# Active Task

## Title

Fix Mission Control AI Signal showing Connect ChatGPT on initial load when ChatGPT is globally connected

## Promoted From

`codex/tasks/backlog-161-mission-control-ai-signal-wrong-initial-state.json`

## Goal

When ChatGPT OAuth is globally connected (settings `ai.provider=chatgpt_oauth` and `GET /api/v1/auth/chatgpt/status` returns connected status), the AI Signal panel initial state must show `Select a run to see AI Signal insights` instead of `Connect ChatGPT in Settings`. Check the global ChatGPT connection status in the boot sequence, store the result in state, and use it in the AI panel render when no run is selected.

## Scope

Implement the active backlog package `codex/tasks/backlog-161-mission-control-ai-signal-wrong-initial-state.json`.

Expected slice:

- use the existing ChatGPT/OAuth status data already fetched by the app
- when no run is selected and ChatGPT is globally connected, render a select-run AI Signal message
- preserve current connected run-specific AI Signal behavior
- preserve the Connect ChatGPT guidance when the provider is truly disconnected
- do not add new AI provider endpoints or broad redesign

## Constraints

- Keep Prompt 1 and Prompt 2 intact.
- Do not bypass approval gates, pack registry, validation, deployment, or runtime binding.
- No runtime self-modification.
- Fix only the specific bug described.
- Do not use this task for broad redesign.
- Do not install new tools.
- Do not run live customer or intrusive targets.
- Do not change unrelated schemas or prompts.

## Validation

- `python3 scripts/validate_backlog_tasks.py`
- `source .venv/bin/activate && python -m pytest api/tests/test_health.py -q`
- `git diff --check`

## Acceptance

- When ChatGPT is globally connected and no run is selected, the AI Signal panel shows `Select a run to view AI Signal`.
- When ChatGPT is connected and a run is selected, the existing run-specific AI Signal behavior remains.
- When ChatGPT is truly disconnected, the panel still shows `Connect ChatGPT in Settings`.
- No regression in AI Signal E2E tests.
