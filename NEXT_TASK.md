# Active Task

## Title

Mission Control header: fix button order, intents, and styling for operational clarity

## Promoted From

`codex/tasks/backlog-172-mission-control-header-buttons-reorder.json`

## Goal

Correct Mission Control header action order and styling so destructive, primary, navigation, and secondary actions are visually clear.

## Scope

Implement the active backlog package `codex/tasks/backlog-172-mission-control-header-buttons-reorder.json`.

Expected slice:

- update Mission Control header button DOM order in `ui/index.html`
- make `Kill Run` use `action danger`
- keep `Start Queued Checks` as the contextual primary action
- keep `View Findings` as a primary action
- make `View Agents` use `action ghost` or `action secondary`, not danger
- make `Cinema Mode` use ghost styling
- preserve existing button handlers and behavior

## Constraints

- Keep Prompt 1 and Prompt 2 intact.
- Do not bypass approval gates, pack registry, validation, deployment, or runtime binding.
- No runtime self-modification.
- Do not install uncontrolled plugins.
- Only update button CSS classes and DOM order in `ui/index.html`.
- Do not change button functionality, handlers, Mission Control JS modules, run cancellation logic, backend APIs, or broader Mission Control layout.

## Validation

- `python3 scripts/validate_backlog_tasks.py`
- `source .venv/bin/activate && python -m pytest api/tests/test_health.py -q`
- `git diff --check`
- Focused Mission Control UI/E2E coverage proving button order and styling
- Browser/safe acceptance where relevant

## Acceptance

- Kill Run renders as danger styling.
- View Agents renders as ghost or secondary styling and is not danger.
- Button visual order is: Kill Run, Start Queued Checks, View Findings, View Agents, Cinema Mode.
- Button functionality is unchanged.
- Mission Control E2E coverage does not regress.
