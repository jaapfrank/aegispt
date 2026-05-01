# Active Task

## Title

Fix 'View Agents' button in Mission Control: change action danger to action secondary

## Promoted From

`codex/tasks/backlog-165-view-agents-button-danger-class.json`

## Goal

In ui/index.html, the 'View Agents ↗' button at line 143 in the Mission Control screen header uses CSS class 'action danger', which renders it red and implies a destructive action. Change the class to 'action secondary' or 'action ghost' so the button reads as a navigation action, not a destructive one. Verify no other navigation buttons in screen headers use 'action danger' incorrectly.

## Scope

Implement the active backlog package `codex/tasks/backlog-165-view-agents-button-danger-class.json`.

Expected slice:

- change the Mission Control `View Agents` navigation button from danger styling to secondary or ghost styling
- preserve its existing navigation behavior to the Live Agents screen
- verify destructive buttons such as `Kill Run` keep danger styling
- verify no other screen-head navigation button is incorrectly marked as danger

## Constraints

- Keep Prompt 1 and Prompt 2 intact.
- Do not bypass approval gates, pack registry, validation, deployment, or runtime binding.
- No runtime self-modification.
- Do not install uncontrolled plugins.
- Do not change approval or scope gate logic.
- Do not change backend APIs.
- Do not redesign Mission Control layout.
- Do not change the destructive styling of real destructive actions such as Kill Run.

## Validation

- `python3 scripts/validate_backlog_tasks.py`
- `source .venv/bin/activate && python -m pytest api/tests/test_health.py -q`
- `git diff --check`
- Focused Mission Control E2E/smoke coverage for the View Agents button and destructive button styling

## Acceptance

- View Agents button renders with secondary/ghost styling, not red/danger.
- View Agents still navigates to the Agents screen.
- Kill Run remains styled as danger.
- No regression in Mission Control E2E tests.
