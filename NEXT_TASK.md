# Active Task

## Title

Fix non-functional notifications bell placeholder in topbar

## Promoted From

`codex/tasks/backlog-160-notifications-bell-non-functional-placeholder.json`

## Goal

Remove the notifications bell from the topbar entirely. This is the safest fix - a broken bell is worse than no bell. If a notification panel is desired instead, it must: open on click, close on Escape or second click, show last 5 audit events from the existing dashboard API response, and require no new backend endpoints. Removing is strongly preferred for this task.

## Scope

Implement the active backlog package `codex/tasks/backlog-160-notifications-bell-non-functional-placeholder.json`.

Expected slice:

- remove the non-functional notifications bell from the topbar, or implement a minimal real panel
- if removed, keep adjacent topbar layout and settings controls intact
- if implemented, use only existing dashboard/audit data and no new backend endpoints
- do not add a fake placeholder panel

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

- Notifications bell is either removed or opens a real panel with content.
- If removed: no other topbar element is broken and layout remains intact.
- If implemented: panel shows recent audit events from existing dashboard API data.
- No regression in topbar-related tests.
