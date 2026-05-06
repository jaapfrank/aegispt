# Active Task

## Title

Settings page navigation overhaul: replace 28-panel vertical list with tabbed category navigation

## Promoted From

`codex/tasks/backlog-203-settings-page-navigation-overhaul.json`

## Goal

Improve the Settings screen so operators can navigate the existing settings panels through five focused tabs and a search/filter input, while preserving the existing panel content, panel rendering model, and settings save/load behavior.

## Scope

Implement the active backlog package `codex/tasks/backlog-203-settings-page-navigation-overhaul.json`.

Expected slice:

- add a five-tab navigation bar at the top of Settings content
- use the categories `AI & Provider`, `Tools & Runtime`, `Integrations`, `Data & Security`, and `Identity & Users`
- show only panels relevant to the selected tab, with no more than six panels per tab
- keep existing expand/collapse behavior within each tab
- add a prominent `Find a setting...` search/filter input that highlights matching panels across tabs
- preserve the existing `DEFAULT_SETTINGS_PANELS` object and panel rendering content

## Constraints

- Do not implement until this file is the single active task.
- Add tab navigation and search only.
- Do not change panel content.
- Do not change settings save/load logic.
- Do not change backend settings APIs.
- Do not bypass pack registry, validation, approval, deployment, runtime binding, scope, ROE, credentials, or kill switch.
- No runtime self-modification.
- No uncontrolled plugin installation.

## Validation

- `python3 scripts/validate_backlog_tasks.py`
- `source .venv/bin/activate && python -m pytest api/tests/test_health.py -q`
- `git diff --check`

## Acceptance

- Settings screen shows a 5-tab navigation bar at top.
- Each tab shows only the panels relevant to its category.
- All existing panels remain accessible through tabs or search.
- Search input narrows/highlights visible panels across tabs.
- Settings screen no longer requires 10+ viewport scrolls to see all panels.
- E2E tests pass.
