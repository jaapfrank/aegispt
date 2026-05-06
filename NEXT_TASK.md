# Active Task

## Title

Bottom navigation bar: remove redundant duplicate of sidebar navigation, or justify with mobile-first purpose

## Promoted From

`codex/tasks/backlog-200-bottom-nav-bar-remove-or-replace-sidebar.json`

## Goal

Remove or gate the redundant sticky bottom navigation bar that duplicates the sidebar so the operator console has one clear desktop navigation path and recovers the wasted screen height.

## Scope

Implement the active backlog package `codex/tasks/backlog-200-bottom-nav-bar-remove-or-replace-sidebar.json`.

Expected slice:

- evaluate the bottom navigation rendered from `BOTTOM_NAV_ITEMS` in `ui/assets/app.js`
- preferred action: remove the bottom navigation entirely because there is no documented mobile requirement
- alternative only if a current mobile story exists: restrict the bottom bar to mobile-only below 640px and hide the sidebar there
- remove associated bottom-nav CSS from `ui/assets/styles.css`
- run E2E coverage to prove no test relies on the bottom navigation

## Constraints

- Do not implement until this file is the single active task.
- Only remove or gate the bottom nav bar.
- Do not change sidebar navigation.
- Do not change topbar navigation.
- Do not change screen routing logic.
- Do not add new navigation structures.
- Do not bypass pack registry, validation, approval, deployment, runtime binding, scope, ROE, credentials, or kill switch.
- No runtime self-modification.
- No uncontrolled plugin installation.

## Validation

- `python3 scripts/validate_backlog_tasks.py`
- `source .venv/bin/activate && python -m pytest api/tests/test_health.py -q`
- `git diff --check`

## Acceptance

- Bottom navigation bar is not visible on a 1280px desktop viewport.
- All screens remain navigable through the sidebar.
- If bottom nav is kept for mobile, it is only visible below 640px.
- No E2E test relies on the bottom nav bar to pass.
- 44px of screen height is recovered on desktop pages.
