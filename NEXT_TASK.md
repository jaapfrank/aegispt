# Active Task

## Title

Fix topbar notifications bell: remove redundant Settings shortcut or implement a minimal notification panel

## Promoted From

`codex/tasks/backlog-177-notifications-bell-fix-or-implement.json`

## Goal

Resolve the confusing duplicate topbar actions where the bell and gear both navigate to Settings. Prefer removing the redundant bell unless a minimal notification panel can be implemented safely within this slice.

## Scope

Implement the active backlog package `codex/tasks/backlog-177-notifications-bell-fix-or-implement.json`.

Expected slice:

- inspect the current topbar bell/settings controls
- ensure there is at most one topbar action that navigates to Settings
- if keeping the bell, give it a lightweight event panel from existing state only
- if removing the bell, leave Settings reachable through the gear action
- preserve topbar density and existing navigation behavior

## Constraints

- Keep Prompt 1 and Prompt 2 intact.
- Do not bypass approval gates, pack registry, validation, deployment, or runtime binding.
- No runtime self-modification.
- Do not install uncontrolled plugins.
- Do not build a full notification backend.
- Do not add backend notification events.
- Do not redesign the topbar.
- Do not change Settings screen content.
- Do not change navigation gating.

## Validation

- `python3 scripts/validate_backlog_tasks.py`
- `source .venv/bin/activate && python -m pytest api/tests/test_health.py -q`
- `git diff --check`
- Focused topbar/UI coverage proving Settings remains reachable and the duplicate bell/settings destination is gone or the bell has a dedicated minimal panel
- Browser/safe acceptance where relevant

## Acceptance

- There is at most one topbar button that navigates to Settings.
- If a notification panel is implemented, it shows at least recent run status events from existing state.
- If the bell is removed, the topbar has only the gear button for Settings.
- The Settings screen remains fully reachable.
- No topbar/navigation E2E regressions.
