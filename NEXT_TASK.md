# Active Task

## Title

Fix Jira 404 console error fired on every findings drawer open when Jira not configured

## Promoted From

`codex/tasks/backlog-157-jira-404-console-error-findings-drawer.json`

## Goal

In the findings drawer JS, change the Jira integration status fetch from api() to apiOrNull() so a 404 does not produce a browser console error. Alternatively, check cached state.settings.integrations.jira_base_url before calling - if null or empty, skip the Jira fetch entirely and show a static "Configure Jira in Settings" hint without an API roundtrip.

## Scope

Implement the active backlog package `codex/tasks/backlog-157-jira-404-console-error-findings-drawer.json`.

Expected slice:

- prevent a missing Jira configuration from producing browser console 404 noise on every finding drawer open
- keep the "Configure Jira in Settings" guidance visible when Jira is unconfigured
- keep the configured-Jira fetch and handoff behavior working
- do not broaden Jira integration behavior beyond this drawer-console bug

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
- No regression in Jira handoff tests.

## Acceptance

- Opening finding drawer with Jira unconfigured produces no 404 console error.
- Drawer still shows "Configure Jira in Settings" when unconfigured.
- When Jira IS configured the fetch runs normally.
- No regression in Jira handoff tests.
