# Active Task

## Title

Fix Manage topbar button misleading label - it opens a delete modal not an engagement manager

## Promoted From

`codex/tasks/backlog-158-manage-button-misleading-label.json`

## Goal

Rename the "Manage" button in the topbar engagement area to "Delete Stale..." or "Cleanup..." so the label accurately describes the action (bulk-delete stale engagements with dry-run preview). The delete modal content and behavior remains unchanged. No new engagement edit form is required in this task - just fix the label to match the action.

## Scope

Implement the active backlog package `codex/tasks/backlog-158-manage-button-misleading-label.json`.

Expected slice:

- replace the misleading topbar "Manage" label with a cleanup/delete-oriented label
- keep the existing delete modal content and behavior unchanged
- do not add a new engagement CRUD manager
- do not redesign the topbar beyond the label/intent mismatch

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
- No regression in bulk-delete E2E tests.

## Acceptance

- Button is labeled "Delete Stale..." or similar - not "Manage".
- Delete modal content and behavior unchanged.
- No regression in bulk-delete E2E tests.
