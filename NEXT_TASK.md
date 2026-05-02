# Active Task

## Title

Clean up Report Center copy: remove internal dev language and improve empty state messaging

## Promoted From

`codex/tasks/backlog-171-report-center-copy-cleanup.json`

## Goal

Clean up user-visible Report Center copy so enterprise operators see clear product language instead of internal design or developer-facing placeholder terms.

## Scope

Implement the active backlog package `codex/tasks/backlog-171-report-center-copy-cleanup.json`.

Expected slice:

- audit operator-visible strings in `ui/assets/modules/reports.js` and `ui/index.html` for the Report Center screen
- replace the screen-copy `Work from the current run strip, open the report you need, and export without a side metadata rail.` with `Review and export technical, executive, and compliance reports for the selected run.`
- rename `Prior Report Delta` to `Compare with Earlier Run`
- replace the confusing comparison instruction with `Select a previous run to compare findings, coverage, and risk score changes.`
- replace Report Reader placeholder/no-selection copy with a one-sentence operator empty state
- clean up developer-facing `reportPlaceholder` strings where they are visible to operators

## Constraints

- Keep Prompt 1 and Prompt 2 intact.
- Do not bypass approval gates, pack registry, validation, deployment, or runtime binding.
- No runtime self-modification.
- Do not install uncontrolled plugins.
- Only update string copy and empty state messages.
- Do not restructure Report Center layout.
- Do not change report generation, export/download behavior, backend report APIs, or PDF generation.

## Validation

- `python3 scripts/validate_backlog_tasks.py`
- `source .venv/bin/activate && python -m pytest api/tests/test_health.py -q`
- `git diff --check`
- Focused Report Center UI/E2E coverage where available/relevant
- Browser/safe acceptance where relevant

## Acceptance

- Report Center screen-copy is operator-appropriate and does not mention internal design terms.
- `Prior Report Delta` is replaced with a clearer comparison label and instruction.
- Report Reader empty state guides the operator to select a report.
- No internal/dev-facing strings are visible to operators in the Report Center.
- Report Center E2E tests do not regress.
