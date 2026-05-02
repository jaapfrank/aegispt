# Active Task

## Title

Problems Center: replace zero-count display with a meaningful empty state and actionable guidance

## Promoted From

`codex/tasks/backlog-179-problems-center-zero-state-cleanup.json`

## Goal

Replace the Problems Center's empty zero-count display with meaningful operator guidance, and keep confirmed/suspected/discounted count summaries only when at least one category has a non-zero count.

## Scope

Implement the active backlog package `codex/tasks/backlog-179-problems-center-zero-state-cleanup.json`.

Expected slice:

- update Problems Center empty/zero-state display logic in `ui/assets/modules/problems.js`
- when total finding count is zero, show `No open problems — findings from completed runs appear here.` and a `Go to Mission Control` action
- when findings exist but all are resolved, show `All problems resolved. Start a new run to re-validate.`
- only show confirmed/suspected/discounted count summary when at least one count is greater than zero
- verify the count summary maps to actual finding status values returned by the API

## Constraints

- Keep Prompt 1 and Prompt 2 intact.
- Do not bypass approval gates, pack registry, validation, deployment, or runtime binding.
- No runtime self-modification.
- Do not install uncontrolled plugins.
- Only update empty/zero-state display logic.
- Do not rebuild the Problems Center layout.
- Do not add new problem status types.
- Do not change the finding status model.
- Do not change backend findings APIs.
- Do not change Findings Theater.

## Validation

- `python3 scripts/validate_backlog_tasks.py`
- `source .venv/bin/activate && python -m pytest api/tests/test_health.py -q`
- `git diff --check`
- Focused Problems Center UI/E2E coverage for zero findings, all resolved findings, and non-zero count summaries
- Browser/safe acceptance where relevant

## Acceptance

- Zero findings: Problems Center shows a one-sentence empty state and a navigation action.
- All findings resolved: Problems Center shows resolved-state guidance.
- Count summary only appears when at least one count is non-zero.
- No Problems Center E2E regressions.
