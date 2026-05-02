# Active Task

## Title

History screen: add meaningful empty state when no completed runs exist

## Promoted From

`codex/tasks/backlog-178-history-screen-empty-state.json`

## Goal

Make the History & Comparison screen useful for new and single-run operators by showing clear guidance when there is no completed-run history yet, and by explaining why comparison is unavailable when only one completed run exists.

## Scope

Implement the active backlog package `codex/tasks/backlog-178-history-screen-empty-state.json`.

Expected slice:

- update the History screen content rendering in `ui/assets/modules/explorer-history.js`
- for zero completed runs, show a one-sentence empty state and a navigation action to Mission Control
- for one completed run, show the single run summary and disable/explain comparison controls
- preserve existing comparison behavior for two or more completed runs
- do not add new data fetching or backend behavior

## Constraints

- Keep Prompt 1 and Prompt 2 intact.
- Do not bypass approval gates, pack registry, validation, deployment, or runtime binding.
- No runtime self-modification.
- Do not install uncontrolled plugins.
- Add empty states only.
- Do not rebuild History comparison logic.
- Do not add new data fetching.
- Do not change run delta computation.
- Do not change backend APIs.

## Validation

- `python3 scripts/validate_backlog_tasks.py`
- `source .venv/bin/activate && python -m pytest api/tests/test_health.py -q`
- `git diff --check`
- Focused History UI/E2E coverage for zero-run, single-run, and two-run states
- Browser/safe acceptance where relevant

## Acceptance

- Zero completed runs: History shows a one-sentence explanation and a navigation action.
- One completed run: History shows the single run summary and explains disabled comparison.
- Two or more completed runs: History comparison behavior remains unchanged.
- No History E2E regressions.
