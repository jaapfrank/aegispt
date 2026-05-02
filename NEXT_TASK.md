# Active Task

## Title

Dashboard first-run empty state: guide new operators with one actionable message instead of a blank screen

## Promoted From

`codex/tasks/backlog-174-dashboard-first-run-empty-state.json`

## Goal

When there are no engagements, runs, or findings, make Dashboard feel intentionally empty instead of broken by showing clear first-run guidance and one primary next step.

## Scope

Implement the active backlog package `codex/tasks/backlog-174-dashboard-first-run-empty-state.json`.

Expected slice:

- update the zero-engagement Dashboard empty state in `ui/assets/modules/dashboard.js`
- show a welcome heading
- show a one-line description of what AegisPT does
- show one primary CTA: `Start Your First Assessment`
- make that CTA navigate to the wizard screen
- optionally keep muted zero-state summary tiles if they are truthful and not noisy

## Constraints

- Keep Prompt 1 and Prompt 2 intact.
- Do not bypass approval gates, pack registry, validation, deployment, or runtime binding.
- No runtime self-modification.
- Do not install uncontrolled plugins.
- Only add or refine the zero-engagement Dashboard empty state.
- Do not rebuild populated Dashboard rendering.
- Do not change setup checklist logic, backend APIs, report generation, runtime behavior, or navigation structure.

## Validation

- `python3 scripts/validate_backlog_tasks.py`
- `source .venv/bin/activate && python -m pytest api/tests/test_health.py -q`
- `git diff --check`
- Focused Dashboard UI/E2E coverage proving the first-run empty state and CTA navigation
- Browser/safe acceptance where relevant

## Acceptance

- Zero-engagement Dashboard shows a welcome heading, one-line description, and `Start Your First Assessment` button.
- The CTA opens the wizard screen.
- Dashboard populated-state behavior remains unchanged.
- Setup checklist behavior is not regressed.
- No E2E regressions.
