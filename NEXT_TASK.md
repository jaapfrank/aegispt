# Active Task

## Title

Fix topbar stats chips: label ambiguity and redundant subtitle labels

## Promoted From

`codex/tasks/backlog-175-topbar-stats-chips-label-clarity.json`

## Goal

Simplify the topbar stats chips so each chip reads as one clear count and one noun instead of concatenated labels such as `ENGAGEMENTS · DOSSIERS`, `RUNS · MISSIONS`, or `OPEN ITEMS · BASELINE`.

## Scope

Implement the active backlog package `codex/tasks/backlog-175-topbar-stats-chips-label-clarity.json`.

Expected slice:

- find the topbar stats chip rendering in `ui/assets/app.js`, `ui/assets/modules/runtime.js`, or the current equivalent UI module
- simplify chip labels to the `N Noun` pattern, such as `4 Engagements`, `4 Runs`, `5 Findings`, `4 Critical`, `5 Open`
- remove redundant mid-dot secondary descriptor words
- remove `BASELINE` unless a real baseline comparison state is active and explicitly represented as a separate badge
- verify chip readability stays at least 11px on the dark topbar background

## Constraints

- Keep Prompt 1 and Prompt 2 intact.
- Do not bypass approval gates, pack registry, validation, deployment, or runtime binding.
- No runtime self-modification.
- Do not install uncontrolled plugins.
- Only update topbar stats chip label strings/rendering and minimal scoped styling if required for readability.
- Do not change engagement/run/finding data fetching.
- Do not change backend APIs, topbar layout structure, or chip navigation behavior.

## Validation

- `python3 scripts/validate_backlog_tasks.py`
- `source .venv/bin/activate && python -m pytest api/tests/test_health.py -q`
- `git diff --check`
- Focused UI/E2E coverage proving simplified chip labels and absence of redundant mid-dot descriptors
- Browser/safe acceptance where relevant

## Acceptance

- Each topbar chip follows the `N Noun` pattern.
- No chip has a mid-dot separator with a redundant secondary descriptor.
- `BASELINE` is absent unless a real baseline comparison state is active as a distinct badge.
- Chips are readable at 11px minimum font size on the dark topbar background.
- No E2E regressions.
