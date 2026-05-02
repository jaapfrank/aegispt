# Active Task

## Title

Shorten or remove topbar/hero subtitle: 'Guided, evidence-first assessment...' is too verbose for enterprise use

## Promoted From

`codex/tasks/backlog-173-topbar-subtitle-too-verbose.json`

## Goal

Remove or sharply shorten the long application shell subtitle so daily enterprise operators do not lose vertical space to repeated marketing copy.

## Scope

Implement the active backlog package `codex/tasks/backlog-173-topbar-subtitle-too-verbose.json`.

Expected slice:

- audit `ui/index.html` and `ui/assets/styles.css`
- remove the long subtitle `Guided, evidence-first assessment operations across wizard-driven setup, live mission control, adaptive pack governance, evidence replay, and report delivery.`
- preferred outcome is to remove the subtitle entirely because screen headings already provide context
- if a replacement tagline is used, it must be dashboard-only and 8 words or fewer

## Constraints

- Keep Prompt 1 and Prompt 2 intact.
- Do not bypass approval gates, pack registry, validation, deployment, or runtime binding.
- No runtime self-modification.
- Do not install uncontrolled plugins.
- Only change the subtitle/tagline text or remove the subtitle element.
- Do not redesign the topbar layout or hero area.
- Do not change screen-level headings, eyebrows, navigation structure, backend APIs, or runtime behavior.

## Validation

- `python3 scripts/validate_backlog_tasks.py`
- `source .venv/bin/activate && python -m pytest api/tests/test_health.py -q`
- `git diff --check`
- Focused UI/E2E coverage proving the long subtitle is absent and shell height remains compact
- Browser/safe acceptance where relevant

## Acceptance

- The long subtitle is absent from all rendered screens.
- If any tagline remains, it is 8 words or fewer and dashboard-only.
- Screen-level headings and descriptions still provide contextual screen guidance.
- The application shell/topbar remains compact.
- No E2E regressions.
