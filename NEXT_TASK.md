# Active Task

## Title

Hide Pack Forge 'Build Lane / Task Planner' Codex section from default operator-facing navigation

## Promoted From

`codex/tasks/backlog-169-pack-forge-codex-lane-operator-visibility.json`

## Goal

Hide developer-facing Codex build-lane panels from the default operator Pack Forge experience while keeping operator pack lifecycle controls visible and functional.

## Scope

Implement the active backlog package `codex/tasks/backlog-169-pack-forge-codex-lane-operator-visibility.json`.

Expected slice:

- find the Pack Forge Codex/build-lane panel render path in `ui/index.html`, `ui/assets/modules/packs.js`, or `ui/assets/app.js`
- hide Codex build-lane/task-planner panels by default for normal operators
- keep Adaptive Planning, Pack Summary, Registry, validation, approval, and deployment controls visible
- keep Codex panels accessible only when an explicit developer/build-lane mode setting is enabled
- avoid removing Codex backend functionality or changing pack lifecycle behavior

## Constraints

- Keep Prompt 1 and Prompt 2 intact.
- Do not bypass approval gates, pack registry, validation, deployment, or runtime binding.
- No runtime self-modification.
- Do not install uncontrolled plugins.
- Do not remove Codex functionality.
- Do not change Codex task generation backend behavior.
- Do not change pack validation, approval, deployment, or runtime-binding logic.
- Do not broadly redesign Pack Forge.

## Validation

- `python3 scripts/validate_backlog_tasks.py`
- `source .venv/bin/activate && python -m pytest api/tests/test_health.py -q`
- `git diff --check`
- Focused UI/E2E coverage proving default Pack Forge hides Codex panels and developer/build-lane mode exposes them
- Pack lifecycle regression coverage where relevant
- Browser/safe acceptance where relevant

## Acceptance

- Default Pack Forge view shows operator-facing Adaptive Planning, Pack Summary, and Registry/lifecycle panels.
- Codex task form, prepare button, suggestions, pack preview, context, and task result panels are hidden unless build-lane/developer mode is enabled.
- Pack validate, approve, and deploy controls remain visible and usable for operators.
- No regression in pack lifecycle tests.
