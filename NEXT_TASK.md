# Active Task

## Title

Advanced Configuration drawer: replace developer language with operator-appropriate copy

## Promoted From

`codex/tasks/backlog-204-advanced-config-drawer-operator-language.json`

## Goal

Make the wizard Advanced Configuration drawer read like an operator-facing assessment control, not an implementation/debug surface, while preserving drawer functionality, tabs, fields, and backend behavior.

## Scope

Implement the active backlog package `codex/tasks/backlog-204-advanced-config-drawer-operator-language.json`.

Expected slice:

- remove `Deterministic Run Controls` from the advanced drawer header
- rewrite the drawer description to: `Fine-tune modules, credentials, profiles, and safety limits for this assessment.`
- make the Type tab clearly communicate that tile selection already sets the assessment type and changes there are overrides
- rename non-functional `What changed?` language to `Why?` or remove it where appropriate
- in the AI drawer section, show the full ChatGPT connection block only when ChatGPT is not connected; when connected, show a minimal connected badge instead

## Constraints

- Do not implement until this file is the single active task.
- Only change string copy and conditional visibility of the ChatGPT block.
- Do not change drawer tab logic.
- Do not change field rendering or field behavior.
- Do not change backend APIs.
- Do not bypass pack registry, validation, approval, deployment, runtime binding, scope, ROE, credentials, or kill switch.
- No runtime self-modification.
- No uncontrolled plugin installation.

## Validation

- `python3 scripts/validate_backlog_tasks.py`
- `source .venv/bin/activate && python -m pytest api/tests/test_health.py -q`
- `git diff --check`

## Acceptance

- `Deterministic Run Controls` does not appear in the advanced drawer.
- The drawer description is operator-appropriate.
- The Type tab includes a note that tile selection already sets this and changes are overrides.
- The ChatGPT block is hidden or reduced to a minimal badge when already connected.
- Wizard E2E tests pass.
