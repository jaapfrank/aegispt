# Active Task

## Title

CSS design system tokens: standardise spacing, typography, and colour to one consistent unit system

## Promoted From

`codex/tasks/backlog-199-css-design-system-tokens.json`

## Goal

Standardise the main CSS spacing/token system in one focused pass so the operator console has one clean `:root` variable source, consistent 4px-grid spacing units, reusable spacing tokens, and a tablet-friendly tile-grid breakpoint.

## Scope

Implement the active backlog package `codex/tasks/backlog-199-css-design-system-tokens.json`.

Expected slice:

- audit `ui/assets/styles.css` for the spacing/token inconsistencies described in the task package
- remove duplicate CSS variable definitions by keeping one clean `:root` block near the top of the file
- define `--spacing-xs` through `--spacing-xl`
- use the spacing tokens for at least 20 repeated spacing values
- add a 2-column tile-grid fallback at the 900px tablet breakpoint

## Constraints

- Do not implement until this file is the single active task.
- Standardise units and remove duplication only.
- Do not redesign components.
- Do not add new CSS classes.
- Do not change colours or fonts.
- Do not change JavaScript.
- Do not bypass pack registry, validation, approval, deployment, runtime binding, scope, ROE, credentials, or kill switch.
- No runtime self-modification.
- No uncontrolled plugin installation.

## Validation

- `python3 scripts/validate_backlog_tasks.py`
- `source .venv/bin/activate && python -m pytest api/tests/test_health.py -q`
- `git diff --check`

## Acceptance

- `ui/assets/styles.css` has no duplicate `:root` block.
- `--spacing-xs` through `--spacing-xl` tokens are defined.
- spacing updates stay on the 4px grid for the main layout sections covered by the slice.
- tile grid has a 2-column fallback at the 900px breakpoint.
- existing E2E coverage does not regress.
