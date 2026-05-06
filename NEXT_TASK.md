# Active Task

## Title

Wizard multi-tile target question mismatch: mixed LAN+Web asks LAN-biased question and labels URL input as CIDR range

## Promoted From

`codex/tasks/backlog-198-wizard-multi-tile-target-question-mismatch.json`

## Goal

Fix the wizard target question and interpretation for multi-tile contexts so mixed LAN + Web selections use neutral target language and classify URL input as URL/web target context instead of CIDR/LAN context.

## Scope

Implement the active backlog package `codex/tasks/backlog-198-wizard-multi-tile-target-question-mismatch.json`.

Expected slice:

- keep single-tile target questions unchanged
- use generic multi-tile target prompt copy
- make URL input for mixed LAN + Web show URL/web interpretation, not CIDR interpretation
- show both URL and CIDR quick-fill examples for multi-tile target entry

## Constraints

- Do not implement until this file is the single active task.
- Only fix the question label, interpretation text, and quick-fill chips for multi-tile context.
- Do not change single-tile target question rendering.
- Do not change backend run profile logic.
- Do not change target interpretation for single-tile contexts.
- Do not bypass pack registry, validation, approval, deployment, runtime binding, scope, ROE, credentials, or kill switch.
- No runtime self-modification.
- No uncontrolled plugin installation.

## Validation

- `python3 scripts/validate_backlog_tasks.py`
- `source .venv/bin/activate && python -m pytest api/tests/test_health.py -q`
- `git diff --check`

## Acceptance

- Multi-tile LAN + Web target step shows generic target question copy.
- URL input in mixed tile context renders URL-appropriate interpretation.
- Quick-fill chips for multi-tile target entry include URL and CIDR examples.
- Single-tile target questions remain unchanged.
- Wizard E2E coverage does not regress.
