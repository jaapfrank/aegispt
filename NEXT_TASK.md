# Active Task

## Title

AI Action Rationale Ledger: Measurable and Provable AI Decisions

## Promoted From

`codex/tasks/backlog-296-ai-action-rationale-ledger.json`

## Goal

To make the AI's behavior measurable and provable, every single tool dispatch must be backed by an immutable 'Rationale Ledger' entry. The AI must explicitly write: 'I observed X in the Context Document, therefore I am dispatching Tool Y with parameters Z'. This ledger is exposed to the operator and included in the final report to prove the pentest was methodological and not random.

## Scope

AI planning and assessment loop.

## Constraints

- Do not implement until this package is the single active task in NEXT_TASK.md.
- Focus strictly on the AI's planning logic and ledger generation. Do not build new testing tools in this task.
- Do not create runtime self-modification or uncontrolled plugin installation.

## Validation

- `python3 scripts/validate_backlog_tasks.py`
- `pytest api/tests/`

## Acceptance

- AI builds a Context Document before running active tools.
- AI generates a nested micro-plan upon finding a new endpoint/layer.
- Every tool execution has a corresponding, provable entry in the Rationale Ledger.
