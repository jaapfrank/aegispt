# Active Task

## Title

AI Recursive Surface Mapping: Deep-dive sub-planning

## Promoted From

`codex/tasks/backlog-295-ai-recursive-surface-mapping.json`

## Goal

When a tool discovers a new layer (e.g., dirsearch finds /api/v2/, or a crawler finds a GraphQL endpoint), the AI must pause and recurse. It creates a 'Sub-Context' for this new layer and generates a new, specific micro-plan just for that endpoint. This ensures that going a layer deeper triggers a fresh analysis phase rather than just throwing generic payloads at it.

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
