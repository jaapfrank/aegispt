# Active Task

## Title

AI Contextual Profiling Engine: Analyze before acting

## Promoted From

`codex/tasks/backlog-294-ai-contextual-profiling-engine.json`

## Goal

Ensure the system NEVER blindly fires 100 tools. Implement a phase 0 'Contextual Profiling' step where the AI performs light, non-intrusive recon (fetching headers, robots.txt, sitemaps, JS source maps). The AI ingests this and builds a 'Target Context Document' that strictly defines the technologies present and dictates exactly which specific tools are relevant.

## Scope

AI planning and assessment loop.

## Constraints

- Do not implement until this file is the single active task.
- Focus strictly on the AI's planning logic and ledger generation. Do not build new testing tools in this task.
- Do not create runtime self-modification or uncontrolled plugin installation.

## Validation

- `python3 scripts/validate_backlog_tasks.py`
- `pytest api/tests/`

## Acceptance

- AI builds a Context Document before running active tools.
- AI generates a nested micro-plan upon finding a new endpoint/layer.
- Every tool execution has a corresponding, provable entry in the Rationale Ledger.
