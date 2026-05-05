# Active Task

## Title

AI cross-task working memory: accumulate analysis context across all tasks in an engagement for compound reasoning

## Promoted From

`codex/tasks/backlog-233-ai-cross-task-working-memory.json`

## Goal

Implement engagement-level AI working memory for post-task analysis. The AI analysis context should include prior task analyses, approved proposal outcomes, engagement finding summaries, and a bounded rolling attack narrative so later task analysis can reason from earlier task results.

## Scope

Implement the active backlog package `codex/tasks/backlog-233-ai-cross-task-working-memory.json`.

Expected slice:

- extend `_build_analysis_context()` with an `engagement_context` section
- include the last five `AgentReasoning` summaries for the current engagement
- include approved proposals and their available outcomes
- include engagement-level finding counts and high-priority finding summaries
- generate or maintain a short bounded attack narrative for the engagement
- cap added context to prevent token-limit growth
- add tests proving later task analysis can see prior task results

## Constraints

- Do not implement until this file is the single active task.
- Extend `_build_analysis_context()` only for this slice.
- Do not change proposal generation logic.
- Do not change proposal approval gates.
- Do not change AI provider connections.
- Keep total added context bounded.
- Do not bypass pack registry, validation, approval, deployment, runtime binding, scope, ROE, credentials, or kill switch.
- No runtime self-modification.
- No uncontrolled plugin installation.

## Validation

- `python3 scripts/validate_backlog_tasks.py`
- `source .venv/bin/activate && python -m pytest api/tests/ -q`
- `git diff --check`

## Acceptance

- `_build_analysis_context()` includes prior task analyses for the current engagement.
- Context includes approved proposals and their recorded outcomes where available.
- Context includes a bounded attack narrative.
- Context size is capped to prevent unbounded token growth.
- AI proposals after the change demonstrate awareness of prior task results in tests with three or more completed tasks.
- No AI agent test regressions.
