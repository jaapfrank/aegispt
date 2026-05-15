# Active Task

## Title

AI Picker Consumes Normalized Evidence Graph for Decision Context

## Goal

Replace the picker's flat findings + tested_keys + task_outcomes context with a compact projection of the normalized evidence graph so the AI sees first-class entities and relationships when choosing the next action, enabling cross-runner pivoting and cross-target chains.

## Scope

- Modify `api/app/services/assessment_loop.py` `_claude_select_next_action` user_content construction to project the normalized graph into a token-efficient representation.
- Add a graph-summarizer service that emits the projection.
- Keep existing fallback for runs without graph data.

## Constraints

- Picker context projection only. Do NOT change the system prompt structure, exec_plan grammar, or memory tool behavior.
- Token budget: projection must stay under 4 KB on typical runs to preserve prompt caching benefit. Larger graphs should be summarized, not dumped verbatim.

## Source Package

`codex/tasks/backlog-373-picker-reads-evidence-graph.json`

## Reference

`docs/evidence_graph_adoption_plan.md` — Section 6.2 sketches the project_graph_for_picker design

## Validation

- `python3 scripts/validate_backlog_tasks.py`
- `.venv/bin/pytest api/tests/test_assessment_loop_graph_projection.py api/tests/test_assessment_loop.py`
- `python3 -m compileall -q api`
- `.venv/bin/ruff check api/app/services/assessment_loop.py api/app/services/assessment_graph.py`
- `git diff --check`
