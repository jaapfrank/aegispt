# Active Task

## Title

Picker Structured Outputs via output_config.format JSON Schema (Phase 3 start)

## Goal

Replace the picker's text-then-JSON-parse path with Anthropic structured outputs (`output_config.format` with a `json_schema`) so Claude is forced to produce a syntactically valid JSON action that matches the `pick / level_up / stop / exec_plan` discriminator. Eliminates the entire class of JSON parse failures observed on 2026-05-15 (unescaped quote in `reasoning` at char 2533, etc.).

## Scope

- Modify `api/app/services/assessment_loop.py:_claude_select_next_action` to add `output_config={"format": {"type": "json_schema", "schema": ...}}` on the picker call.
- Define the schema for the 4 action shapes (pick, level_up, stop, exec_plan).
- For the `exec_plan.plan` field — which has freeform inner objects (params, data, capture, expect.body_contains) incompatible with Anthropic strict mode's `additionalProperties: false` — use a JSON-stringified pattern: declare `plan` as a string in the outer schema, add a 1-2 sentence directive to the system prompt instructing Claude to serialize the plan, and decode it client-side with one `json.loads` step.

## Constraints

- Schema + plumbing only. Do NOT change the system prompt body. Do NOT alter the hop loop, tool definitions, or evidence consumption.
- Anthropic strict mode requires `additionalProperties: false` on every object. The exec_plan.plan stringification is the only acceptable workaround for inner freeform objects.
- Tool use (memory + http_fetch) must continue to work — structured outputs constrains the FINAL text output, not tool_use intermediate hops.
- Must NOT touch: `_AI_PICKER_SYSTEM_PROMPT` body lines 1-200 (only the brief plan-stringification note is appended), `workers/runners/`, `workers/orchestration/`, `api/app/services/memory_backend.py`, `api/app/services/http_fetch_backend.py`.

## Source Package

`codex/tasks/backlog-380-picker-structured-outputs-schema.json`

## Reference

- `api/app/services/assessment_loop.py` (`_AI_PICKER_SYSTEM_PROMPT`, `_claude_select_next_action`, `_tolerant_json_fix`)
- `docs/AGENT_SYSTEM_MAP.md` section 2 (Known issues — JSON parse failures)
- Anthropic structured outputs docs (output_config.format json_schema strict mode)
- `docs/checkpoints/2026-mythos-phase2-review.md` (Phase 2 close-out, GO decision for Phase 3)

## Validation

- `python3 scripts/validate_backlog_tasks.py`
- `.venv/bin/pytest api/tests/test_assessment_loop_structured_outputs.py api/tests/test_assessment_loop.py`
- `python3 -m compileall -q api`
- `.venv/bin/ruff check api/app/services/assessment_loop.py`
- `git diff --check`
- Acceptance: 20 consecutive live picker advances on Gruyere succeed with no JSON parse failures; exec_plan with nested plan body parses end-to-end; prompt cache hit ratio stays within 5% of pre-change baseline.
