# Active Task

## Title

Picker prompt addendum: instruct Claude to chain-reason over the RECENT_CAPTURES projection (#334 follow-up, backfill 2 of 6)

## Goal

Task \#334 added a RECENT_CAPTURES section to the graph projection showing the picker the last 5 captured_value entities (tokens, cookies, hostnames, etc.) with origin step + redacted preview. The data is now in the prompt but the system-prompt body never tells Claude HOW to use it for cross-target chain reasoning. Without an explicit instruction, Claude reads the section as background context rather than actionable lineage. This task adds a small instruction block — appended OUTSIDE the protected lines 1-200 of `_AI_PICKER_SYSTEM_PROMPT` — that explicitly directs the picker to reuse a previously-captured value when its kind matches a step's needed parameter (e.g., captured token of kind=token becomes Authorization header in the next task; captured hostname becomes the target_id of a new pivot task).

## Scope

- Append a single 10-15 line "CHAIN REASONING ON RECENT_CAPTURES" addendum to `_AI_PICKER_SYSTEM_PROMPT` BELOW line 300 (outside the must_not_touch range).
- Phrase it as guidance, not as a hard rule: "When you see a RECENT_CAPTURES entry whose kind matches a parameter needed by a candidate step, prefer that value as the parameter source via interpolation rather than re-acquiring it."
- Add 2 unit tests:
  - (a) the new addendum is present in the live prompt
  - (b) the addendum sits outside lines 1-200

## Constraints

- Append-only text addition outside lines 1-200. Do NOT modify the existing prompt body, do NOT add new tools, do NOT change the schema or `output_config` (#330 contract), do NOT change the RECENT_CAPTURES section format itself.
- Per `feedback_no_prescriptive_recipes` memory: instruction must be GENERIC ("when a captured value-kind matches a needed parameter, prefer it"); NO Gruyere/juice-shop/testfire-specific patterns or recipes. Emergent discovery only.
- Must NOT touch: `_AI_PICKER_SYSTEM_PROMPT` body lines 1-200, `_PICKER_OUTPUT_SCHEMA` (#330), RECENT_CAPTURES section format in `assessment_graph.py` (#334 contract), evidence_ingest captured_value redaction policy (#334 contract), `workers/runners/`, `workers/orchestration/`.

## Source Package

`codex/tasks/backlog-393-picker-prompt-recent-captures-chain-reasoning.json`

## Reference

- `api/app/services/assessment_loop.py` — `_AI_PICKER_SYSTEM_PROMPT` constant (the body to append below, NOT inside lines 1-200)
- `api/app/services/assessment_graph.py` — `project_graph_for_picker` RECENT_CAPTURES section format (#334)
- `api/tests/test_cross_target_provenance.py` — where the new tests should sit
- DONE_LOG entry for #334 (Cross-Target Provenance) for the data layer this prompt-side instruction sits on top of

## Validation

- `python3 scripts/validate_backlog_tasks.py`
- `.venv/bin/pytest api/tests/test_assessment_loop_structured_outputs.py api/tests/test_cross_target_provenance.py`
- `python3 -m compileall -q api`
- `.venv/bin/ruff check api/app/services/assessment_loop.py`
- `git diff --check`
