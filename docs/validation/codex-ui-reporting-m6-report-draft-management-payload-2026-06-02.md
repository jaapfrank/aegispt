# Codex UI/Reporting M6 - Report Draft Management Payload

Date: 2026-06-02
Owner: Codex
Lane: Codex UI/reporting worklist

## Scope

Continued M6 by carrying deterministic management decision facts into the
AI-assisted report draft structured payload. This keeps the report-draft API,
deterministic draft fallback, and ChatGPT OAuth draft input aligned with the
same evidence-backed management decision model used by management reports.

Touched files:

- `api/app/schemas/report_center.py`
- `api/app/services/reports.py`
- `api/tests/test_reports.py`
- state/worklist documentation

No Claude score-lane files, `NEXT_TASK.md`, `TASK_QUEUE.md`,
assessment-loop/runtime files, worker runner files, scoring code, or active
XBEN validation artifacts were touched.

## Behavior

- Added `management_decision` to `RunReportDraftRead`.
- Management draft variants now include `management_decision` in:
  - `structured_payload`
  - top-level API response
  - `draft_contract.allowed_input_facts`
  - `source_data_categories` as `report_draft.management_decision`
- Technical draft variants continue to return an empty `management_decision`
  and do not include it in allowed input facts.
- ChatGPT OAuth report-draft instructions now explicitly state that
  `management_decision` is the canonical verdict/decision/action source for
  management variants.
- Deterministic management draft fallback now uses the same management decision
  facts in its executive-summary section.

## Proof

Validated with:

- `python3 -m compileall -q api/app/services/reports.py api/app/schemas/report_center.py api/tests/test_reports.py`
- `. .venv/bin/activate && ruff check api/app/services/reports.py api/app/schemas/report_center.py api/tests/test_reports.py`
- `. .venv/bin/activate && python -m pytest api/tests/test_reports.py -k "ai_report_draft" -vv` (5 passed, 19 deselected)
- `. .venv/bin/activate && python -m pytest api/tests/test_reports.py` (24 passed)
- `python3 scripts/validate_backlog_tasks.py`
- `git diff --check`

The ChatGPT OAuth test uses a fake backend and inspects the exact JSON payload
that would be sent to ChatGPT. It now proves that technical drafts receive no
management decision object, while management drafts receive the structured
decision facts and may use them only as fixed input facts.
