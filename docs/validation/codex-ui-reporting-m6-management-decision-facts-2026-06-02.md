# Codex UI/Reporting M6 - Management Decision Facts

Date: 2026-06-02
Owner: Codex
Lane: Codex UI/reporting worklist

## Scope

Implemented a narrow M6 step: deterministic management-report decision facts
before optional LLM phrasing. This keeps management Markdown, management HTML,
and PDF output grounded in the same evidence-backed facts.

Touched files:

- `api/app/services/reports.py`
- `api/tests/test_reports.py`
- state/worklist documentation

No Claude score-lane files, `NEXT_TASK.md`, `TASK_QUEUE.md`, assessment-loop
runtime files, worker runner files, scoring code, or active XBEN validation
artifacts were touched.

## Behavior

- Added `_management_decision_facts(...)` as a structured report-fact helper for
  management audiences.
- The helper derives:
  - management verdict
  - management decision
  - first actions
  - evidence basis
  - tested scope summary
  - explicit not-claimed / not-certified caveats
  - methodology references
  - task coverage counts
- Dutch management Markdown and Dutch management PDF now include
  `Besluit in een oogopslag`.
- English management summary Markdown/HTML/PDF now includes
  `Management Decision`.
- ChatGPT-backed Dutch management drafting now receives the structured decision
  facts as fixed input, so the model phrases known facts rather than inventing
  the decision.
- The existing management-report raw-label protections remain in place: raw
  flags, benchmark IDs, runner/tool labels, FastAPI/OpenAPI implementation
  labels, and HTTP baseline titles stay out of the management-facing title
  layer.

## Proof

Validated with:

- `python3 -m compileall -q api/app/services/reports.py api/app/services/report_pdf.py api/tests/test_reports.py`
- `. .venv/bin/activate && ruff check api/app/services/reports.py api/app/services/report_pdf.py api/tests/test_reports.py`
- `. .venv/bin/activate && python -m pytest api/tests/test_reports.py -k management_reports_rewrite_internal_runner_language -vv` (1 passed, 23 deselected)
- `. .venv/bin/activate && python -m pytest api/tests/test_reports.py` (24 passed)
- `python3 scripts/validate_backlog_tasks.py`
- `git diff --check`

The focused test now verifies that management Markdown, summary HTML, summary
PDF, and Dutch management PDF include the management decision/evidence basis
while still excluding raw internal runner labels.
