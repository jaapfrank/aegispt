# Codex UI/Reporting W6B - Management PDF Plain-Language Repair

Date: 2026-06-02
Owner: Codex UI/reporting lane

## Scope

This repair follows operator feedback that the management PDF and Dutch
management PDF still read like technical output: raw `Flag captured` labels,
FastAPI/OpenAPI titles, generic "see technical report" impact text, and no
clear explanation of which testing standards were used.

Touched files:

- `api/app/services/reports.py`
- `api/tests/test_reports.py`
- `docs/strategy/codex-ui-reporting-worklist-2026-06-01.md`
- `CURRENT_STATE.md`
- `DECISIONS.md`
- `DONE_LOG.md`

## Change

- Added management-safe business categories for:
  - confirmed attack paths / flag-capture style proof
  - public API documentation exposure
  - informational connectivity baseline findings
- Expanded technical-title filtering so FastAPI, OpenAPI, Swagger, auto-docs,
  HTTP status, and baseline labels do not become primary management copy.
- Reworked Dutch management Markdown/HTML/PDF copy to explain findings in
  plain business language:
  - what happened
  - why it matters
  - what to do first
  - what is informational only
- Added explicit methodology sections to both Dutch management output and the
  English management summary:
  - PTES
  - OWASP WSTG versioned reference
  - NIST SP 800-115
  - optional OWASP ASVS where findings are mapped
- Clarified that the management report is evidence-first assessment output, not
  a certification.
- Cleaned Dutch management target/date presentation so output no longer shows
  `Urls:` prefixes or English month names.

## Regression Proof

`test_management_reports_rewrite_internal_runner_language` now creates a run
with raw titles matching the operator screenshot:

- `Flag captured (interactive-exploit): ...`
- `Vulnerability: FastAPI Auto-docs Exposure`
- `Vulnerability: FastAPI OpenAPI Schema Exposure`
- `AegisPT HTTP Status 200 Baseline`

The test verifies Markdown, summary HTML, summary PDF, and Dutch management PDF:

- raw runner/benchmark/flag/tool titles do not appear
- FastAPI/OpenAPI/status baseline labels do not appear as primary management
  copy
- safe business categories do appear
- PTES, OWASP WSTG, and NIST SP 800-115 are present
- Dutch output includes `Welke standaarden zijn gebruikt?`

## Validation

Commands run:

```bash
python3 -m compileall -q api/app/services/reports.py api/app/services/report_pdf.py api/tests/test_reports.py
. .venv/bin/activate && ruff check api/app/services/reports.py api/app/services/report_pdf.py api/tests/test_reports.py
. .venv/bin/activate && python -m pytest api/tests/test_reports.py -k management_reports_rewrite_internal_runner_language -vv
. .venv/bin/activate && python -m pytest api/tests/test_reports.py
```

Observed results:

- compileall: passed
- ruff touched report files: passed
- focused management/PDF regression: 1 passed, 22 deselected
- full report suite: 23 passed

## Non-Collision

No Claude score-lane files were edited for this repair. `NEXT_TASK.md`,
`TASK_QUEUE.md`, `api/app/services/finding_verifier.py`,
`api/tests/test_sqli_reprover.py`, scoring/orchestration code, runner files,
and active XBEN validation artifacts were left untouched.
