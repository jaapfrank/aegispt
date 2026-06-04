# Codex UI/Reporting M6 - Management Report Story + Remediation Repair

Date: 2026-06-02

## Scope

Repaired the management report layer after operator review showed that the PDF
still read like a thin findings table instead of a management-ready assessment
story.

This stayed inside the Codex UI/reporting lane:

- `api/app/services/reports.py`
- `api/tests/test_reports.py`

No assessment runtime, runner, score-lane, `NEXT_TASK.md`, or `TASK_QUEUE.md`
files were changed.

## Behavior Proved

- English summary reports and Dutch management reports now include a
  management-readable risk picture chart.
- Management outputs now include explicit sections for:
  - why the situation matters
  - what an attacker could practically do
  - what Engineering and IT/Ops should do
  - how the test was built from scope, discovery, focused checks, evidence, and
    reportable findings
  - standards used, shown with `[PTES]`, `[WSTG]`, `[NIST]`, and `[ASVS]`
    badges
- The Dutch management PDF is no longer dependent on "see technical report"
  style placeholders for impact/action wording in the tested fixture.
- AI-assisted management draft payloads now expose the same deterministic
  `management_story` object with `attacker_story`, `remediation_tracks`, and
  `standards_badges`; technical draft variants still keep management-only facts
  out of their payload.
- Raw runner/tool/lab language remains suppressed from management-facing
  Markdown, HTML, and PDF output.

## Validation

- `.venv/bin/python -m py_compile api/app/services/reports.py api/app/services/report_pdf.py api/tests/test_reports.py`
- `.venv/bin/python -m pytest api/tests/test_reports.py::test_management_reports_rewrite_internal_runner_language -q`
- `.venv/bin/python -m pytest api/tests/test_reports.py::test_ai_report_draft_supports_chatgpt_oauth_provider api/tests/test_reports.py::test_ai_report_draft_separates_management_and_technical_contracts -q`
- `.venv/bin/python -m pytest api/tests/test_reports.py -q`
- `.venv/bin/ruff check api/app/services/reports.py api/app/services/report_pdf.py api/tests/test_reports.py`
- `python3 scripts/validate_backlog_tasks.py`
- `git diff --check`

## Residual Risk

- This is deterministic report rendering and draft-payload work. It does not
  make new exploitation claims, change finding persistence, or execute a live
  target assessment.
- Standard badges are rendered as report-native text/CSS badges, not external
  logo assets, so exports remain self-contained and deterministic.
