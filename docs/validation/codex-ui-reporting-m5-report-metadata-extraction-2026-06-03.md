# Codex UI/Reporting M5 Report Metadata Extraction Validation - 2026-06-03

## Scope

Codex continued M5 by extracting report variant metadata out of the legacy
`api/app/services/reports.py` module into the report-only helper package.

Changed report files:

- `api/app/services/reporting/metadata.py`
- `api/app/services/reports.py`

The new metadata helper owns:

- primary report variant ordering
- compliance framework allowlist and default framework
- report variant labels and descriptions
- report variant alias normalization
- compliance framework selection for report requests

`reports.py` still imports and re-exports the same public names so existing
callers such as `api/app/services/report_pdf.py` continue to resolve report
labels and normalization through the existing compatibility entry point.

## Validation

Commands run:

- `./.venv/bin/ruff check --fix api/app/services/reports.py api/app/services/reporting`
- `./.venv/bin/ruff check api/app/services/reports.py api/app/services/reporting`
- `./.venv/bin/pytest api/tests/test_reports.py -q`

Results:

- ruff fixed import ordering only, then passed cleanly
- `api/tests/test_reports.py` passed with exit code 0

## Boundary Check

This extraction stayed inside Codex's UI/reporting lane.

No Claude score-lane files, `NEXT_TASK.md`, `TASK_QUEUE.md`,
assessment-loop/runtime files, worker runner files, scoring code, or active
XBEN validation artifacts were changed.
