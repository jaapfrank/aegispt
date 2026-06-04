# Codex UI/Reporting M5 - Report Lifecycle Extraction

Date: 2026-06-03
Owner: Codex UI/reporting lane

## Scope

Continued M5 by extracting report lifecycle and availability helpers out of
`api/app/services/reports.py` into:

- `api/app/services/reporting/lifecycle.py`

This module now owns report-ready status sets, status-count aggregation,
`report_lifecycle_summary()`, and `report_availability_for_run()`. `reports.py`
keeps importing the same helper names so report catalog construction and router
imports remain compatible.

## Non-Goals

- No assessment runtime behavior changed.
- No scoring, worker, runner, or assessment-loop files were touched.
- No report availability labels, catalog payload shape, export paths, draft
  permissions, or lifecycle state semantics were intentionally changed.

## Proof

Commands run after the lifecycle extraction:

- `./.venv/bin/ruff check api/app/services/reports.py api/app/services/reporting`
- `./.venv/bin/pytest api/tests/test_reports.py -q`

The same report test file covers report catalogs, export readiness, PDF output,
management reports, compliance variants, AI draft payloads, evidence gaps, and
attack narrative paths.

## Result

Ruff passed and the report test file passed. The extraction preserved report
catalog/lifecycle behavior while moving another concern out of the legacy
`reports.py` module.

## Lane Safety

No Claude score-lane files, `NEXT_TASK.md`, `TASK_QUEUE.md`,
assessment-loop/runtime files, worker runner files, scoring code, or active XBEN
validation artifacts were changed.
