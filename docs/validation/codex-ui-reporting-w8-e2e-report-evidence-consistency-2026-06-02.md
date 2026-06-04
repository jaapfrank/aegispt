# Codex UI/Reporting W8 - End-to-End Report/Evidence Consistency

Date: 2026-06-02
Owner: Codex UI/reporting lane
Scope: React v2 consistency fixture plus backend report catalog/export checks

## Goal

Prove that one named consistency fixture tells the same canonical finding story
across Mission Control, Findings Theater, Evidence Replay, Report Center, report
preview, and exported report endpoints.

## Fixture

The React fixture intentionally keeps a stale run-local summary:

- selected run-local summary: `1 total / 1 high+`
- chain-aware canonical findings: `2 total / 2 high+`
- findings: `Critical stored XSS in profile preview` and
  `High-risk missing HSTS header`
- status count: `open 2`
- evidence refs: `evidence://finding-critical` and `evidence://finding-high`

This means the W8 test fails if any customer/operator surface uses the stale
run-local summary instead of the canonical chain-aware findings.

## Changes

- Added a Playwright test:
  `Canonical consistency fixture stays aligned across mission evidence findings and reports`.
- Made the React report fixture catalog and markdown export derive counts,
  severity totals, status totals, and evidence refs from the active fixture
  findings instead of static report payloads.
- Added backend test:
  `test_report_catalog_and_exports_keep_canonical_finding_truth`.
- Backend assertions verify `/reports`, management markdown, technical
  markdown, and evidence markdown all preserve the same two-finding canonical
  truth.

## Proof Points

- Mission Control snapshot shows `2 findings need review`, `3/4` checked, and
  `2 reportable`.
- Mission Control Technical still exposes the mismatch as diagnostic truth:
  canonical `2 persisted / 2 high+` and run-local `1 total / 1 high+`.
- Findings Theater renders both canonical finding rows.
- Evidence Replay states `2 saved findings` and links the replay conclusion
  state back to Findings and Reports.
- Report Center shows `2 total`, `2 included of 2 canonical findings`, and
  `Count check: matches canonical.`
- Markdown preview/export contains `Canonical Findings: 2`,
  `High/Critical: 2`, `Finding Status: open 2`, both finding titles, and both
  evidence refs.
- Backend report catalog returns `included_findings.count == 2`,
  `critical == 1`, `high == 1`, `open == 2`, and `linked_findings == 2`.
- Backend management/technical/evidence exports preserve the same count and
  evidence-backed finding story in their appropriate layers.

## Validation

- `python3 -m compileall -q api/tests/test_reports.py api/app/services/reports.py api/app/schemas/report_center.py`
- `. .venv/bin/activate && ruff check api/tests/test_reports.py api/app/services/reports.py api/app/schemas/report_center.py`
- `cd ui-v2 && npx eslint tests/react-v2-critical-paths.spec.ts`
- `cd ui-v2 && npm run build`
- `cd ui-v2 && npx playwright test tests/react-v2-critical-paths.spec.ts --grep "Canonical consistency"` (1 passed)
- `. .venv/bin/activate && python -m pytest api/tests/test_reports.py -k report_catalog_and_exports_keep_canonical_finding_truth -vv` (1 passed, 23 deselected)
- `cd ui-v2 && npx playwright test tests/react-v2-critical-paths.spec.ts` (22 passed)
- `cd ui-v2 && npm test` (25 passed)
- `. .venv/bin/activate && python -m pytest api/tests/test_reports.py` (24 passed)
- `python3 scripts/validate_backlog_tasks.py`
- `git diff --check`

## Non-Overlap

No Claude score-lane files, `NEXT_TASK.md`, `TASK_QUEUE.md`, runtime runner
files, solver/scoring code, or active XBEN validation artifacts were changed for
W8.
