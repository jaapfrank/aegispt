# Codex UI/Reporting M4 - Report Truth View Model Adapter

Date: 2026-06-02
Owner: Codex UI/reporting lane
Scope: React v2 Report Center presentation truth

## Goal

Move Report Center's canonical report truth calculations out of the screen
component and into a UI-facing view-model adapter. This keeps the W8
cross-surface consistency contract easier to preserve when Report Center UI is
edited later.

## Changes

- Added `ui-v2/src/viewModels/reportTruth.ts`.
- Moved Report Center truth model construction into `buildReportTruth`.
- Moved report count status labels, status tones, stage detail copy, included
  bullets, excluded bullets, evidence-status checks, customer-copy warning
  checks, severity chart data, and catalog count parsing into the adapter.
- Updated `ui-v2/src/components/screens/ReportCenter.tsx` to import the
  adapter and keep the screen focused on rendering and user actions.

## Product Truth Preserved

- Report Center still treats chain-aware findings from
  `getFindingsForRunContext(run)` as canonical.
- Catalog included counts are still compared against canonical findings before
  export.
- Customer-facing metadata still checks for internal benchmark/lab/fixture/smoke
  wording.
- W8's mismatch-sensitive fixture still proves Report Center and exported
  markdown use canonical truth instead of stale run-local summary data.

## Validation

- `cd ui-v2 && npx eslint src/components/screens/ReportCenter.tsx src/viewModels/reportTruth.ts`
- `cd ui-v2 && npx tsc -b --pretty false`
- `cd ui-v2 && npm run build`
- `cd ui-v2 && npx playwright test tests/react-v2-critical-paths.spec.ts --grep "Report Center|Canonical consistency"` (2 passed)
- `cd ui-v2 && npm test` (25 passed)
- `python3 scripts/validate_backlog_tasks.py`
- `git diff --check`

Note: an earlier concurrent `npm test` attempt was discarded after Vite returned
`ERR_CONNECTION_REFUSED` while a separate Playwright run was using the dev
server. The standalone rerun passed.

## Non-Overlap

No Claude score-lane files, `NEXT_TASK.md`, `TASK_QUEUE.md`, runtime runner
files, solver/scoring code, backend report code, or active XBEN validation
artifacts were changed for M4.
