# Codex UI/Reporting M4 Report Preview Metadata Validation - 2026-06-04

## Scope

Completed the remaining M4 Report Center preview/export metadata adapter slice.
This stayed inside the Codex-owned UI/reporting lane and did not edit
`NEXT_TASK.md`, `TASK_QUEUE.md`, or Claude-owned score-lane/runtime files.

## Behavior Proven

- `buildReportPreviewMetadata` derives selected-report presentation metadata:
  availability label/tone, preview loaded state, preview line/section counts,
  Markdown finding-count claim, export readiness, available formats, primary
  filename, content hash summary, and readiness chart data.
- Report Center package, readiness chart, preview, export-action, and hash
  panels consume the shared adapter instead of recomputing those facts locally.
- The canonical Report Center flow shows the adapter-backed export format,
  default filename, short content hash, preview claim state before preview, and
  loaded preview metadata after Markdown preview generation.
- The M7 contradictory-score fixture still blocks customer-ready wording before
  export review.

## Validation

- `cd ui-v2 && npx eslint src/components/screens/ReportCenter.tsx src/viewModels/reportPreviewMetadata.ts tests/react-v2-critical-paths.spec.ts`
- `cd ui-v2 && npx tsc -b --pretty false`
- `cd ui-v2 && npx playwright test tests/react-v2-critical-paths.spec.ts -g "M4 report preview metadata|Report Center shows canonical report truth|Report Center flags the named M7 contradictory score fixture"` (`3` passed after repairing a misplaced test label)
- `cd ui-v2 && npm test` (`45` passed, including i18n key parity)
- `cd ui-v2 && npm run build` (passed; existing Vite chunk-size warning remains)
- `python3 scripts/validate_backlog_tasks.py`
- `git diff --check` (no whitespace errors; git reported existing line-ending
  normalization warnings)
- `git diff --name-only -- NEXT_TASK.md TASK_QUEUE.md api/app/services/assessment_loop.py api/app/services/assessment_loop_internals/guards.py api/app/services/m2_verdict_gate.py workers/orchestration/tasks.py workers/runners/interactive_exploit` (no output)

## Notes

Preview claim counts remain advisory UI review metadata. Canonical report truth
still comes from report catalog data, canonical findings, and the
cross-surface consistency view-model.
