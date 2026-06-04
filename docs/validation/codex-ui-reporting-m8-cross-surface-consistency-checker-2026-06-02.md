# Codex UI/Reporting M8 - Cross-Surface Consistency Checker

Date: 2026-06-02
Owner: Codex
Lane: UI/reporting, non-overlap with Claude score-lane

## Scope

Implemented the M8 cross-surface consistency helper for Report Center so the UI
can compare canonical finding truth against the run-local summary, report
catalog counts, generated markdown preview claims, and evidence-link
availability.

Touched files:

- `ui-v2/src/viewModels/crossSurfaceConsistency.ts`
- `ui-v2/src/components/screens/ReportCenter.tsx`
- `ui-v2/tests/react-v2-critical-paths.spec.ts`
- `CURRENT_STATE.md`
- `DONE_LOG.md`
- `DECISIONS.md`
- `docs/strategy/codex-ui-reporting-worklist-2026-06-01.md`

No score-lane runtime, solver, worker, `NEXT_TASK.md`, `TASK_QUEUE.md`, or
active XBEN validation files were touched.

## Behavior Proven

- Added a pure `buildCrossSurfaceConsistency(...)` view-model helper that
  compares:
  - run-local finding summary count
  - canonical findings loaded from the selected run/chain context
  - selected report and full catalog included-finding counts
  - markdown preview finding claims when a preview is generated
  - evidence-linked finding availability
- Report Center now renders a compact `Truth consistency` panel with canonical,
  run-local, catalog, evidence, and preview status.
- The checker treats stale run-local summaries as a visible review caveat while
  keeping customer/report truth anchored to canonical findings.
- The existing canonical consistency fixture now proves a deliberate stale
  run-local summary (`1`) remains visible as a caveat while report surfaces,
  findings, evidence, and preview stay on the canonical two-finding truth.

## Validation

- `cd ui-v2 && npx eslint src/components/screens/ReportCenter.tsx src/viewModels/reportTruth.ts src/viewModels/crossSurfaceConsistency.ts tests/react-v2-critical-paths.spec.ts`
- `cd ui-v2 && npx tsc -b --pretty false`
- `cd ui-v2 && npx playwright test tests/react-v2-critical-paths.spec.ts --grep "Report Center|Canonical consistency"` (2 passed)
- `cd ui-v2 && npm run build`
- `cd ui-v2 && npm test` (25 passed, including i18n key parity)
- `python3 scripts/validate_backlog_tasks.py`
- `git diff --check`
