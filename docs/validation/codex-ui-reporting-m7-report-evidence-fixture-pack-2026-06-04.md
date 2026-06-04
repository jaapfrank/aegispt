# Codex UI/Reporting M7 - Report/Evidence Fixture Pack

Date: 2026-06-04
Owner: Codex
Lane: UI/reporting

## Scope

M7 adds a named UI/reporting fixture matrix so report/evidence truth states are
first-class regression scenarios instead of ad hoc objects inside one large
Playwright spec.

The matrix covers:

- observed task output with no persisted finding
- run-local verified/signal count without canonical persistence
- verified and persisted finding ready for reporting
- blocked contradictory score/report-catalog state
- management report scope that names untested areas without claiming coverage

## Files

- `ui-v2/tests/fixtures/reportEvidenceScenarios.ts`
- `ui-v2/tests/react-v2-critical-paths.spec.ts`

## Proof

The new fixture matrix is exercised in two ways:

- `M7 report and evidence fixture matrix locks canonical truth boundaries`
  checks the named scenarios directly through `buildRunTruthModel` and
  `buildCrossSurfaceConsistency`.
- `Report Center flags the named M7 contradictory score fixture before export`
  routes the contradictory-score scenario through the mocked React v2 API and
  proves Report Center shows a review/mismatch state before export.

Focused validation:

```text
cd ui-v2 && npx eslint tests/react-v2-critical-paths.spec.ts tests/fixtures/reportEvidenceScenarios.ts
cd ui-v2 && npx tsc -b --pretty false
cd ui-v2 && npx playwright test tests/react-v2-critical-paths.spec.ts -g "M7 report and evidence fixture matrix|Report Center flags the named M7 contradictory score fixture|Report Center shows canonical report truth|Canonical consistency fixture"
cd ui-v2 && npm test
cd ui-v2 && npm run build
python3 scripts/validate_backlog_tasks.py
git diff --check
git diff --name-only -- NEXT_TASK.md TASK_QUEUE.md api/app/services/assessment_loop.py api/app/services/assessment_loop_internals/guards.py api/app/services/m2_verdict_gate.py workers/orchestration/tasks.py workers/runners/interactive_exploit
```

Result:

- ESLint passed
- TypeScript build passed
- focused Playwright set passed: 4/4
- full React v2 test script passed: 44/44
- production build passed; existing Vite large-chunk warning remains
- backlog validation passed
- `git diff --check` passed
- non-overlap check produced no changed Claude score-lane files

## Non-Overlap

No Claude score-lane files, runtime runners, assessment-loop files,
`NEXT_TASK.md`, or `TASK_QUEUE.md` were edited.
