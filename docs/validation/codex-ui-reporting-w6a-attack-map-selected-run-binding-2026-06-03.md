# Codex UI Reporting W6A - Attack Map Selected-Run Binding

Date: 2026-06-03
Owner: Codex
Lane: UI/reporting only

## Scope

This repair responds to operator feedback that the Mission Control attack map
showed the same output regardless of the selected mission/run.

Files changed in this pass:

- `ui-v2/src/components/screens/MissionControlV3.tsx`
- `ui-v2/tests/react-v2-critical-paths.spec.ts`
- `CURRENT_STATE.md`
- `DONE_LOG.md`
- `DECISIONS.md`
- `docs/strategy/codex-ui-reporting-worklist-2026-06-01.md`

## Root Cause

Mission Control receives chain-aware tasks/findings for canonical truth. That is
correct for count/report consistency, but it is wrong for the attack map route:
the map is meant to visualize what happened in the selected mission/run. Since
the chain task endpoint returns the whole assessment-chain task list, every run
inside that chain could render the same map.

## Behavior

- The attack map now uses `run.tasks` for the selected run route.
- Chain-aware findings are filtered to findings whose `run_id` matches the
  selected run.
- Legacy findings without `run_id` remain visible as fallback data.
- Findings from sibling runs in the same assessment chain no longer appear as
  selected-run proof.
- The compact current path now shows the selected run's last task before a
  terminal dead-end/outcome, instead of jumping straight from decision to
  dead-end.

## Regression Test

Added a fixture with two runs in the same assessment chain:

- the selected run has local task `selected-only-probe`
- the assessment-chain endpoint returns stale sibling task `chain-stale-probe`
- chain findings include a stale finding from another run

The browser test proves that both compact and full attack maps show
`selected-only-probe` and do not show `chain-stale-probe` or the sibling
finding as selected-run proof.

## Validation

Passed:

- `cd ui-v2 && npx eslint src/components/screens/MissionControlV3.tsx tests/react-v2-critical-paths.spec.ts`
- `cd ui-v2 && npx tsc -b --pretty false`
- `cd ui-v2 && npx playwright test tests/react-v2-critical-paths.spec.ts -g "Mission Control attack map follows the selected run"` (1 passed)
- `cd ui-v2 && npx playwright test tests/react-v2-critical-paths.spec.ts -g "Mission Control renders interactive live results overview and technical views from fixtures"` (1 passed)
- `cd ui-v2 && npm test` (26 passed, including i18n key parity)
- `cd ui-v2 && npm run build` (passed; existing Vite chunk-size warning remains)
- `python3 scripts/validate_backlog_tasks.py`
- `git diff --check`

Generated `ui-v2/dist` and `ui-v2/test-results` were removed after validation.

## Non-Overlap

No Claude score-lane files were changed:

- `NEXT_TASK.md`
- `TASK_QUEUE.md`
- `api/app/services/assessment_loop.py`
- `api/app/services/assessment_loop_internals/guards.py`
- `api/app/services/m2_verdict_gate.py`
- `workers/orchestration/tasks.py`
- `workers/runners/interactive_exploit/**`
- active XBEN/focused-assessment validation artifacts
