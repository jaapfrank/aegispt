# Codex UI Reporting W6A - Attack Map Pan/Zoom

Date: 2026-06-03
Owner: Codex
Lane: UI/reporting only

## Scope

This repair responds to operator feedback that the full Mission Control attack
map did not fit wide routes, could not zoom out far enough, could not be dragged
with the mouse, and had a `Fit` action that reset scale rather than centering
the actual route.

Files changed in this pass:

- `ui-v2/src/components/screens/MissionControlV3.tsx`
- `ui-v2/tests/react-v2-critical-paths.spec.ts`
- `CURRENT_STATE.md`
- `DONE_LOG.md`
- `DECISIONS.md`
- `docs/strategy/codex-ui-reporting-worklist-2026-06-01.md`

Screenshot evidence:

- `docs/validation/codex-ui-reporting-w6a-attack-map-panzoom-1536x864.png`

## Behavior

- The full attack map overlay now uses a real pan/zoom viewport instead of a
  scaled scrollbox.
- Operators can zoom with the mouse wheel, zoom with keyboard shortcuts or
  buttons, drag the map canvas to pan, double-click to fit, or press `0` to fit.
- Zoom-out now supports much wider attack paths by allowing a lower minimum
  scale.
- `Fit` calculates from the rendered viewport and map dimensions, then centers
  the whole route in view.
- Attack-map transform state is exposed through test-only attributes so the
  browser test can prove that wheel zoom and drag pan change the UI.
- Node click-through detail remains intact; panning does not steal normal node
  selection.

## Validation

Passed:

- `cd ui-v2 && npx eslint src/components/screens/MissionControlV3.tsx tests/react-v2-critical-paths.spec.ts`
- `cd ui-v2 && npx tsc -b --pretty false`
- `cd ui-v2 && AEGISPT_CAPTURE_ATTACK_MAP_PANZOOM=1 npx playwright test tests/react-v2-critical-paths.spec.ts -g "Mission Control renders interactive live results overview and technical views from fixtures"` (1 passed; screenshot captured)
- `cd ui-v2 && npm test` (25 passed, including i18n key parity)
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
