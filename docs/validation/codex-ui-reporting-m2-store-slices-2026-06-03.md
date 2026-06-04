# Codex UI/Reporting M2 - Store Slices

Date: 2026-06-03
Owner: Codex

## Scope

Split the React v2 Zustand store into state slices without changing the public
`useAegisStore` API or visible product behavior.

## Changes

- Kept `ui-v2/src/store/index.ts` as the store composition root.
- Added `ui-v2/src/store/types.ts` for the shared `AegisStore`,
  `ActorState`, `RunStreamState`, and slice creator types.
- Added `engagementRunSlice.ts` for engagement selection, run selection, task
  state, and run-scoped reset behavior.
- Added `evidenceSlice.ts` for findings, selected finding, inventory,
  AI-insights, and proposals.
- Added `operatorSlice.ts` for actor/settings state while preserving local
  actor persistence.
- Added `runtimeSlice.ts` for loading/error and run-stream state.
- Added `actorPersistence.ts` so Settings can keep importing the existing actor
  storage keys through the root store module.

## Behavior Proof

- `cd ui-v2 && npx eslint src/store/index.ts src/store/types.ts src/store/actorPersistence.ts src/store/engagementRunSlice.ts src/store/evidenceSlice.ts src/store/operatorSlice.ts src/store/runtimeSlice.ts`
- `cd ui-v2 && npx tsc -b --pretty false`
- `cd ui-v2 && npx playwright test tests/i18n.spec.ts` (3 passed)
- `cd ui-v2 && npx playwright test tests/react-v2-critical-paths.spec.ts --grep "Mission experience spine carries the selected run story across the shell|Mission Control renders interactive live results overview"` (2 passed)
- `cd ui-v2 && npm test` (27 passed, including i18n key parity)
- `cd ui-v2 && npm run build` (passed; existing Vite chunk-size warning remains)
- `python3 scripts/validate_backlog_tasks.py`
- `git diff --check`

## Non-Overlap

No Claude score-lane files, `NEXT_TASK.md`, `TASK_QUEUE.md`,
assessment-loop/runtime files, worker runner files, scoring code, or active
XBEN validation artifacts were changed by this M2 slice.
