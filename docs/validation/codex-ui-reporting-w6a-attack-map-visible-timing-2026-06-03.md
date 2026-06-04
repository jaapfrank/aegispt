# Codex Validation - W6A Attack Map Visible Timing Repair

Date: 2026-06-03
Owner: Codex UI/reporting lane

## Scope

Operator feedback: the Mission Control attack map still did not show when the
attack happened or how long the system needed to reach proof. Timing was present
in detail metadata but not visible in the map itself.

## Changes

- Added compact timing chips to attack-map nodes and the compact current path.
- Exposed run start, elapsed route time, task completion/failure time, task
  duration, proof persisted time, elapsed time from run start, and source-task
  duration directly on map cards.
- Updated route end-time calculation to include persisted finding timestamps,
  not only task timestamps.
- Extended the Mission Control Playwright fixture with a timed run where proof
  is persisted 8 minutes after start and its source task takes 1 minute.

## Proof

- Compact current path shows proof clock time plus `after 8m`.
- Full attack-map proof node shows proof clock time plus `after 8m` and
  `source took 1m`.
- Full-map detail panel still exposes the expanded timing metadata:
  `Persisted`, `Elapsed from run start`, and `Source task duration`.

## Validation

- `cd ui-v2 && npx eslint src/components/screens/MissionControlV3.tsx tests/react-v2-critical-paths.spec.ts`
- `cd ui-v2 && npx tsc -b --pretty false`
- `cd ui-v2 && npx playwright test tests/react-v2-critical-paths.spec.ts --grep "Mission Control renders interactive live results overview and technical views from fixtures"` (1 passed)
- `cd ui-v2 && npm test` (25 passed, including i18n key parity)
- `cd ui-v2 && npm run build`
- `python3 scripts/validate_backlog_tasks.py`
- `git diff --check`

## Non-Overlap

No Claude score-lane files, `NEXT_TASK.md`, `TASK_QUEUE.md`,
assessment-loop/runtime files, worker runner files, scoring code, or active XBEN
validation artifacts were changed.
