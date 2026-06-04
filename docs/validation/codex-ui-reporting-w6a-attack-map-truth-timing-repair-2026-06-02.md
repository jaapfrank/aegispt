# Codex UI/Reporting W6A - Attack Map Truth and Timing Repair

Date: 2026-06-02
Owner: Codex UI/reporting lane

## Operator Feedback

The attack map did not match the findings and the work that actually happened.
It also lacked time context: when the attack step happened, when proof was
persisted, and how long the system spent reaching that point.

## Scope

This repair keeps the Mission Control attack-map experience but changes the
map facts:

- route nodes are selected from real run tasks, with recent task order retained
- proof nodes use the actual persisted finding title, redacting only sensitive
  proof tokens/benchmark ids
- the proof node is linked back to the best completed/matching task instead of
  implying that a queued task caused existing proof
- compact current path prefers the source task that explains persisted proof
  when findings exist
- full-map detail panels expose task start/update time, task duration, finding
  persisted time, elapsed time from run start, and source-task duration

## Files Changed

- `ui-v2/src/components/screens/MissionControlV3.tsx`
- `ui-v2/tests/react-v2-critical-paths.spec.ts`

## Behavior Proven

- The full attack map now shows the real fixture finding title
  `Critical stored XSS in profile preview` instead of the generic
  `Input and data handling` management category.
- Selecting the proof node shows `Persisted`, `Elapsed from run start`, and
  `Source task duration`.
- The route keeps failed/dead-end branches visible while separating them from
  persisted proof.

## Validation

- `cd ui-v2 && npx eslint src/components/screens/MissionControlV3.tsx tests/react-v2-critical-paths.spec.ts`
- `cd ui-v2 && npx tsc -b --pretty false`
- `cd ui-v2 && npx playwright test tests/react-v2-critical-paths.spec.ts --grep "Mission Control renders interactive"` (1 passed)
- `cd ui-v2 && npm test` (25 passed, including i18n key parity)
- `cd ui-v2 && npm run build`
- `python3 scripts/validate_backlog_tasks.py`
- `git diff --check`

## Non-Overlap

No Claude score-lane files, `NEXT_TASK.md`, `TASK_QUEUE.md`,
assessment-loop/runtime files, worker runner files, scoring code, or active
XBEN validation artifacts were changed.
