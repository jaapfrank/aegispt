# Codex UI Reporting W6A - Mission Control Live Activity Repair - 2026-06-03

## Scope

Repair Mission Control after operator feedback that the Live screen still felt
static and did not clearly show what the system was doing.

## Behavior Proven

- Mission Control exposes a semantic activity state for the Live cockpit:
  `running`, `queued`, `review`, `done`, or `idle`.
- Queued runs show a live system activity rail under the cockpit headline.
- The mission route marks the queued continuation phase so the operator can see
  where the route will move next.
- Queue handoff and queue rows carry status-driven motion cues.
- Compact Mission path nodes carry status-driven activity cues.
- Animations are tied to real status attributes and include a
  `prefers-reduced-motion: reduce` guard.

## Screenshot Evidence

- `docs/validation/codex-ui-reporting-w6a-mission-live-activity-1536x864.png`

## Validation

- `cd ui-v2 && npx eslint src/components/screens/MissionControlV3.tsx tests/react-v2-critical-paths.spec.ts`
- `cd ui-v2 && npx tsc -b --pretty false`
- `cd ui-v2 && npx playwright test tests/react-v2-critical-paths.spec.ts -g "Mission Control explains queued signal-only runs"` (1 passed)
- `cd ui-v2 && AEGISPT_CAPTURE_MISSION_LIVE_ACTIVITY=1 npx playwright test tests/react-v2-critical-paths.spec.ts -g "Mission Control explains queued signal-only runs"` (1 passed, screenshot captured)
- `cd ui-v2 && npm test` (27 passed, including i18n key parity)
- `cd ui-v2 && npm run build` (passed; existing Vite chunk-size warning remains)
- `python3 scripts/validate_backlog_tasks.py`
- `git diff --check`

## Non-Overlap

No Claude score-lane files, `NEXT_TASK.md`, `TASK_QUEUE.md`,
assessment-loop/runtime files, worker runner files, scoring code, or active XBEN
validation artifacts were changed.
