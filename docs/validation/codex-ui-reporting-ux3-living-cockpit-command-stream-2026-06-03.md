# Codex UX3 Living Cockpit Command Stream

Date: 2026-06-03
Owner: Codex UI/reporting lane

## Scope

Completed the UX3 Mission Control living-cockpit repair without editing
`NEXT_TASK.md`, `TASK_QUEUE.md`, Claude-owned score-lane files, assessment-loop
runtime files, worker runner files, or active XBEN validation artifacts.

This slice builds on the already-proven W6A live-activity work and fixes the
remaining UX3 gap: the operator should see the active/next command and latest
output in the first Mission Control viewport without opening the full Live CLI
or scrolling down.

## Behavior

- Added a compact `Current command` stream inside the `Mission snapshot`.
- The strip selects the running task first, then the queued task, then the
  latest task.
- The strip shows:
  - command-style `$ tool --target ...` text
  - current task status
  - latest stdout/stderr from stored task detail when available
  - explicit queued/running/no-output recovery copy when output is not present
- Running tasks poll task detail every seven seconds so the cockpit can refresh
  while remaining a lightweight preview.
- Command and output copy wraps across two lines instead of truncating too
  aggressively at 1536x864.
- The full Live CLI remains the drilldown for complete terminal output.

## Screenshot Evidence

- `docs/validation/codex-ui-reporting-ux3-living-cockpit-command-stream-1536x864.png`

## Validation

- `cd ui-v2 && npx eslint src/components/screens/MissionControlV3.tsx tests/react-v2-critical-paths.spec.ts`
- `cd ui-v2 && npx tsc -b --pretty false`
- `cd ui-v2 && npx playwright test tests/react-v2-critical-paths.spec.ts -g "Mission Control renders interactive live results overview|Mission Control explains queued signal-only runs|Mission Control cockpit exposes the current command stream"` (`3` passed)
- `cd ui-v2 && AEGISPT_CAPTURE_UX3_LIVING_COCKPIT=1 npx playwright test tests/react-v2-critical-paths.spec.ts -g "Mission Control cockpit exposes the current command stream"` (`1` passed, screenshot captured)
- `cd ui-v2 && npm test` (`33` passed, including i18n key parity)
- `cd ui-v2 && npm run build` (passed; existing Vite chunk-size warning remains)

## Notes

The first targeted test run exposed a fixture issue: the running-run fixture
loaded a non-default inventory id and fell back to an empty task state. The
fixture router now returns inventory for the selected primary run so running,
queued, and selected-run cockpit assertions prove the intended state.
