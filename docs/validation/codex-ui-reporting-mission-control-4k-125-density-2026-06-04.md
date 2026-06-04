# Codex UI/Reporting Validation — Mission Control 4k/125 Density Repair

Date: 2026-06-04

## Scope

Repaired Mission Control first-viewport density after operator feedback from a
15-inch 4k display at 125% scaling, then removed the duplicate cockpit command
strip after follow-up feedback that the same command/output appeared twice. The
effective browser viewport was modeled as `2048x1152` in dark mode.

## Behavior Repaired

- The Mission Control cockpit is now a compact mission snapshot only: operator
  state, target, risk, next action, checked evidence, and findings.
- The Live CLI panel is the single command-following surface in the Live view;
  command/output no longer appears again in the cockpit.
- Mission Control's inline terminal is a compact preview. Structured JSON output
  is summarized into a few useful lines instead of filling the first viewport
  with raw expanded output; full raw output remains in the dedicated Live CLI.
- Queue rows now use the same selected-run task timeline as the Live CLI
  selector. Repeated tools stay visible as separate task executions instead of
  being merged into one row.
- Queue remains visible beside Live CLI in the first `2048x1152` dark-mode
  viewport.
- Attack path, story cards, live events, and technical facts are kept behind a
  drilldown so the first viewport stays focused.
- The regression asserts that the snapshot height stays bounded, Live CLI and
  Queue remain visible high enough in the viewport, and the snapshot does not
  expose a duplicate `Current command stream`.
- A regression also proves that repeated tool executions are not grouped in the
  Queue and that selecting a Queue row opens the matching Live CLI task output.

## Screenshot Evidence

- `docs/validation/codex-ui-reporting-mission-control-4k-125-scale-2048x1152.png`

## Validation

- `cd ui-v2 && npx eslint src/components/screens/MissionControlV3.tsx tests/react-v2-critical-paths.spec.ts`
- `cd ui-v2 && npx tsc -b --pretty false`
- `cd ui-v2 && AEGISPT_CAPTURE_MISSION_CONTROL_4K_SCALE=1 npx playwright test tests/react-v2-critical-paths.spec.ts -g "Mission Control stays scan-friendly"`
- `cd ui-v2 && npx playwright test tests/react-v2-critical-paths.spec.ts -g "Mission Control"`
- `cd ui-v2 && npm test`
- `cd ui-v2 && npm run build`

Result: all validations passed. The build still emits the existing Vite
large-chunk warning.
