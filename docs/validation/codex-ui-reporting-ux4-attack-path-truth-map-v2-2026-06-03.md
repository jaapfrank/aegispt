# Codex UX4 Attack Path Truth Map V2

Date: 2026-06-03
Owner: Codex UI/reporting lane

## Scope

Completed UX4 from the Codex UI/reporting worklist without editing
`NEXT_TASK.md`, `TASK_QUEUE.md`, Claude-owned score-lane files, assessment-loop
runtime files, worker runner files, scoring code, or active XBEN validation
artifacts.

This slice verifies and tightens the Mission Control full attack map as a
truthful selected-run route map. It builds on the W6A attack-map repairs and
adds UX4-specific proof for fit/usability under 125% and 150%-style viewport
pressure.

## Behavior

- The full attack map is selected-run bound: it uses the selected run's tasks
  and filters run-linked findings to the selected run.
- Stale sibling assessment-chain tasks and findings are not reused when a
  different run is selected.
- Multiple reportable findings render as individual proof milestones instead
  of a grouped or vague finding-cluster card.
- The proof path and report node agree on finding count and severity mix.
- Important map cards show timing directly on the card: run start, task
  completion/failure, task duration, proof time, elapsed-from-start, and
  source-task timing where available.
- The full map remains a real interaction surface with mouse-wheel zoom,
  drag-to-pan, Fit, keyboard zoom, replay controls, detail click-through, and
  severity legend.
- The full-map overlay now keeps the detail panel beside the canvas from the
  `lg` breakpoint upward, so 125% and 150%-style effective viewports preserve
  enough map height for Fit.
- Proof cards now reserve enough vertical space for timing chips, avoiding the
  clipped-card state visible in the first screenshot pass.

## Screenshot Evidence

- `docs/validation/codex-ui-reporting-ux4-attack-path-truth-map-1536x864.png`
- Supporting earlier W6A evidence:
  `docs/validation/codex-ui-reporting-w6a-attack-map-panzoom-1536x864.png`
  and
  `docs/validation/codex-ui-reporting-w6a-attack-map-full-path-findings-1536x864.png`

## Validation

- `cd ui-v2 && npx eslint src/components/screens/MissionControlV3.tsx tests/react-v2-critical-paths.spec.ts`
- `cd ui-v2 && npx tsc -b --pretty false`
- `cd ui-v2 && npx playwright test tests/react-v2-critical-paths.spec.ts -g "Mission Control attack map fit remains usable"` (`1` passed)
- `cd ui-v2 && npx playwright test tests/react-v2-critical-paths.spec.ts -g "Mission Control renders interactive live results overview|Mission Control attack map follows the selected run|Mission Control attack map draws multiple critical findings|Mission Control attack map fit remains usable"` (`4` passed)
- `cd ui-v2 && AEGISPT_CAPTURE_ATTACK_MAP_FULL_PATH=1 npx playwright test tests/react-v2-critical-paths.spec.ts -g "Mission Control attack map draws multiple critical findings as path milestones"` (`1` passed, screenshot captured)
- `cd ui-v2 && AEGISPT_CAPTURE_UX4_ATTACK_MAP=1 npx playwright test tests/react-v2-critical-paths.spec.ts -g "Mission Control attack map draws multiple critical findings as path milestones"` (`1` passed, UX4 screenshot captured)
- `cd ui-v2 && npm test` (`34` passed, including i18n key parity)
- `cd ui-v2 && npm run build` (passed; existing Vite chunk-size warning remains)

## Notes

The first UX4 visual inspection showed correct data behavior but clipped
proof-card timing chips. The implementation now increases proof-card height and
spacing and keeps the side detail panel from collapsing below the canvas at
large laptop/effective-zoom widths. A dedicated Playwright regression checks
that Start, Proof 5, and Outcome nodes fit inside the map canvas at 1230x690
and 1024x576 effective viewports, matching the operator's 125%/150% scaling
concern.
