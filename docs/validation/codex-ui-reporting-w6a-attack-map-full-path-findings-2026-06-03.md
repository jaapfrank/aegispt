# Codex UI Reporting W6A - Attack Map Full-Path Findings Repair - 2026-06-03

## Scope

Repair Mission Control's full attack map after operator feedback that multiple
critical findings were visible in Impact but not represented as actual attack
path events.

## Behavior Proven

- The attack map still scopes to the selected run, not stale assessment-chain
  sibling output.
- A run with 5 critical findings and 1 informational baseline renders each
  persisted finding as its own proof milestone in the full attack path.
- Proof milestones expose severity, persisted time, elapsed-from-run-start, and
  source-task timing.
- The report/outcome node summarizes the total finding mix (`5 critical ·
  1 info`) without replacing the proof path with a single `+N more` card.
- The full map remains pan/zoomable and Fit uses actual rendered bounds to avoid
  excessive empty canvas space.

## Screenshot Evidence

- `docs/validation/codex-ui-reporting-w6a-attack-map-full-path-findings-1536x864.png`

## Validation

- `cd ui-v2 && npx eslint src/components/screens/MissionControlV3.tsx tests/react-v2-critical-paths.spec.ts`
- `cd ui-v2 && npx tsc -b --pretty false`
- `cd ui-v2 && npx playwright test tests/react-v2-critical-paths.spec.ts -g "Mission Control attack map draws multiple critical findings as path milestones"` (1 passed)
- `cd ui-v2 && npx playwright test tests/react-v2-critical-paths.spec.ts -g "Mission Control attack map follows the selected run"` (1 passed)
- `cd ui-v2 && npx playwright test tests/react-v2-critical-paths.spec.ts -g "Mission Control renders interactive live results overview"` (1 passed)
- `cd ui-v2 && AEGISPT_CAPTURE_ATTACK_MAP_FULL_PATH=1 npx playwright test tests/react-v2-critical-paths.spec.ts -g "Mission Control attack map draws multiple critical findings as path milestones"` (1 passed, screenshot captured)
- `cd ui-v2 && npm test` (27 passed, including i18n key parity)
- `cd ui-v2 && npm run build` (passed; existing Vite chunk-size warning remains)
- `python3 scripts/validate_backlog_tasks.py`
- `git diff --check`

## Non-Overlap

No Claude score-lane files, `NEXT_TASK.md`, `TASK_QUEUE.md`,
assessment-loop/runtime files, worker runner files, scoring code, or active XBEN
validation artifacts were changed.
