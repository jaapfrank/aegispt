# Codex UX8 Light Mode Readability Repair - 2026-06-03

## Scope

Repair the remaining React v2 light-mode surfaces where hardcoded dark panels
could still inherit light-theme `text-text` / `text-muted` colors and become
hard to read.

This is a UX8 repair pass, not a new promoted task. `NEXT_TASK.md` was not
edited.

## Repair

- Added shared theme-safe surface classes in `ui-v2/src/index.css`:
  - `theme-surface-card`
  - `theme-subcard`
  - `dark-canvas`
  - `terminal-code`
- Converted ordinary product panels away from dark-only backgrounds in:
  - Report Center management proof, report metrics, stage detail, chart cards,
    dossier header, markdown code blocks, and chart tooltip
  - Evidence Replay mission route and selected evidence step panels
  - Findings Theater triage board, filter/header surfaces, and raw evidence
    block
  - Problems Center triage board
  - Mission Control story/run/queue cards while keeping attack-map and terminal
    surfaces intentionally dark with scoped text tokens
  - Intake guided panels, wizard panels, selected tile state, context footer,
    and launch overlay
  - Cinema Mode and crash recovery terminal stack blocks
- Added Playwright regression coverage that fails when a normal light-mode
  workspace contains hardcoded dark panels unless the surface is explicitly
  scoped as `dark-canvas` or `terminal-code`.

## Screenshot Evidence

- `docs/validation/codex-ui-reporting-ux8-light-mode-report-center-1536x864.png`
- `docs/validation/codex-ui-reporting-ux8-light-mode-management-proof-1536x864.png`
- `docs/validation/codex-ui-reporting-ux8-light-mode-evidence-replay-1536x864.png`
- `docs/validation/codex-ui-reporting-ux8-light-mode-findings-theater-1536x864.png`
- `docs/validation/codex-ui-reporting-ux8-light-mode-problems-1536x864.png`
- `docs/validation/codex-ui-reporting-ux8-light-mode-intake-1536x864.png`
- `docs/validation/codex-ui-reporting-ux8-light-mode-full-attack-map-1536x864.png`

## Validation

- `cd ui-v2 && npx eslint src/components/screens/ReportCenter.tsx src/components/screens/EvidenceReplay.tsx src/components/screens/FindingsTheater.tsx src/components/screens/ProblemsCenter.tsx src/components/screens/MissionControlV3.tsx src/components/CinemaMode.tsx src/components/ErrorBoundary.tsx src/components/Intake.tsx tests/react-v2-critical-paths.spec.ts`
- `cd ui-v2 && npx tsc -b --pretty false`
- `cd ui-v2 && AEGISPT_CAPTURE_UX8_LIGHT_MODE=1 npx playwright test tests/react-v2-critical-paths.spec.ts -g "Light mode keeps report evidence triage and intake"` (`1` passed, screenshots captured)
- `cd ui-v2 && npm test` (`40` passed, including i18n key parity)
- `cd ui-v2 && npm run build` (passed; existing Vite chunk-size warning remains)
