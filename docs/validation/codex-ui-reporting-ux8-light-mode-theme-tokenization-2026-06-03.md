# Codex UI/Reporting UX8 Light Mode Theme Tokenization

Date: 2026-06-03
Owner: Codex
Lane: UI/reporting, worklist-only

## Scope

UX8 adds a reliable React v2 light-mode foundation without promoting work into
`NEXT_TASK.md` and without touching Claude-owned score-lane/runtime files.

Implemented behavior:

- `data-theme` is applied to the document root and persists through
  `localStorage`.
- The shell follows stored preference first and falls back to system light-mode
  preference when no stored preference exists.
- The App shell exposes a localized light/dark toggle.
- Core shell, sidebar, workspace, focus, panel, mission-spine, Mission Control
  snapshot, command strip, and terminal contrast are driven by semantic theme
  tokens instead of hardcoded dark-only colors.
- Live CLI remains a deliberate dark terminal surface in light mode, with fixed
  readable terminal contrast for command/stdout/stderr output.

## Screenshot Proof

- `docs/validation/codex-ui-reporting-ux8-light-mode-dashboard-1536x864.png`
- `docs/validation/codex-ui-reporting-ux8-light-mode-mission-control-1280x720.png`
- `docs/validation/codex-ui-reporting-ux8-light-mode-live-cli-1024x576.png`

The screenshots cover the requested 1536x864 and 1280x720 sizes plus a
constrained 1024x576 viewport that exercises the same cramped first-viewport
pressure as high browser/display scaling. Existing attack-map fit regression
coverage still verifies the 125%/150%-style viewport pressure path.

## Validation

- `cd ui-v2 && npx eslint src/components/screens/MissionControlV3.tsx src/components/app-shell/AppShell.tsx src/components/MissionExperienceSpine.tsx src/components/screens/Dashboard.tsx tests/react-v2-critical-paths.spec.ts`
- `cd ui-v2 && npx tsc -b --pretty false`
- `cd ui-v2 && node scripts/check-i18n.mjs`
- `cd ui-v2 && AEGISPT_CAPTURE_UX8_LIGHT_MODE=1 npx playwright test tests/react-v2-critical-paths.spec.ts -g "theme toggle persists light mode|Light mode keeps mission and command drilldowns"` (`2` passed, screenshots captured)
- `cd ui-v2 && npm test` (`39` passed, including i18n key parity)
- `cd ui-v2 && npm run build` (passed; existing Vite chunk-size warning remains)

Final hygiene:

- `python3 scripts/validate_backlog_tasks.py` passed
- `git diff --check` passed
- `git diff --name-only -- NEXT_TASK.md TASK_QUEUE.md api/app/services/assessment_loop.py api/app/services/assessment_loop_internals/guards.py api/app/services/m2_verdict_gate.py workers/orchestration/tasks.py workers/runners/interactive_exploit` produced no output
