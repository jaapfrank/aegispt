# Codex UX2 Shared Page Experience Contract

Date: 2026-06-03
Owner: Codex UI/reporting lane

## Scope

Completed UX2 from the Codex UI/reporting worklist without editing
`NEXT_TASK.md`, `TASK_QUEUE.md`, Claude-owned score-lane files, assessment-loop
runtime files, worker runner files, or active XBEN validation artifacts.

## Behavior

- Added a compact mission-context presentation for secondary/admin/diagnostic
  React v2 routes:
  - Intake
  - Live CLI
  - Packs
  - CVE Library
  - Research
  - Settings
- Kept the full mission story spine on primary assessment/review/outcome routes
  where the route-stage rail is still useful.
- Added route-specific context copy for setup, diagnostics, build, knowledge,
  research, and admin pages so the first viewport answers what the page is for.
- Compact context still shows canonical mission facts: target, checked evidence,
  saved proof, and one primary mission action.
- The compact spine uses a wider breakpoint so 1280x720 does not squeeze or
  truncate the Live CLI title; it stacks context/facts/actions instead.

## Screenshot Evidence

- `docs/validation/codex-ui-reporting-ux2-admin-compact-spine-1536x864.png`
- `docs/validation/codex-ui-reporting-ux2-diagnostics-compact-spine-1280x720.png`

## Validation

- `cd ui-v2 && npx eslint src/components/MissionExperienceSpine.tsx tests/react-v2-critical-paths.spec.ts`
- `cd ui-v2 && npx tsc -b --pretty false`
- `cd ui-v2 && npx playwright test tests/react-v2-critical-paths.spec.ts -g "Mission experience spine carries|Secondary admin and diagnostics routes use compact mission context"` (`2` passed)
- `cd ui-v2 && AEGISPT_CAPTURE_UX2_PAGE_CONTRACT=1 npx playwright test tests/react-v2-critical-paths.spec.ts -g "Secondary admin and diagnostics routes use compact mission context"` (`1` passed, screenshots captured)
- `cd ui-v2 && npm test` (`32` passed, including i18n key parity)
- `cd ui-v2 && npm run build` (passed; existing Vite chunk-size warning remains)

## Notes

This slice intentionally avoids a broad per-screen redesign. UX2 is a shared
page-experience repair: it reduces cockpit weight on supporting pages while
preserving the same selected-run truth, facts, and actions.
