# Codex UX1 Trust-Breaking State Repair - 2026-06-03

## Scope

UX1 repaired raw/confusing UI states in the Codex-owned React v2 UI/reporting
lane. No Claude score-lane files, `NEXT_TASK.md`, `TASK_QUEUE.md`,
assessment-loop/runtime files, worker runner files, scoring code, or active
XBEN validation artifacts were changed.

## Behavior Repaired

- Added `ui-v2/src/viewModels/safeMessaging.ts` so operator-facing UI can mask
  raw API, provider, stack, billing, request-id, and diagnostic payload text.
- Updated AppShell global error copy to use safe operator-facing messages
  instead of raw `Error.message` text.
- Updated Research:
  - raw `500` / provider-style errors are replaced with safe recovery copy
  - refresh and generation actions use safe error handling
  - no-engagement state now explains the required engagement context and links
    to mission creation
- Updated Report Center:
  - raw AI/provider billing text returned as a briefing string is masked before
    rendering
  - report catalog, preview, export, compare, and findings-load failures use
    safe report-specific recovery copy
- Updated History:
  - raw history-load errors are masked
  - refresh is safely handled
  - filtered empty state now distinguishes "no runs exist" from "filters hide
    available runs"
  - reset/refresh actions recover from the empty state
- Updated Dashboard:
  - load, refresh, and rapid-response scan errors use safe copy
  - active-task metric prefers dashboard `active_run` task counts when the
    dashboard endpoint provides them, avoiding a mixed local/portfolio signal
- Updated Findings Theater global error copy to use the same safe formatter for
  finding/detail load failures.

## Screenshot Proof

- `docs/validation/codex-ui-reporting-ux1-report-provider-mask-1536x864.png`
- `docs/validation/codex-ui-reporting-ux1-research-safe-error-1536x864.png`
- `docs/validation/codex-ui-reporting-ux1-history-filter-empty-1536x864.png`
- `docs/validation/codex-ui-reporting-ux1-history-filter-reset-1536x864.png`

## Validation

- `cd ui-v2 && npx eslint src/viewModels/safeMessaging.ts src/components/app-shell/AppShell.tsx src/components/screens/Research.tsx src/components/screens/History.tsx src/components/screens/Dashboard.tsx src/components/screens/ReportCenter.tsx src/components/screens/FindingsTheater.tsx tests/react-v2-critical-paths.spec.ts`
- `cd ui-v2 && npx tsc -b --pretty false`
- `cd ui-v2 && npx playwright test tests/react-v2-critical-paths.spec.ts -g "Report Center masks raw provider briefing failures|Research masks raw API failures|History explains filtered empty states|Report Center shows canonical report truth|Canonical consistency fixture"` (`5` passed)
- `cd ui-v2 && AEGISPT_CAPTURE_UX1_TRUST_REPAIR=1 npx playwright test tests/react-v2-critical-paths.spec.ts -g "Report Center masks raw provider briefing failures|Research masks raw API failures|History explains filtered empty states"` (`3` passed, screenshots captured)
- `cd ui-v2 && npm test` (`31` passed, including i18n key parity)
- `cd ui-v2 && npm run build` (passed; existing Vite chunk-size warning remains)

## Remaining Notes

This UX1 slice intentionally stayed narrow. Some admin/detail screens outside
the named UX1 scope still have local raw `error.message` handling and should be
cleaned in a broader safe-messaging pass, likely during UX2 shared page
experience work.
