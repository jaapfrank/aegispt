# Codex UI/Reporting M1 - App Shell Split

Date: 2026-06-02
Owner: Codex UI/reporting lane

## Scope

M1 split the React v2 app composition root into route-shell modules without
changing runtime behavior or product truth. The active score-lane and
assessment runtime files were not touched.

## Files Changed

- `ui-v2/src/App.tsx`
- `ui-v2/src/components/app-shell/AppShell.tsx`
- `ui-v2/src/components/app-shell/CommandPalette.tsx`
- `ui-v2/src/components/app-shell/ToastViewport.tsx`
- `ui-v2/src/components/app-shell/WorkspaceSkeleton.tsx`
- `ui-v2/src/components/app-shell/commandItems.ts`
- `ui-v2/src/components/app-shell/navConfig.ts`
- `ui-v2/src/components/app-shell/navigation.tsx`
- `ui-v2/src/components/app-shell/types.ts`
- `ui-v2/src/components/app-shell/utils.ts`
- `ui-v2/src/components/screens/IntakeScreen.tsx`

## Behavior Preserved

- `App.tsx` now owns only the `I18nProvider` and route tree.
- `AppShell.tsx` owns bootstrap, engagement/run loading, selected-run scoped
  loading, topbar, workspace layout, route transitions, and error-boundary
  wrapping.
- Navigation config/rendering, command palette items/UI, toast viewport, and
  workspace loading skeleton are separated into shell modules.
- The mission experience spine remains hidden on Mission Control and visible on
  the other shell routes.
- Command palette navigation, engagement/run/finding selection actions,
  translated shell labels, skip link, and operator landmarks remain covered by
  the existing UI tests.

## Validation

- `cd ui-v2 && npx eslint src/App.tsx src/components/app-shell/AppShell.tsx src/components/app-shell/CommandPalette.tsx src/components/app-shell/ToastViewport.tsx src/components/app-shell/WorkspaceSkeleton.tsx src/components/app-shell/navigation.tsx src/components/app-shell/navConfig.ts src/components/app-shell/commandItems.ts src/components/app-shell/types.ts src/components/app-shell/utils.ts src/components/screens/IntakeScreen.tsx`
- `cd ui-v2 && npx tsc -b --pretty false`
- `cd ui-v2 && npx playwright test tests/react-v2-critical-paths.spec.ts --grep "App shell|primary navigation routes|Mission Intake"` (2 passed)
- `cd ui-v2 && npm test` (25 passed, including i18n key parity)
- `cd ui-v2 && npm run build`
- `python3 scripts/validate_backlog_tasks.py`
- `git diff --check`

An earlier full `npm test -- --run` was started in parallel with a separate
focused Playwright run. That parallel execution caused the shared Vite server
to drop connections (`ERR_CONNECTION_REFUSED` / `ERR_CONNECTION_RESET`). The
same full suite passed when rerun standalone after the focused run completed.

## Non-Overlap

No Claude score-lane files, `NEXT_TASK.md`, `TASK_QUEUE.md`,
assessment-loop/runtime files, worker runner files, scoring code, or active
XBEN validation artifacts were changed.
