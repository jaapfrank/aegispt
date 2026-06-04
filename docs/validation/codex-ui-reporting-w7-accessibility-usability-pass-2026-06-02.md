# Codex UI/reporting W7 accessibility and usability pass

Date: 2026-06-02
Owner: Codex UI/reporting lane

## Scope

W7 focused on keyboard access, semantic landmarks, focus clarity, and calmer
Mission Control interaction without touching Claude's score-lane files.

## What changed

- Added a translated skip link that moves focus directly to the AegisPT
  workspace.
- Added named shell landmarks for the main workspace, primary navigation, and
  operator menu.
- Extended focus-visible styling from the content area to the whole shell,
  including topbar, sidebar, tab panels, and interactive map regions.
- Made the command palette input/list behave like a combobox with a labelled
  listbox and active descendant.
- Made the global mission spine route expose its active step and progressbar
  semantics.
- Converted Mission Control view buttons into a real tablist with
  `aria-selected`, `aria-controls`, tab panels, and Arrow/Home/End keyboard
  navigation.
- Improved the full attack map dialog with labelled title/help text, initial
  focus on Close, Escape close, focus return to the opener, keyboard zoom
  shortcuts, and accessible names for attack-map nodes.

## Visual proof

- `docs/validation/codex-ui-reporting-w7-accessibility-usability-mission-control-1536x864.png`
- `docs/validation/codex-ui-reporting-w7-accessibility-usability-mission-control-1280x720.png`
- `docs/validation/codex-ui-reporting-w7-accessibility-usability-full-map-1536x864.png`

## Validation

- `cd ui-v2 && npx eslint src/App.tsx src/components/MissionExperienceSpine.tsx src/components/screens/MissionControlV3.tsx tests/react-v2-critical-paths.spec.ts`
- `cd ui-v2 && npm run build`
- `cd ui-v2 && npx playwright test tests/react-v2-critical-paths.spec.ts --grep "App shell exposes keyboard|Mission Control renders interactive"` (2 passed)
- `cd ui-v2 && npx playwright test tests/react-v2-critical-paths.spec.ts` (21 passed)
- `cd ui-v2 && npm test` (24 passed, including i18n key parity)
- `python3 scripts/validate_backlog_tasks.py`
- `git diff --check`

## Non-overlap

No `NEXT_TASK.md`, `TASK_QUEUE.md`, runtime runner, assessment-loop, verifier,
or active score-lane validation files were changed.
