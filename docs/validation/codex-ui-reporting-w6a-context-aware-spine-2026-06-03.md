# Codex UI Reporting W6A - Context-Aware Mission Spine

Date: 2026-06-03
Owner: Codex
Lane: UI/reporting only

## Scope

This repair responds to operator feedback that the product still needed to feel
like one guided system, not separate screens. The previous Mission Control
operator deck remained complete; this pass changes the global mission spine so
ordinary pages explain their role in the same mission story.

Files changed in this pass:

- `ui-v2/src/components/MissionExperienceSpine.tsx`
- `ui-v2/src/components/app-shell/AppShell.tsx`
- `ui-v2/tests/react-v2-critical-paths.spec.ts`
- `CURRENT_STATE.md`
- `DONE_LOG.md`
- `DECISIONS.md`
- `docs/strategy/codex-ui-reporting-worklist-2026-06-01.md`

Screenshot evidence:

- `docs/validation/codex-ui-reporting-w6a-context-aware-spine-evidence-1536x864.png`

## Design References Checked

- Nielsen Norman Group usability heuristics:
  https://media.nngroup.com/media/articles/attachments/Heuristic_Summary1_A4_compressed.pdf
  - Applied as visible system status, recognition over recall, and minimalist
    first-screen communication.
- Fluent 2 layout guidance:
  https://fluent2.microsoft.design/layout
  - Applied as relationships between components, hierarchy, and balanced use of
    space.
- Fluent 2 accessibility guidance:
  https://fluent2.microsoft.design/accessibility
  - Applied as matching visual active-state and screen-reader active-state via
    `aria-current="step"`.
- Fluent 2 color guidance:
  https://fluent2.microsoft.design/color
  - Applied as semantic status color without relying on color alone.
- Carbon status indicators:
  https://v10.carbondesignsystem.com/patterns/status-indicator-pattern/
  - Applied as concise status labels paired with visual indicators.

## Behavior

- `AppShell` now passes the current route to `MissionExperienceSpine`.
- The mission spine remains run-aware but is now also page-aware:
  - Dashboard: selected-run mission summary
  - Evidence Replay: `You are replaying the proof trail`
  - Findings/Problems: `You are deciding what counts`
  - Report Center: `You are turning proof into a report`
  - Live CLI: `You are watching raw output`
  - Surface Map: `You are mapping the surface`
  - History: `You are reviewing the mission memory`
- The route rail marks the active page's mission stage with
  `aria-current="step"`.
- Screenshot review found cramped title/action behavior; the title can now wrap
  and action buttons stack cleanly at normal desktop widths.

## Validation

Passed:

- `cd ui-v2 && npx eslint src/components/MissionExperienceSpine.tsx src/components/app-shell/AppShell.tsx tests/react-v2-critical-paths.spec.ts`
- `cd ui-v2 && npx tsc -b --pretty false`
- `cd ui-v2 && npx playwright test tests/react-v2-critical-paths.spec.ts --grep "Mission experience spine carries the selected run story across the shell"` (1 passed)
- `cd ui-v2 && AEGISPT_CAPTURE_SPINE_CONTEXT=1 npx playwright test tests/react-v2-critical-paths.spec.ts --grep "Mission experience spine carries the selected run story across the shell"` (1 passed; screenshot captured)
- `cd ui-v2 && npm test` (25 passed, including i18n key parity)
- `cd ui-v2 && npm run build` (passed; existing Vite chunk-size warning remains)
- `python3 scripts/validate_backlog_tasks.py`
- `git diff --check`

Generated `ui-v2/dist` and `ui-v2/test-results` were removed after validation.

## Non-Overlap

No Claude score-lane files were changed:

- `NEXT_TASK.md`
- `TASK_QUEUE.md`
- `api/app/services/assessment_loop.py`
- `api/app/services/assessment_loop_internals/guards.py`
- `api/app/services/m2_verdict_gate.py`
- `workers/orchestration/tasks.py`
- `workers/runners/interactive_exploit/**`
- active XBEN/focused-assessment validation artifacts
