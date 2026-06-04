# Codex UI Reporting W6A - Mission Control Operator Deck

Date: 2026-06-03
Owner: Codex
Lane: UI/reporting only

## Scope

This repair responds to operator feedback that Mission Control still felt like a
set of disconnected, text-heavy panels rather than a guided assessment
experience. The change stays inside the Codex UI/reporting lane.

Files changed in this pass:

- `ui-v2/src/components/screens/MissionControlV3.tsx`
- `ui-v2/src/index.css`
- `ui-v2/tests/react-v2-critical-paths.spec.ts`
- `CURRENT_STATE.md`
- `DONE_LOG.md`
- `DECISIONS.md`
- `docs/strategy/codex-ui-reporting-worklist-2026-06-01.md`

Screenshot evidence:

- `docs/validation/codex-ui-reporting-w6a-mission-control-operator-deck-1536x864.png`

## Design References Checked

- Nielsen Norman Group usability heuristics:
  https://media.nngroup.com/media/articles/attachments/Heuristic_Summary1_A4_compressed.pdf
  - Applied as visible system status, real-world language, recognition over
    recall, and minimalist first-viewport information.
- Fluent 2 accessibility guidance:
  https://fluent2.microsoft.design/accessibility
  - Applied as clearer hierarchy, meaningful text, focusable interactions, and
    zoom/reflow-aware sizing.
- Carbon status indicators:
  https://v10.carbondesignsystem.com/patterns/status-indicator-pattern/
  - Applied as limited status load, urgency hierarchy, and status text paired
    with color.
- OWASP WSTG Identify Application Entry Points:
  https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/06-Identify_Application_Entry_Points
  - Applied as route language grounded in mapping/testing entry points before
    conclusions.

## Behavior

- Mission Control `Live` now starts with an operator-presence deck:
  - `You are here`
  - current operator role
  - system state
  - evidence state
  - route stage
  - lead proof
  - impact
  - next actions
- Mission route stages are clickable links instead of passive labels:
  - Map -> Surface Map
  - Inspect/Test -> Live CLI
  - Proof -> Findings
  - Report -> Reports
- First-viewport copy was shortened so status, route, proof, impact, and action
  remain primary.
- Story cards, run picture, queue internals, CLI output, and technical facts
  remain available through the details layer.
- The Mission snapshot now uses a dashboard-aligned blue instrument surface and
  fixed route-button dimensions to reduce layout compression at zoomed display
  scales.
- Playwright can optionally capture the fixture-backed Mission Control
  screenshot through `AEGISPT_CAPTURE_MISSION_CONTROL=1`.

## Validation

Passed:

- `cd ui-v2 && npx eslint src/components/screens/MissionControlV3.tsx tests/react-v2-critical-paths.spec.ts`
- `cd ui-v2 && npx tsc -b --pretty false`
- `cd ui-v2 && npx playwright test tests/react-v2-critical-paths.spec.ts --grep "Mission Control renders interactive live results overview and technical views from fixtures"` (1 passed)
- `cd ui-v2 && AEGISPT_CAPTURE_MISSION_CONTROL=1 npx playwright test tests/react-v2-critical-paths.spec.ts --grep "Mission Control renders interactive live results overview and technical views from fixtures"` (1 passed; screenshot captured)
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
