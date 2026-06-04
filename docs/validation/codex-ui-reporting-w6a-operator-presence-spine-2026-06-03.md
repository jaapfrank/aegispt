# Codex Validation - W6A Operator Presence Spine Repair

Date: 2026-06-03
Owner: Codex UI/reporting lane

## Scope

Operator feedback: the UI still felt like many separate screens. The product
needed to carry the operator through the assessment, show all important state,
and create a stronger sense of being part of the live system.

This repair targeted the global React v2 mission spine because it appears above
ordinary screens and acts as the bridge between Mission Control, Evidence,
Findings, and Reports.

## Reviewed UI References

- Nielsen Norman Group usability heuristics: visible system status,
  real-world language, recognition over recall, and minimalist design.
- Microsoft Fluent guidance: clear hierarchy, plain meaningful text,
  interaction states, and semantic color used for status rather than decoration.
- IBM Carbon status indicator pattern: combine color, shape/type/symbol and do
  not rely on color alone for state.
- OWASP WSTG guidance: map entry points and execution paths before drawing
  security conclusions.

Sources:

- https://media.nngroup.com/media/articles/attachments/Heuristic_Summary1_A4_compressed.pdf
- https://fluent2.microsoft.design/accessibility
- https://fluent2.microsoft.design/color
- https://v10.carbondesignsystem.com/patterns/status-indicator-pattern/
- https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/06-Identify_Application_Entry_Points
- https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/01-Information_Gathering/07-Map_Execution_Paths_Through_Application

## Changes

- Reframed the shell spine from administrative `Now / Route / Next` into
  `You are here / Route / Your next move`.
- Kept canonical selected-run, chain-aware task/finding, and inventory truth.
- Added compact facts for target, checked progress, proof count, risk,
  evidence trails, and report readiness.
- Added concise route-step context for Live, Evidence, Findings, and Report.
- Updated the visual treatment to a single blue instrument surface with a live
  status orb, active route cards, compact status dots, semantic status accents,
  and zero base letter-spacing.

## Proof

- The spine still carries the selected run story and canonical counts.
- The spine now visibly includes:
  - `You are here`
  - `Your next move`
  - `Target`
  - `Checked`
  - `Proof`
  - `Risk`
  - `Evidence`
- Route buttons remain keyboard/click drilldowns into Mission Control,
  Evidence, Findings, and Reports.

## Validation

- `cd ui-v2 && npx eslint src/components/MissionExperienceSpine.tsx tests/react-v2-critical-paths.spec.ts`
- `cd ui-v2 && npx tsc -b --pretty false`
- `cd ui-v2 && npx playwright test tests/react-v2-critical-paths.spec.ts --grep "Mission experience spine carries the selected run story across the shell"` (1 passed)
- `cd ui-v2 && npm test` (25 passed, including i18n key parity)
- `cd ui-v2 && npm run build`
- `python3 scripts/validate_backlog_tasks.py`
- `git diff --check`

## Non-Overlap

No Claude score-lane files, `NEXT_TASK.md`, `TASK_QUEUE.md`,
assessment-loop/runtime files, worker runner files, scoring code, or active XBEN
validation artifacts were changed.
