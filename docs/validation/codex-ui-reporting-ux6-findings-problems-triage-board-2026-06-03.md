# Codex UI/Reporting UX6 - Findings and Problems triage board

Date: 2026-06-03
Owner: Codex UI/reporting lane
Scope: React v2 Findings Theater and Problems Center

## Summary

UX6 makes review and remediation decisions clearer without changing finding
schema or backend scoring/runtime behavior.

Changes:

- added `ui-v2/src/viewModels/triageBoards.ts` for deterministic finding and
  problem triage models
- added a Findings Theater triage board before the long finding list
- grouped repeated findings by normalized title/severity while keeping each
  individual evidence ref visible
- added severity lanes, proof strength, due/SLA cues, and next action copy based
  on existing finding list fields only
- added a Problems Center decision board with urgent, due, owner-needed, and
  SLA-watch lanes
- kept stored business impact, technical evidence, and remediation guidance in
  the selected finding detail drawer; the triage board does not invent these
  facts when they are absent from list payloads
- updated Problems Center load/bulk failure copy to use safe operator messages
  instead of raw endpoint/provider text

## Behavior Proven

- repeated findings are grouped in the first viewport but do not hide evidence
  refs or target count
- a missing-evidence finding remains labelled as evidence missing / proof needs
  review
- clicking a finding triage group opens the selected finding detail drawer
- Problems Center shows the small remediation decisions needed today:
  urgent/high severity, due/overdue, missing owner, and SLA-watch work
- selecting a problem from the decision board feeds the existing bulk-action
  selection state
- existing Findings Theater evidence/business-impact/remediation separation
  remains intact
- canonical consistency across Mission Control, Findings, Evidence Replay, and
  Reports remains intact

## Screenshot Evidence

- `docs/validation/codex-ui-reporting-ux6-findings-triage-board-1536x864.png`

## Validation

Completed:

- `cd ui-v2 && npx eslint src/components/screens/FindingsTheater.tsx src/components/screens/ProblemsCenter.tsx src/viewModels/triageBoards.ts tests/react-v2-critical-paths.spec.ts`
- `cd ui-v2 && npx tsc -b --pretty false`
- `cd ui-v2 && AEGISPT_CAPTURE_UX6_TRIAGE_BOARD=1 npx playwright test tests/react-v2-critical-paths.spec.ts -g "Findings Theater triage board|Problems Center triage board|Findings Theater filters|Findings Theater shows verified|Findings Theater separates"` (`5` passed, screenshot captured)
- `cd ui-v2 && npm test` (`37` passed, including i18n key parity)
- `cd ui-v2 && npm run build` (passed; existing Vite chunk-size warning remains)
- `python3 scripts/validate_backlog_tasks.py`
- `git diff --check`
