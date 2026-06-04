# Codex UI/Reporting W6A — Mission Experience Spine

Date: 2026-06-01

Owner: Codex UI/reporting lane

## Operator Problem

The operator clarified that the missing value was product-wide, not only in
reports. Mission Control, Cinema Mode, the full attack map, findings, evidence,
and reports need to feel like one guided assessment story. Otherwise the product
can have many correct screens while still feeling like disconnected pages.

## Change

React v2 now renders a global `MissionExperienceSpine` from the app shell when a
run is selected. The spine uses the same selected run, chain-aware tasks,
findings, and inventory already loaded by the shell.

It presents:

- `Now`: the current mission scene in short plain language.
- `Route`: a live/evidence/findings/report progress rail.
- `Next`: the most useful next action for the current state.

Click-through actions route to Mission Control, Live CLI, Evidence Replay,
Findings, and Reports. Terminal runs with stale queued task rows stay in
outcome/review state instead of appearing live.

## Files

- `ui-v2/src/components/MissionExperienceSpine.tsx`
- `ui-v2/src/App.tsx`
- `ui-v2/src/index.css`
- `ui-v2/tests/react-v2-critical-paths.spec.ts`

## Visual Proof

Screenshots captured with mocked API data through the real Vite app:

- `docs/validation/codex-ui-reporting-w6-mission-experience-spine-1536x864.png`
- `docs/validation/codex-ui-reporting-w6-mission-experience-spine-1280x720.png`

Visual review notes:

- 1536x864: the spine renders as a compact cockpit strip above Dashboard.
- 1280x720: the spine stacks into readable `Now`, `Route`, and `Next` rows
  without overlapping text or compressed route cards.
- The style follows the Dashboard blue surface language rather than the older
  black terminal-only Mission Control feel.

## Validation

Passed:

- `cd ui-v2 && npm run build`
  - Vite emitted the existing large chunk warning only.
- `cd ui-v2 && npx eslint src/App.tsx src/components/MissionExperienceSpine.tsx tests/react-v2-critical-paths.spec.ts`
- `cd ui-v2 && npx playwright test tests/react-v2-critical-paths.spec.ts`
  - 20 passed.
- `cd ui-v2 && npm test`
  - 23 passed.
- `python3 -m compileall -q api/app/services/reports.py && . .venv/bin/activate && ruff check api/app/services/reports.py`
- `. .venv/bin/activate && python -m pytest api/tests/test_reports.py`
  - 22 passed.
- `python3 scripts/validate_backlog_tasks.py`

## Scope Boundary

This completes the product-wide mission spine step. It does not claim that
Cinema Mode is fully redesigned or that management-report rewrite rules are
complete. The next Codex-owned report-specific step remains W6B management
report rewrite rules.
