# Codex UI/Reporting M3 - API Domain Clients

Date: 2026-06-03
Owner: Codex

## Scope

Split the React v2 API client into domain clients without changing existing
screen imports or API behavior.

## Changes

- Kept `ui-v2/src/api/client.ts` as a compatibility barrel for existing screen
  imports.
- Added `ui-v2/src/api/transport.ts` for `api`, `apiBlob`, `ApiError`,
  base-url handling, actor headers, and tenant headers.
- Split domain functions into:
  - `engagements.ts`
  - `runs.ts`
  - `findings.ts`
  - `reports.ts`
  - `inventory.ts`
  - `settings.ts`
  - `schedules.ts`
  - `problems.ts`
  - `packs.ts`
  - `customVulnerabilities.ts`
  - `research.ts`
  - `deception.ts`

## Behavior Proof

- `cd ui-v2 && npx eslint src/api/client.ts src/api/transport.ts src/api/engagements.ts src/api/runs.ts src/api/findings.ts src/api/reports.ts src/api/inventory.ts src/api/settings.ts src/api/schedules.ts src/api/problems.ts src/api/packs.ts src/api/customVulnerabilities.ts src/api/research.ts src/api/deception.ts`
- `cd ui-v2 && npx tsc -b --pretty false`
- `cd ui-v2 && npx playwright test tests/i18n.spec.ts` (3 passed)
- `cd ui-v2 && npx playwright test tests/react-v2-critical-paths.spec.ts --grep "All primary React v2 screens render non-empty content|Report Center shows canonical report truth|Evidence Replay uses assessment-chain tasks|Findings Theater filters findings|Mission experience spine carries"` (5 passed)
- `cd ui-v2 && npm test` (27 passed, including i18n key parity)
- `cd ui-v2 && npm run build` (passed; existing Vite chunk-size warning remains)
- `python3 scripts/validate_backlog_tasks.py`
- `git diff --check`

## Non-Overlap

No Claude score-lane files, `NEXT_TASK.md`, `TASK_QUEUE.md`,
assessment-loop/runtime files, worker runner files, scoring code, or active
XBEN validation artifacts were changed by this M3 slice.
