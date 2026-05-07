# backlog-269 React v2 Mission Control

Date: 2026-05-07

## Scope

Implemented the React v2 Mission Control screen from `codex/tasks/backlog-269-react-v2-mission-control.json`.

## Behavior

- `ui-v2/src/components/screens/MissionControl.tsx` now renders a three-panel operations layout from real v2 store/API state.
- Selected run, task rows, findings, inventory scan map, AI proposals, and assessment-chain phase state are read from existing backend endpoints.
- Active runs poll every 3 seconds through bounded `GET /api/v1/runs/{run_id}` refreshes.
- Task rows expand and fetch bounded execution output from `GET /api/v1/tasks/{task_id}`.
- AI proposals are reviewed through `POST /api/v1/runs/{run_id}/ai-proposals/{proposal_id}/review`.
- `Kill Run` and `Start Queued Checks` call the existing cancel/dispatch endpoints.
- Phase approval uses the existing assessment-chain decision endpoint.
- The old `/app/`, old `ui/`, `api/`, `workers/`, and `ui-v2/src/components/CinemaMode.tsx` were not changed.

## Real Backend Acceptance

`http://127.0.0.1:8000` was relevant and reachable. The current live backend returned a selected running run with:

- run id: `ef952159-2c93-4da7-ac3e-8574fde0bc52`
- profile: `passive-easm-discovery`
- task: `easm-discover`
- task stale recovery: `eligible=true`, `has_execution_evidence=false`
- assessment chain: `FULL-EXTERNAL-WEB`, phase `passive-surface`

Mission Control renders that stale EASM state as backend truth; this task did not alter backend routing/runtime behavior.

## Browser Evidence

Playwright acceptance ran through the Vite dev server at `http://127.0.0.1:5173/mission-control` against the live backend proxy on the required viewports.

Screenshots:

- `codex/results/backlog-269-react-v2-mission-control-1440.png`
- `codex/results/backlog-269-react-v2-mission-control-1024.png`
- `codex/results/backlog-269-react-v2-mission-control-768.png`
- `codex/results/backlog-269-react-v2-mission-control-375.png`

Structured browser evidence:

- `codex/results/backlog-269-react-v2-mission-control-playwright.json`

All four viewport checks verified:

- Mission Control heading visible
- real backend run-data copy visible
- Task Output panel visible
- AI Proposals panel visible
- Phase Chain panel visible
- Scan Map panel visible
- backend `easm-discover` task row expandable
- Cinema Mode real-data guard visible
- no page errors or browser console errors

## Validation

- `python3 scripts/validate_backlog_tasks.py` passed before implementation.
- prerequisite check passed: `REQUIRES: backlog-268 completed first.` is satisfied in `DONE_LOG.md`.
- `cd ui-v2 && npm run build` passed.
- Playwright browser acceptance passed on 1440px, 1024px, 768px, and 375px.
- Final post-documentation checks are recorded in `DONE_LOG.md`.

## Exception

The task text asks for Cinema Mode integration but also forbids touching `ui-v2/src/components/CinemaMode.tsx`. Repo truth shows that component still uses mock targets and mock event streams. To comply with the no-fake-chain rule, Mission Control does not open that mock 3D view as run evidence; it opens a guarded real-data notice instead. Existing risk tracking remains in `risico.md` R-017 and `extra_tests.md` XT-020.
