# Active Task

## Title

React v2 Mission Control: three-panel live operations screen with real run data, task output, AI proposals, and phase chain

## Promoted From

`codex/tasks/backlog-269-react-v2-mission-control.json`

## Goal

Implement the active backlog package `codex/tasks/backlog-269-react-v2-mission-control.json` so the new React v2 operator UI has a real-data Mission Control screen built on the completed v2 foundation.

## Scope

Implement the active backlog package `codex/tasks/backlog-269-react-v2-mission-control.json`.

Expected Mission Control slice:

- build `ui-v2/src/components/screens/MissionControl.tsx`
- render three panels: scan map, task/live operations, and AI Signal
- use real run, task, inventory, AI insight/proposal, and phase-chain data from the completed v2 store/API client foundation
- show truthful empty/loading states when no run or no inventory exists
- support approved operator actions through existing API endpoints only
- keep Cinema Mode integration bounded to real store data
- keep existing `/app/` and manual/wizard/backend flows untouched

## Constraints

- Do not implement until this file is the single active task.
- This task depends on completed backlog-268; do not patch old UI modules as a substitute.
- Do not replace Mission Control globally.
- Do not bypass existing backend scope, ROE, approval, runner registry, provenance, report, credential, runtime binding, or kill-switch behavior.
- Do not create runtime self-modification or uncontrolled plugin installation.
- Production UI must use existing icon patterns and no emoji.
- Do not touch `api/`, `workers/`, `ui/`, or `ui-v2/src/components/CinemaMode.tsx` unless repo truth changes.

## Validation

- `python3 scripts/validate_backlog_tasks.py`
- `cd ui-v2 && npm run build`
- `git diff --check`

## Acceptance

- Mission Control renders real selected-run data from the v2 store/API client.
- Task rows render from backend task data and expand to show bounded execution output when available.
- AI proposals render from `GET /api/v1/runs/{runId}/ai-insights` and approve/reject through the existing review endpoint.
- Phase-chain state renders only from real run/chain data.
- Kill Run and Start Queued Checks use existing run cancel/dispatch endpoints.
- Active runs poll boundedly without replacing manual/wizard flows or old `/app/`.
