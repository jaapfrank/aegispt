# Active Task

## Title

React v2 foundation: Zustand store, typed API client, React Router v6, and actor header injection

## Promoted From

`codex/tasks/backlog-268-react-v2-foundation-store-api-routing.json`

## Goal

Implement the active backlog package `codex/tasks/backlog-268-react-v2-foundation-store-api-routing.json` so the new React v2 operator UI has a production-ready frontend foundation before any screen-specific work continues.

## Scope

Implement the active backlog package `codex/tasks/backlog-268-react-v2-foundation-store-api-routing.json`.

Expected foundation slice:

- install and wire Zustand for global app state
- install and wire React Router v6 for new v2 routes
- create typed API client functions for existing FastAPI endpoints used by upcoming v2 screens
- inject `X-Actor` from the frontend store on API requests
- bootstrap engagements/runs from the backend without mock mission data becoming product truth
- configure Vite proxy for `/api/*` to `http://127.0.0.1:8000`
- keep existing `/app/` and manual/wizard/backend flows untouched

## Constraints

- Do not implement until this file is the single active task.
- This task starts the new `ui-v2` foundation; do not patch old UI modules as a substitute.
- Do not replace Mission Control globally.
- Do not bypass existing backend scope, ROE, approval, runner registry, provenance, report, credential, runtime binding, or kill-switch behavior.
- Do not create runtime self-modification or uncontrolled plugin installation.
- Production UI must use existing icon patterns and no emoji.

## Validation

- `python3 scripts/validate_backlog_tasks.py`
- `cd ui-v2 && npm run build`
- `cd ui-v2 && npm run lint`
- `git diff --check`

## Acceptance

- React v2 routes work through React Router without breaking current `/app/`.
- Global store persists selected actor, engagement, selected run, and loading/error state.
- API client calls existing backend endpoints through `/api/v1/*` with `X-Actor`.
- Vite dev proxy targets `http://127.0.0.1:8000`.
- Mock-only mission state is clearly separated from real backend bootstrap.
- No old UI task is promoted ahead of the v2 foundation.
