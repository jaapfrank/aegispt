# Active Task

## Title

React v2 deployment: build React app and serve from FastAPI at /app-v2/ alongside existing /app/ — gradual migration path

## Promoted From

`codex/tasks/backlog-276-react-v2-deployment-fastapi-serve.json`

## Goal

Implement the active backlog package `codex/tasks/backlog-276-react-v2-deployment-fastapi-serve.json` so React v2 is built and served by FastAPI at `/app-v2/` while the existing classic UI remains available at `/app/`.

## Scope

Implement the active backlog package `codex/tasks/backlog-276-react-v2-deployment-fastapi-serve.json`.

Expected React v2 deployment slice:

- add a build script for `ui-v2`
- configure Vite for `/app-v2/` asset paths
- serve the built React app from FastAPI at `/app-v2/`
- keep the existing `/app/` classic UI unchanged and reachable
- add UI switcher links between classic and v2
- preserve shared local actor identity between both UIs where current repo truth supports it

## Constraints

- Do not implement until this file is the single active task.
- This task depends on completed backlog-268 through backlog-275.
- Work only in the React v2 deployment scope.
- Do not remove, break, or replace the existing `/app/` route or old vanilla JS UI.
- Do not touch `ui/assets/`, `api/app/routers/`, or `workers/` unless repo truth makes a narrow deployment-only exception unavoidable; document any exception before implementation.
- Do not bypass existing backend scope, ROE, approval, runner registry, provenance, report, credential, runtime binding, or kill-switch behavior.
- Do not create runtime self-modification or uncontrolled plugin installation.
- Production UI must use existing icon patterns and no emoji.

## Validation

- `python3 scripts/validate_backlog_tasks.py`
- `cd ui-v2 && npm run build`
- `source .venv/bin/activate && python -m pytest api/tests/test_health.py -q`
- `curl -s http://127.0.0.1:8000/app-v2/ | grep -c 'AegisPT'`
- `git diff --check`

## Acceptance

- `/app-v2/` serves the React v2 app from FastAPI.
- Direct route load such as `/app-v2/findings` works for React Router.
- `/app/` still serves the existing classic UI.
- Both UIs expose switcher links.
- Actor name persists between UI switches where current localStorage contract supports it.
- Build passes with no TypeScript errors.
