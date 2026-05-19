# backlog-275 React v2 Cinema Mode Real Data Evidence

Date: 2026-05-08

## Scope

Implemented the active task `codex/tasks/backlog-275-react-v2-cinema-mode-real-data.json`.

Cinema Mode now uses real selected-run data instead of mock targets and mock event streams:

- inventory hosts from the selected run inventory snapshot become deterministic 3D nodes
- finding severity controls node color and finding badges
- task stdout/stderr/snapshot lines are polled through existing run/task APIs
- the bottom HUD shows the actual active tool and target
- the camera follows the active event target node where possible and otherwise orbits the center
- the stats overlay uses real critical/high finding counts, discovered host count, and pending AI proposal count
- no Google Fonts URL or hardcoded event stream remains

## Repo Truth Notes

- `http://127.0.0.1:8000` was relevant because the v2 UI validates through the Vite proxy against live FastAPI run, task, inventory, finding, and AI-insight endpoints.
- A narrow exception was required outside `CinemaMode.tsx`: Mission Control had to open the actual Cinema component instead of the previous guard, otherwise the acceptance criterion "Cinema Mode opens" could not be satisfied.
- The existing React Three dependencies were React 19-oriented and crashed under the current React 18 app with `Cannot read properties of undefined (reading 'S')`; they were pinned to React 18-compatible versions.
- Troika/Drei text rendering in the pinned stack does not accept WOFF2 directly for 3D glyph parsing. The required `ui-v2/public/fonts/FiraMono.woff2` is present and used by a local `@font-face` for the Cinema HUD, while 3D Text uses a local Fira Mono TTF to avoid runtime font parsing errors. No external font request is made.

## Behavior Proof

- Live selected run with inventory rendered a nonblank WebGL canvas and real node/stat HUD.
- Live run/task polling observed existing `/api/v1/runs/{id}` and `/api/v1/tasks/{id}` responses.
- No-inventory fallback was browser-tested against a run without inventory; the overlay showed `HOSTS 0` instead of fake nodes.
- The previous mock strings, `TARGETS`, `EVENT_STREAM`, and `fonts.gstatic.com` references are absent from the touched Cinema source.

## Validation

- `python3 scripts/validate_backlog_tasks.py` passed before implementation with exactly one active task.
- Prerequisite check passed: backlog-268 and backlog-269 are present in `DONE_LOG.md`.
- `cd ui-v2 && npm run build` passed with no TypeScript errors. Vite emitted only chunk-size warnings.
- `AEGISPT_LOCAL_ENSURE_ZAP=0 bash scripts/restart_local_inline_host.sh` restarted the local FastAPI host.
- Playwright browser acceptance ran against `http://127.0.0.1:5173/mission-control` with proxy to `http://127.0.0.1:8000`.
- Cinema Mode was opened and closed on 1440px, 1024px, 768px, and 375px.
- Canvas pixel checks passed on every viewport:
  - 1440px: 1,295,642 non-background canvas pixels
  - 1024px: 786,432 non-background canvas pixels
  - 768px: 691,200 non-background canvas pixels
  - 375px: 304,500 non-background canvas pixels
- API evidence observed 9 task-detail calls and 119 run-scoped calls during Cinema validation.
- External font requests: 0
- Console errors: 0
- Page errors: 0
- Horizontal overflow: none

## Artifacts

Screenshots are stored under `codex/results/playwright-backlog-275-cinema/`:

- `backlog-275-cinema-1440.png`
- `backlog-275-cinema-1024.png`
- `backlog-275-cinema-768.png`
- `backlog-275-cinema-375.png`
- `backlog-275-cinema-canvas-1440.png`
- `backlog-275-cinema-canvas-1024.png`
- `backlog-275-cinema-canvas-768.png`
- `backlog-275-cinema-canvas-375.png`
- `backlog-275-cinema-no-inventory-fallback.png`

## Boundaries

- No backend routes, workers, runner registry, approval gates, scope/ROE handling, credentials, runtime binding, report generation, provenance model, or kill switch behavior were changed.
- Cinema Mode reads and visualizes stored run data only; it does not execute tools or mutate runtime state.
