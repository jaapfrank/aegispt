# Backlog 276 - React v2 Deployment FastAPI Serve

Date: 2026-05-08

## Scope

Completed the React v2 deployment slice so the built React app is served by the existing FastAPI process at `/app-v2/` while the classic UI remains reachable at `/app/`.

## Implementation

- Added `scripts/build_ui_v2.sh` as the repo-local React v2 build entrypoint.
- Updated `ui-v2/vite.config.ts` with `base: '/app-v2/'` so built assets resolve correctly from the FastAPI subpath.
- Set React Router `BrowserRouter` basename to `/app-v2` so direct routes such as `/app-v2/findings` resolve inside the v2 app.
- Added a FastAPI React static-file mount at `/app-v2`, a `/app-v2/health` endpoint, and a React Router fallback through a `ReactAppStaticFiles` subclass.
- Preserved `/app/` classic UI static serving unchanged.
- Added redirects from the previous development `/v2` path to `/app-v2/` to avoid stranding old local links after the base-path change.
- Added a classic topbar link to `/app-v2/` and a React v2 topbar link back to `/app/`.
- Aligned React v2 actor initialization with the classic localStorage key `aegispt-actor`, while continuing to write the earlier v2 compatibility key.
- Updated `scripts/run_ui_fast_tests.sh` so the fast UI test lane builds React v2 before running the legacy fast Playwright suite.

## Validation

- `python3 scripts/validate_backlog_tasks.py` passed before implementation.
- `cd ui-v2 && npm run build` passed with no TypeScript errors.
- `bash scripts/build_ui_v2.sh` passed with no TypeScript errors.
- `source .venv/bin/activate && python -m pytest api/tests/test_health.py -q` passed.
- `curl -s http://127.0.0.1:8000/app-v2/ | grep -c 'AegisPT'` returned `1`.
- `curl -s http://127.0.0.1:8000/app-v2/health` returned `{"status":"ok","version":"v2"}`.
- `curl http://127.0.0.1:8000/app-v2/findings` returned HTTP 200 text/html and contained `AegisPT`.
- Playwright acceptance against `http://127.0.0.1:8000` covered 1440px, 1024px, 768px, and 375px:
  - `/app/` classic UI exposed `switch-to-v2-ui`.
  - `/app-v2/` React UI exposed `switch-to-classic-ui`.
  - `/app-v2/findings` loaded directly through FastAPI and React Router.
  - `aegispt-actor=deployment-operator` was read by React v2 after switching from classic.
  - no horizontal overflow was detected on the four viewports.
- After the final FastAPI restart, a focused Playwright check confirmed `/app-v2/findings` still loads directly at 375px and `/v2/findings` redirects to `/app-v2/findings`.
- `git diff --check` passed.

## Evidence

- Browser screenshots:
  - `codex/results/playwright-backlog-276-app-v2/classic-1440.png`
  - `codex/results/playwright-backlog-276-app-v2/classic-1024.png`
  - `codex/results/playwright-backlog-276-app-v2/classic-768.png`
  - `codex/results/playwright-backlog-276-app-v2/classic-375.png`
  - `codex/results/playwright-backlog-276-app-v2/app-v2-1440.png`
  - `codex/results/playwright-backlog-276-app-v2/app-v2-1024.png`
  - `codex/results/playwright-backlog-276-app-v2/app-v2-768.png`
  - `codex/results/playwright-backlog-276-app-v2/app-v2-375.png`

## Notes

- The classic UI currently reloads actor display from backend operator settings in some flows; this task validates and aligns the shared localStorage contract (`aegispt-actor`) rather than changing classic Settings behavior.
- Vite still emits the existing chunk-size warning for the large app/Cinema chunks; this is not a TypeScript or serving failure.
