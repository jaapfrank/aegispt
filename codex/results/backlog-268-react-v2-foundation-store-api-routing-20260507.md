# backlog-268 React v2 foundation evidence

Date: 2026-05-07

## Scope

Implemented the React v2 foundation only:

- Zustand global store in `ui-v2/src/store/index.ts`
- typed API client and response/input types in `ui-v2/src/api/`
- React Router v6 route shell in `ui-v2/src/App.tsx` and `ui-v2/src/main.tsx`
- actor and tenant header injection for API requests
- backend bootstrap for engagements, runs, findings, inventory, AI insights, and settings
- Vite development proxy for `/api/*` to `http://127.0.0.1:8000`

No old `ui/`, backend, worker, runner, scope, ROE, approval, provenance, report, credential, runtime binding, or kill-switch path was changed.

## Validation

- `python3 scripts/validate_backlog_tasks.py` passed before implementation with exactly one active task.
- `cd ui-v2 && npm run build` passed.
- `cd ui-v2 && npm run lint` passed.
- `curl -sS -o /tmp/aegispt-health.txt -w '%{http_code}' http://127.0.0.1:8000/health/live` returned `200`.
- `curl -sS -o /tmp/aegispt-v2-proxy.json -w '%{http_code}' -H 'X-Actor: operator-ui' http://127.0.0.1:5173/api/v1/engagements` returned `200`, proving the Vite proxy path reached the backend.
- Playwright acceptance against `http://127.0.0.1:5173` passed on 1440px, 1024px, 768px, and 375px.
- Playwright captured 88 API requests and verified `X-Actor: operator-ui` plus `X-Tenant-ID: tenant-a` after engagement selection.
- Playwright also loaded the same route shell against the live local backend through the Vite proxy on 1440px, 1024px, 768px, and 375px with no horizontal overflow.

## Browser Proof

Screenshots:

- `codex/results/backlog-268-react-v2-foundation-1440.png`
- `codex/results/backlog-268-react-v2-foundation-1024.png`
- `codex/results/backlog-268-react-v2-foundation-768.png`
- `codex/results/backlog-268-react-v2-foundation-375.png`
- `codex/results/backlog-268-react-v2-foundation-live-1440.png`
- `codex/results/backlog-268-react-v2-foundation-live-1024.png`
- `codex/results/backlog-268-react-v2-foundation-live-768.png`
- `codex/results/backlog-268-react-v2-foundation-live-375.png`

The browser proof used mocked API payloads for deterministic route/header acceptance, then repeated route-shell acceptance through the Vite proxy against the live local backend on port 8000.

## Notes

- `npm install zustand react-router-dom` initially hit an existing peer dependency conflict: the scaffold has React 18 while `@react-three/drei@10.7.7` declares React 19 peer requirements. The dependency add was completed with `--legacy-peer-deps`, matching the existing scaffold's workable install state.
- The app initially crashed in-browser because the existing `CinemaMode.tsx` imported React Three dependencies eagerly. The foundation now lazy-loads Cinema Mode so unopened 3D code cannot block React Router/bootstrap.
- `npm audit --omit=dev --json` reported zero production dependency vulnerabilities.
- The Vite build reports only the existing large-chunk warning from 3D/cinema dependencies.
