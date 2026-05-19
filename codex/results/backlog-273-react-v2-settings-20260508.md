# backlog-273 React v2 Settings proof

## Scope

Implemented the React v2 Settings screen as the five-tab configuration surface for:

- AI & Provider
- Tools & Runtime
- Integrations
- Data & Security
- Identity & Users

The screen uses the existing backend contracts only. It does not install tools, dispatch runners, bypass scope/ROE/approval gates, or mutate runtime capabilities outside the settings/auth endpoints.

## Files

- `ui-v2/src/components/screens/Settings.tsx`
- `ui-v2/src/App.tsx`
- `ui-v2/src/api/client.ts`
- `ui-v2/src/api/types.ts`

## Behavior proved

- `/settings` renders the new Settings screen instead of the placeholder route.
- The top summary chips render tenant, selected engagement, model, and actor role.
- All five tabs render on 1440px, 1024px, 768px, and 375px viewports.
- ChatGPT OAuth status refresh calls the real engagement-scoped backend status endpoint.
- ChatGPT OAuth connect calls the real engagement-scoped authorize endpoint and shows an honest backend state without completing external provider login in automation.
- Runtime readiness loads from `GET /api/v1/settings/readiness` and renders capability/tool status rows with expandable details.
- Integration settings save through `PATCH /api/v1/settings`.
- Actor name saves to `localStorage` and updates the Zustand actor state used by `X-Actor`.
- API keys are read from, created through, and revoked through the real auth endpoints.
- Engagement data export calls the real data-export endpoint and produces a JSON download.
- CI/CD and purge controls are deliberately honest/disabled where the current backend Settings contract does not expose a safe direct operation.

## Validation

- `python3 scripts/validate_backlog_tasks.py` passed before implementation with exactly one active task.
- `cd ui-v2 && npm run build` passed.
- `http://127.0.0.1:8000` was relevant for live API validation and was restarted with `AEGISPT_LOCAL_ENSURE_ZAP=0 bash scripts/restart_local_inline_host.sh`.
- Vite dev server ran at `http://127.0.0.1:5173/`.
- Playwright acceptance passed against `http://127.0.0.1:5173/settings`.

## Live API evidence

The browser acceptance observed successful calls including:

- `GET /api/v1/settings`
- `GET /api/v1/settings/readiness`
- `GET /api/v1/auth/chatgpt/status?engagement_id=...`
- `GET /api/v1/auth/chatgpt/authorize?engagement_id=...`
- `GET /api/v1/auth/identity/status`
- `GET /api/v1/auth/keys`
- `POST /api/v1/auth/keys`
- `POST /api/v1/auth/keys/{key_id}/revoke`
- `GET /api/v1/engagements/{engagement_id}/data-export`
- `PATCH /api/v1/settings`

## Browser artifacts

Screenshots and export proof are stored under:

- `codex/results/playwright-backlog-273-settings/settings-1440.png`
- `codex/results/playwright-backlog-273-settings/settings-1024.png`
- `codex/results/playwright-backlog-273-settings/settings-768.png`
- `codex/results/playwright-backlog-273-settings/settings-375.png`
- `codex/results/playwright-backlog-273-settings/settings-1440-after-actions.png`
- `codex/results/playwright-backlog-273-settings/engagement-data-export.json`

## Boundaries

- The Connect ChatGPT control calls the existing authorize flow only when the operator clicks it; full external provider login was not completed in automated acceptance.
- CI/CD webhook and typed purge controls remain read-only/unavailable because repo truth does not expose matching Settings-screen contracts in this slice.
- Old `/app/`, old `ui/`, `api/`, `workers/`, runner registry, approval gates, scope, ROE, credentials, provenance, reports, runtime binding, and kill switch were not changed.
