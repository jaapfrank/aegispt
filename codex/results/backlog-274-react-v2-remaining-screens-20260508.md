# backlog-274 React v2 Remaining Screens Evidence

Date: 2026-05-08

## Scope

Implemented the active task `codex/tasks/backlog-274-react-v2-remaining-screens.json`.

React v2 now exposes real-data screens for:

- Dashboard
- History
- Problems Center
- Surface Map
- Packs
- Evidence Replay
- Custom CVE Library
- Research

Only `ui-v2/` frontend source and task governance documents were changed. No `api/`, `workers/`, or old `ui/` files were modified.

## Repo Truth Notes

- `http://127.0.0.1:8000` was relevant because the React v2 app validates through the Vite proxy against live FastAPI endpoints.
- The task package mentioned some endpoint names that are not current repo truth:
  - no global `GET /api/v1/runs`; History uses existing engagement-scoped run endpoints through `getPortfolioRuns()`.
  - no `GET /api/v1/engagements/{id}/inventory/latest`; Surface Map reads the existing inventory list endpoint and selects the latest returned snapshot.
  - no global `GET /api/v1/packs`; Packs uses the existing engagement-scoped pack endpoint.
- Missing/unavailable backend states are rendered honestly; no fake chains or mock data were added.

## Behavior Proof

- Dashboard reads `GET /api/v1/dashboard` and existing engagement/run/finding state.
- History lists portfolio runs from real engagement-scoped run endpoints, filters locally, and exposes an explicit Compare action.
- Problems Center reads `GET /api/v1/problems` and wires bulk lifecycle actions to `PATCH /api/v1/problems/bulk`.
- Surface Map renders stored inventory hosts/services/endpoints from engagement inventory snapshots.
- Packs lists engagement capability packs, artifacts, and lifecycle actions through existing pack APIs.
- Evidence Replay loads real runs, task details, stdout/stderr, and artifact references.
- Custom CVE Library uses real list/create/update/delete/import/export endpoints; live acceptance created, edited, and soft-deleted an acceptance definition.
- Research calls the existing AI research lab and generation endpoints and marks results as review-only pack lifecycle artifacts.

## Validation

- `python3 scripts/validate_backlog_tasks.py` passed before implementation with exactly one active task.
- Prerequisite check passed: backlog-268 through backlog-273 are present in `DONE_LOG.md`.
- `cd ui-v2 && npm run build` passed with no TypeScript errors. Vite emitted only the existing chunk-size warning.
- `AEGISPT_LOCAL_ENSURE_ZAP=0 bash scripts/restart_local_inline_host.sh` restarted the local FastAPI host.
- Playwright browser acceptance ran against `http://127.0.0.1:5173` with Vite proxy to `http://127.0.0.1:8000`.
- Playwright covered all eight routes on 1440px, 1024px, 768px, and 375px:
  - routes tested: 32
  - API responses observed: 836
  - API 5xx responses: 0
  - horizontal overflow: none
  - console errors: none
- Playwright also proved the History Compare control, Custom CVE create/edit/delete, and Research generation control wiring.

## Boundaries

- No backend behavior was changed.
- No runner registry, approval gate, pack validation/deployment, scope, ROE, credential handling, provenance, reports, runtime binding, or kill switch behavior was bypassed.
- Pack validate/approve/deploy and Problems bulk mutation controls were wired but not exercised in live acceptance to avoid unintended lifecycle changes in the shared local dataset; they are tracked in `extra_tests.md`.
