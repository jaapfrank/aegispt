# backlog-270 React v2 Intake Wizard Evidence

Date: 2026-05-07

## Scope

Implemented the React v2 intake slice only:

- `ui-v2/src/components/Intake.tsx`
- `ui-v2/src/components/wizard/AssessmentTiles.tsx`
- `ui-v2/src/api/client.ts`
- `ui-v2/src/api/types.ts`

No `api/`, `workers/`, or old `ui/` files were changed.

## Product Truth

- AI Intake now calls the real backend intake interpretation endpoint: `POST /api/v1/intake/interpretation`.
- If no engagement exists, the first AI answer creates a real engagement through `POST /api/v1/engagements`.
- Confirming the mission creates real scope, inventory, and run records through the existing backend APIs.
- Manual Wizard is now tile based with 13 assessment tiles, target/depth selection, preview, written authorization checkbox, and real mission creation.
- Intake mode persists in `localStorage` as `aegispt-v2-intake-mode`.
- Written authorization is required before launch in both AI and Manual paths.
- The live backend's ChatGPT intake provider was disabled during acceptance; the UI still called the real endpoint and displayed backend failure/disabled truth while using operator-confirmed deterministic mission fields.

## Runtime Relevance

`http://127.0.0.1:8000` was relevant because Vite proxies React v2 API calls to the FastAPI backend. The running host was restarted onto the current checkout before browser acceptance. Direct endpoint proof:

- `GET /api/v1/engagements` returned HTTP 200.
- `POST /api/v1/intake/interpretation` returned HTTP 200 with provider-disabled backend truth.

## Playwright Evidence

Structured evidence: `codex/results/backlog-270-react-v2-intake-wizard-playwright.json`

Screenshots:

- `codex/results/backlog-270-react-v2-intake-wizard-ai-1440.png`
- `codex/results/backlog-270-react-v2-intake-wizard-manual-1024.png`
- `codex/results/backlog-270-react-v2-intake-wizard-1440.png`
- `codex/results/backlog-270-react-v2-intake-wizard-768.png`
- `codex/results/backlog-270-react-v2-intake-wizard-375.png`

Acceptance results captured in the JSON:

- AI flow forced an empty engagement list, then proved real engagement creation, 4 real backend interpretation calls, real scope creation, real inventory creation, real run creation, Mission Control navigation, run profile visibility, and no horizontal overflow at 1440px.
- Manual flow proved real scope creation, real inventory creation, real run creation, Mission Control navigation, authorization-gated launch, and no horizontal overflow at 1024px.
- Responsive manual-grid validation passed at 1440px, 768px, and 375px with visible assessment tiles, no console/page errors, and no horizontal overflow.

## Validation

- `python3 scripts/validate_backlog_tasks.py`
- `cd ui-v2 && npm run build`
- `git diff --check`

Final validation after promotion is recorded in `DONE_LOG.md`.

## Boundaries

- Existing manual/backend flows remain intact; this slice only implements React v2 Intake.
- AI only plans/interprets intake text through the existing backend boundary; execution still uses existing scope, inventory, run, approval, provenance, runner registry, and kill-switch flows.
- Operator-facing copy avoids credential/RCE/exploitation phrasing outside ROE/tier context.
