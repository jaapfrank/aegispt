# backlog-271 React v2 Findings Theater Evidence

Date: 2026-05-07

## Scope

Implemented the React v2 Findings Theater slice only:

- `ui-v2/src/components/screens/FindingsTheater.tsx`
- `ui-v2/src/App.tsx`
- `ui-v2/src/store/index.ts`
- `ui-v2/src/api/client.ts`
- `ui-v2/src/api/types.ts`

No `api/`, `workers/`, or old `ui/` files were changed.

## Product Truth

- `/findings` now renders `FindingsTheater` instead of the placeholder screen.
- Findings list loads from `GET /api/v1/runs/{runId}/findings?theater=true`.
- Clicking a finding stores `selectedFindingId` in the v2 Zustand store and loads:
  - `GET /api/v1/findings/{findingId}/theater`
  - `GET /api/v1/findings/{findingId}/evidence`
- The drawer is evidence-backed from current backend data: summary, CVSS, OWASP mapping, related execution excerpts, artifact SHA-256, AI enrichment, remediation, Jira handoff when configured, and finding-chain context.
- Attack Path UI renders only when `/theater` returns `vulnerability_chains.available=true` with real chain records.
- Operator-facing `Mark as Fixed` sends backend truth `status=resolved`, because the current API schema accepts `resolved` rather than the package's `fixed` wording.
- `Mark as False Positive` sends the required documented reason with `status=false_positive`.

## Runtime Relevance

`http://127.0.0.1:8000` was relevant because React v2 calls live FastAPI endpoints through the Vite proxy. The local inline host was restarted onto the current checkout before acceptance.

For acceptance, a local validation engagement/run was seeded into the existing development database with two findings, a completed `httpx` task, a related evidence artifact, a stored SHA-256, AI enrichment for one finding, and a stored finding-chain record. Browser validation then used the real API endpoints, not mocked UI data.

Validation records:

- engagement: `a716f96c-41a3-4a1d-af84-84bdc81f0362`
- run: `c23cb121-f143-4c64-b4d4-becfa3ab809a`
- findings:
  - `bd0d42bb-97d2-49bb-9427-5257aba2ffef`
  - `798b9c07-e6ed-4b6d-8b49-329237624df3`
- artifact SHA-256: `64a24648c3955acaa5215678adc1f34b9b6df8cbe1fa6911c7f9c7335bb71fd8`

## Playwright Evidence

Structured evidence: `codex/results/backlog-271-react-v2-findings-theater-playwright.json`

Screenshots:

- `codex/results/backlog-271-react-v2-findings-theater-1440.png`
- `codex/results/backlog-271-react-v2-findings-theater-1024.png`
- `codex/results/backlog-271-react-v2-findings-theater-768.png`
- `codex/results/backlog-271-react-v2-findings-theater-375.png`

Acceptance results captured in the JSON:

- real findings GET with `?theater=true`
- real finding theater detail GET
- real finding evidence GET
- drawer opens and closes
- evidence block and SHA-256 render
- AI enrichment renders when available
- provider/connect action renders when enrichment is not available and ChatGPT is not connected
- Attack Path tab renders only from real chain data
- `Mark as Fixed` PATCHes `resolved`
- `Mark as False Positive` PATCHes `false_positive`
- no page errors, console errors, or horizontal overflow across 1440px, 1024px, 768px, and 375px

## Validation

- `python3 scripts/validate_backlog_tasks.py`
- `cd ui-v2 && npm run build`
- `git diff --check`

Final validation after promotion is recorded in `DONE_LOG.md`.
