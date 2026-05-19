# backlog-272 React v2 Report Center Evidence

Date: 2026-05-07

## Scope

Implemented the React v2 Report Center slice only:

- `ui-v2/src/components/screens/ReportCenter.tsx`
- `ui-v2/src/App.tsx`
- `ui-v2/src/api/client.ts`
- `ui-v2/src/api/types.ts`

No `api/`, `workers/`, or old `ui/` files were changed.

## Product Truth

- `/reports` now renders `ReportCenter` instead of the placeholder screen.
- The Reports tab loads selected-run catalog data from `GET /api/v1/runs/{runId}/reports`.
- Report cards select real catalog variants and load Markdown preview through the existing repo-truth report export endpoint:
  - `GET /api/v1/runs/{runId}/report?format=markdown&variant={variant}`
- HTML and PDF downloads use the existing backend export endpoint:
  - `GET /api/v1/runs/{runId}/report?format=html&variant={variant}`
  - `GET /api/v1/runs/{runId}/report?format=pdf&variant={variant}`
- Markdown preview is rendered locally without new external libraries, covering headings, bold text, unordered lists, and fenced code blocks.
- The compare section compares current and earlier selected-engagement findings from real `GET /api/v1/runs/{runId}/findings` responses.
- The Dossier tab uses real selected-engagement and run timeline data from existing APIs.
- Repo truth exception: `/api/v1/engagements/{engId}/dossier` does not exist in the current backend, so the UI documents that fallback instead of making a noisy 404 probe.
- Evidence hash disclosure shows the backend report catalog `content_sha256` and labels it as verified report-content hash.

## Runtime Relevance

`http://127.0.0.1:8000` was relevant because React v2 calls live FastAPI report catalog, report export, run list, and finding list endpoints through the Vite proxy. The local inline host was restarted onto the current checkout before acceptance.

For acceptance, a local validation engagement was seeded into the existing development database with two completed runs, completed `httpx` task evidence, inventory snapshots, evidence artifacts, and current/previous finding deltas.

Validation records:

- engagement: `a412bab7-e93d-4717-a253-def0f598ded6`
- previous run: `c02cbf4f-2252-40c7-b17f-e71e0b23afd9`
- current run: `0b9d6123-078d-4bf5-8074-b3032d4981a3`

## Playwright Evidence

Structured evidence: `codex/results/backlog-272-react-v2-report-center-playwright.json`

Reports screenshots:

- `codex/results/backlog-272-react-v2-report-center-1440.png`
- `codex/results/backlog-272-react-v2-report-center-1024.png`
- `codex/results/backlog-272-react-v2-report-center-768.png`
- `codex/results/backlog-272-react-v2-report-center-375.png`

Dossier screenshots:

- `codex/results/backlog-272-react-v2-report-center-dossier-1440.png`
- `codex/results/backlog-272-react-v2-report-center-dossier-1024.png`
- `codex/results/backlog-272-react-v2-report-center-dossier-768.png`
- `codex/results/backlog-272-react-v2-report-center-dossier-375.png`

Acceptance results captured in the JSON:

- report catalog loaded from real backend data
- report card click loaded Markdown preview
- Generate Markdown Preview rendered formatted markdown
- Download HTML and Download PDF triggered browser downloads
- Compare with Earlier Run rendered a real diff summary
- Dossier tab rendered the engagement timeline from backend run data
- evidence hash disclosure showed a 64-character backend content SHA-256
- Dossier timeline click selected a run and navigated to Mission Control
- no page errors, console errors, or horizontal overflow across 1440px, 1024px, 768px, and 375px

## Validation

- `python3 scripts/validate_backlog_tasks.py`
- `cd ui-v2 && npm run build`
- Playwright browser acceptance against `http://127.0.0.1:5173/reports` with live FastAPI proxy
- `git diff --check`

Final validation after promotion is recorded in `DONE_LOG.md`.
