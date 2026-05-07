# Active Task

## Title

React v2 Report Center: run selector, adaptive report catalog, markdown/HTML/PDF preview, and download actions

## Promoted From

`codex/tasks/backlog-272-react-v2-report-center.json`

## Goal

Implement the active backlog package `codex/tasks/backlog-272-react-v2-report-center.json` so the React v2 Report Center loads real report catalog data, previews, downloads, comparison context, and dossier timeline from existing backend APIs.

## Scope

Implement the active backlog package `codex/tasks/backlog-272-react-v2-report-center.json`.

Expected React v2 Report Center slice:

- build `ui-v2/src/components/screens/ReportCenter.tsx`
- provide top-level `Reports` and `Dossier` tabs
- show selected-run strip with profile, date, and status
- load available reports from `GET /api/v1/runs/{runId}/reports`
- render report cards with icon, title, availability status, and short description
- select a report and load/generate preview through existing report endpoints
- provide Markdown preview, HTML download, and PDF download actions
- render markdown preview with a small local renderer, without adding external libraries
- compare the selected run with earlier runs for the same engagement
- load dossier data from `GET /api/v1/engagements/{engId}/dossier` where available, or document repo-truth fallback if the endpoint does not exist
- show evidence hash in a collapsed disclosure when the backend exposes it

## Constraints

- Do not implement until this file is the single active task.
- This task depends on completed backlog-268.
- Work only in the React v2 Report Center scope.
- Do not touch `api/`, `workers/`, or old `ui/`.
- Do not bypass existing backend scope, ROE, approval, runner registry, provenance, report, credential, runtime binding, or kill-switch behavior.
- Do not create runtime self-modification or uncontrolled plugin installation.
- Production UI must use existing icon patterns and no emoji.
- Reports and narratives must stay evidence-backed and must not invent findings, coverage, or certification claims.

## Validation

- `python3 scripts/validate_backlog_tasks.py`
- `cd ui-v2 && npm run build`
- `git diff --check`

## Acceptance

- Report catalog loads from real backend data.
- Clicking a report card loads a preview.
- Generate Markdown Preview shows formatted markdown.
- Download HTML and PDF trigger file downloads or honest backend unavailable states.
- Compare with Earlier Run shows a real diff summary.
- Dossier tab shows engagement timeline from backend data.
- Evidence hash is shown in a collapsed disclosure when available.
- Build passes with no TypeScript errors.
