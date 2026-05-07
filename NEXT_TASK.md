# Active Task

## Title

React v2 Findings Theater: two-column list + slide-in drawer with evidence, AI enrichment, CVSS, OWASP, and attack path tab

## Promoted From

`codex/tasks/backlog-271-react-v2-findings-theater.json`

## Goal

Implement the active backlog package `codex/tasks/backlog-271-react-v2-findings-theater.json` so the React v2 Findings Theater loads real findings from the backend and presents evidence-backed details in a two-column list plus slide-in drawer.

## Scope

Implement the active backlog package `codex/tasks/backlog-271-react-v2-findings-theater.json`.

Expected React v2 Findings Theater slice:

- build `ui-v2/src/components/screens/FindingsTheater.tsx`
- load findings from `GET /api/v1/runs/{runId}/findings?theater=true`
- provide severity, status, and search filters
- group findings by severity in the list
- open a Framer Motion slide-in detail drawer when a finding is selected
- show summary, CVSS, OWASP category, technical evidence, SHA-256 hash, AI enrichment, remediation actions, integration entry points, and attack path data only when backed by real finding/reasoning records
- PATCH finding status for fixed and false-positive actions through existing backend endpoints

## Constraints

- Do not implement until this file is the single active task.
- This task depends on completed backlog-268.
- Work only in the React v2 Findings Theater scope.
- Do not touch `api/`, `workers/`, or old `ui/`.
- Do not bypass existing backend scope, ROE, approval, runner registry, provenance, report, credential, runtime binding, or kill-switch behavior.
- Do not create runtime self-modification or uncontrolled plugin installation.
- Production UI must use existing icon patterns and no emoji.
- Attack path UI must only appear when backed by real `compound_chain_id` / AgentReasoning-style data; no fake chains.
- Narrative or enrichment text must remain evidence-backed and must not invent findings.

## Validation

- `python3 scripts/validate_backlog_tasks.py`
- `cd ui-v2 && npm run build`
- `git diff --check`

## Acceptance

- Findings list renders from the real API.
- Filter bar filters by severity and status.
- Clicking a finding opens a slide-in drawer.
- Drawer displays raw evidence in a monospace block with hash.
- AI enrichment is shown when available, or the correct provider/connect action is shown when not.
- Mark as Fixed and Mark as False Positive actions PATCH the finding through existing APIs.
- Attack path tab is shown only when real compound-chain data exists.
- Drawer closes with the close button.
- Build passes with no TypeScript errors.
