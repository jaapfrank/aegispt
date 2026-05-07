# Active Task

## Title

React v2 Intake: connect existing chat UI and wizard to real backend — AI Intake calls wizard API, Manual Wizard calls existing assessment tile flow, both create real missions

## Promoted From

`codex/tasks/backlog-270-react-v2-intake-wizard.json`

## Goal

Implement the active backlog package `codex/tasks/backlog-270-react-v2-intake-wizard.json` so the React v2 intake screen creates real engagements, scopes, inventory snapshots, and runs through the existing backend APIs.

## Scope

Implement the active backlog package `codex/tasks/backlog-270-react-v2-intake-wizard.json`.

Expected React v2 Intake slice:

- wire AI Intake mode in `ui-v2/src/components/Intake.tsx` to the real backend interpretation endpoint
- create an engagement first when none exists
- update the shared Mission Profile sidebar from extracted assessment type, targets, depth, and safety fields
- enable `Confirm & Launch Mission` only after required fields are confirmed
- on confirm, call existing scope, inventory, and run creation APIs, then navigate to `/mission-control` with the real run selected
- replace the placeholder manual wizard mode with the existing tile-based assessment/depth/preview/authorization flow
- enforce the written-authorization checkbox before mission creation
- persist selected intake mode in localStorage

## Constraints

- Do not implement until this file is the single active task.
- This task depends on completed backlog-268.
- Work only in the React v2 intake scope.
- Do not touch `api/`, `workers/`, or old `ui/`.
- Do not bypass existing backend scope, ROE, approval, runner registry, provenance, report, credential, runtime binding, or kill-switch behavior.
- Do not create runtime self-modification or uncontrolled plugin installation.
- Production UI must use existing icon patterns and no emoji.

## Validation

- `python3 scripts/validate_backlog_tasks.py`
- `cd ui-v2 && npm run build`
- `git diff --check`

## Acceptance

- AI mode calls the real backend for interpretation responses.
- Engagement is created on first message if none exists.
- Mission Profile sidebar reflects real extracted data.
- Confirm button creates real engagement, scope, inventory, and run via API.
- On success, Intake navigates to `/mission-control` with the run selected.
- Manual wizard shows all 13 assessment tiles with correct data.
- Tile grid to target input to preview to authorization checkbox to mission creation works end to end.
- Authorization checkbox is required before mission creation.
- Build passes with no TypeScript errors.
