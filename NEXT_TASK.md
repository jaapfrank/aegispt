# Active Task

## Title

React v2 Living Intake Wizard: Split-path wizard with modern 3D card flips and mission launch ceremony

## Promoted From

`codex/tasks/backlog-277-react-v2-living-intake-wizard.json`

## Goal

Implement the active backlog package `codex/tasks/backlog-277-react-v2-living-intake-wizard.json` so the React v2 Intake screen becomes a living split-path intake experience while preserving the existing backend mission submission logic.

## Scope

Implement the active backlog package `codex/tasks/backlog-277-react-v2-living-intake-wizard.json`.

Expected React v2 intake slice:

- show a clear split between conversational AI intake and visual tile wizard
- use tactile 3D CSS card flip feedback for assessment type selection
- add the full-screen mission launch ceremony when the wizard submits
- keep transition into Mission Control seamless and animated
- preserve the existing real engagement/run creation and authorization flow

## Constraints

- Do not implement until this file is the single active task.
- This task depends on completed backlog-270.
- Work only in the React v2 Intake visual presentation and transition scope.
- Do not change underlying backend submission logic.
- Do not touch `api/app/routers/runs.py` or `workers/`.
- Do not bypass existing backend scope, ROE, approval, runner registry, provenance, report, credential, runtime binding, or kill-switch behavior.
- Do not create runtime self-modification or uncontrolled plugin installation.
- Production UI must use existing icon patterns and no emoji.

## Validation

- `cd ui-v2 && npm run build`
- `python3 scripts/validate_backlog_tasks.py`
- `git diff --check`

## Acceptance

- Intake shows a clear split between AI chat and visual tiles.
- Clicking an assessment type tile performs a 3D flip animation.
- Submitting the wizard triggers the full-screen deploying overlay.
- Transition to Mission Control is seamless and animated.
