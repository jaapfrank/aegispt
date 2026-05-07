# Active Task

## Title

React v2 Settings: five-tab navigation with AI & Provider, Tools & Runtime, Integrations, Data & Security, Identity & Users panels

## Promoted From

`codex/tasks/backlog-273-react-v2-settings.json`

## Goal

Implement the active backlog package `codex/tasks/backlog-273-react-v2-settings.json` so the React v2 Settings screen exposes the five-tab configuration surface with real API calls and collapsed summaries.

## Scope

Implement the active backlog package `codex/tasks/backlog-273-react-v2-settings.json`.

Expected React v2 Settings slice:

- build `ui-v2/src/components/screens/Settings.tsx`
- provide top summary chips for tenant, selected engagement, model, and actor role
- provide five tabs:
  - `AI & Provider`
  - `Tools & Runtime`
  - `Integrations`
  - `Data & Security`
  - `Identity & Users`
- load ChatGPT OAuth status and provider settings from existing backend APIs where available
- load runtime readiness from `GET /api/v1/settings/readiness`
- render readiness rows with ready/degraded/blocked states and expandable details
- render integration/data/security/identity sections with collapsed one-line summaries
- save settings through existing settings APIs where available
- persist actor name to local storage and the v2 Zustand store so `X-Actor` continues to reflect operator identity
- keep disabled/unavailable states honest when backend APIs are not present or not configured

## Constraints

- Do not implement until this file is the single active task.
- This task depends on completed backlog-268.
- Work only in the React v2 Settings screen scope.
- Do not touch `api/`, `workers/`, or old `ui/`.
- Do not bypass existing backend scope, ROE, approval, runner registry, provenance, report, credential, runtime binding, or kill-switch behavior.
- Do not create runtime self-modification or uncontrolled plugin installation.
- Production UI must use existing icon patterns and no emoji.
- Settings writes must use existing backend settings contracts and must not silently install, enable, or run capabilities.

## Validation

- `python3 scripts/validate_backlog_tasks.py`
- `cd ui-v2 && npm run build`
- `git diff --check`

## Acceptance

- Five tabs render.
- Collapsed sections show current value summaries.
- ChatGPT OAuth status and connect/refresh actions use real backend states or honest unavailable states.
- Runtime readiness loads from `GET /api/v1/settings/readiness`.
- Integration/settings forms save through existing settings APIs where available.
- Actor name persists to local storage and updates the Zustand store.
- API key surfaces use real backend states or honest unavailable states.
- Build passes with no TypeScript errors.
