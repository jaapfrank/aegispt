# Active Task

## Title

React v2 remaining screens: Dashboard, History, Problems Center, Surface Map, Packs, Evidence Replay, Custom CVE Library, Research

## Promoted From

`codex/tasks/backlog-274-react-v2-remaining-screens.json`

## Goal

Implement the active backlog package `codex/tasks/backlog-274-react-v2-remaining-screens.json` so the React v2 application exposes the remaining real-data screens after the foundation, Mission Control, Intake, Findings Theater, Report Center, and Settings slices.

## Scope

Implement the active backlog package `codex/tasks/backlog-274-react-v2-remaining-screens.json`.

Expected React v2 remaining screens slice:

- build separate files under `ui-v2/src/components/screens/` for:
  - `Dashboard.tsx`
  - `History.tsx`
  - `ProblemsCenter.tsx`
  - `SurfaceMap.tsx`
  - `Packs.tsx`
  - `EvidenceReplay.tsx`
  - `CustomCVELibrary.tsx`
  - `Research.tsx`
- wire all eight screens into `ui-v2/src/App.tsx`
- use real backend APIs where available and keep unavailable states honest where repo truth does not expose a matching endpoint
- keep each screen within React v2 UI scope and preserve existing backend safety controls

## Constraints

- Do not implement until this file is the single active task.
- This task depends on completed backlog-268 through backlog-273.
- Work only in the React v2 remaining screens scope.
- Do not touch `api/`, `workers/`, or old `ui/` unless the task package and repo truth make a narrow typed API addition unavoidable; document any exception before implementation.
- Do not bypass existing backend scope, ROE, approval, runner registry, provenance, report, credential, runtime binding, or kill-switch behavior.
- Do not create runtime self-modification or uncontrolled plugin installation.
- Production UI must use existing icon patterns and no emoji.
- Use existing backend contracts and do not silently install, enable, or run capabilities.

## Validation

- `python3 scripts/validate_backlog_tasks.py`
- `cd ui-v2 && npm run build`
- `git diff --check`

## Acceptance

- All eight remaining screens render and are reachable from navigation.
- Dashboard uses real dashboard/engagement/run/finding data where available.
- History loads real runs with filters where backend contracts support them.
- Problems Center shows real finding lifecycle data where backend contracts support it.
- Surface Map uses real inventory data where available.
- Packs list uses real pack data where available.
- Evidence Replay shows real task execution/stdout/artifact data where available.
- Custom CVE Library and Research screens keep unavailable backend states honest rather than using fake data.
- Build passes with no TypeScript errors.
