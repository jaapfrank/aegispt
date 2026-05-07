# Active Task

## Title

React v2 Cinema Mode: replace hardcoded EVENT_STREAM with real run data — hosts as 3D nodes, live task stdout, local fonts

## Promoted From

`codex/tasks/backlog-275-react-v2-cinema-mode-real-data.json`

## Goal

Implement the active backlog package `codex/tasks/backlog-275-react-v2-cinema-mode-real-data.json` so React v2 Cinema Mode uses real inventory, task stdout, findings, and AI proposal data instead of hardcoded mock streams.

## Scope

Implement the active backlog package `codex/tasks/backlog-275-react-v2-cinema-mode-real-data.json`.

Expected React v2 Cinema Mode slice:

- replace hardcoded target/node data in `ui-v2/src/components/CinemaMode.tsx` with real hosts from the selected run inventory snapshot
- replace the hardcoded event stream with real task stdout polling from existing run/task APIs
- load Fira Mono locally from `ui-v2/public/fonts/FiraMono.woff2`
- make the bottom HUD and stats overlay reflect real selected-run data
- keep camera movement deterministic and tied to the active task target where possible

## Constraints

- Do not implement until this file is the single active task.
- This task depends on completed backlog-268 and backlog-269.
- Work only in the React v2 Cinema Mode real-data scope.
- Do not touch `api/`, `workers/`, old `ui/`, or unrelated React v2 screens unless repo truth makes a narrow typed store/API addition unavoidable; document any exception before implementation.
- Do not bypass existing backend scope, ROE, approval, runner registry, provenance, report, credential, runtime binding, or kill-switch behavior.
- Do not create runtime self-modification or uncontrolled plugin installation.
- Production UI must use existing icon patterns and no emoji.
- Use existing backend contracts and do not silently install, enable, or run capabilities.

## Validation

- `python3 scripts/validate_backlog_tasks.py`
- `cd ui-v2 && npm run build`
- `git diff --check`

## Acceptance

- Cinema Mode opens with real inventory hosts as 3D nodes when inventory exists.
- Cinema Mode shows a truthful waiting/discovery fallback when no inventory exists.
- Event stream uses real task stdout changes, not hardcoded `EVENT_STREAM`.
- Local font path `/fonts/FiraMono.woff2` is used; no Google Fonts URL remains.
- Bottom HUD shows real active tool and target names.
- Camera follows the actual running task target node where possible.
- Stats overlay shows real critical findings, high findings, host count, and pending AI proposal count.
- Build passes with no TypeScript errors.
