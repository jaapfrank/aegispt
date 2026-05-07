# Active Task

## Title

Add 14 missing new security runners to FULL-EXTERNAL-WEB chain so they are actually dispatched

## Promoted From

`codex/tasks/backlog-252-full-external-web-chain-missing-new-runners.json`

## Goal

Implement the active backlog package `codex/tasks/backlog-252-full-external-web-chain-missing-new-runners.json` so the FULL-EXTERNAL-WEB chain and API Security wizard plan dispatch the already-registered runner profiles listed in that package.

## Scope

Implement the active backlog package `codex/tasks/backlog-252-full-external-web-chain-missing-new-runners.json`.

Expected slice:

- reconcile current product truth against the package before editing, because backlog-250 already wired several related profiles
- ensure FULL-EXTERNAL-WEB passive and active phases include the package-listed profiles where still missing
- keep auth-context-dependent profiles gated on configured auth context
- update the API Security wizard execution plan only where the package still applies
- preserve existing run profiles, runner implementations, approval gates, scope checks, runtime binding, and kill-switch behavior

## Constraints

- Do not implement until this file is the single active task.
- Work only on chain/wizard dispatch completeness described by the active package.
- Do not change runner implementations or weaken run-profile approval/scope/ROE constraints.
- Do not add fake runner coverage: any preview or chain entry must map to an existing RunProfile/tool path.
- If the package is partially obsolete because current code already implements an item, document that truth in `DONE_LOG.md` and `CURRENT_STATE.md` rather than duplicating entries.

## Validation

- `python3 scripts/validate_backlog_tasks.py`
- `source .venv/bin/activate && python -m pytest api/tests/ -q`
- `git diff --check`

## Acceptance

- FULL-EXTERNAL-WEB chain contains the still-applicable package-listed profiles without duplicate dispatch.
- Auth-context runners remain gated and do not silently run without credentials/context.
- Wizard/API Security previews match actual dispatchable profile/tool paths.
- Existing manual wizard path, approval model, scope enforcement, runtime binding, and kill switch remain intact.
