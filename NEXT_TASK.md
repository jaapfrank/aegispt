# Active Task

## Title

WiFi certification hardware blocker: show amber informational status when only hardware limitations remain

## Promoted From

`codex/tasks/backlog-253-wifi-certification-hardware-blocker-documentation.json`

## Goal

Implement the active backlog package `codex/tasks/backlog-253-wifi-certification-hardware-blocker-documentation.json` so WiFi certification/readiness distinguishes software-ready-with-hardware-limitation from a red blocked state.

## Scope

Implement the active backlog package `codex/tasks/backlog-253-wifi-certification-hardware-blocker-documentation.json`.

Expected slice:

- reconcile current diagnostics/readiness truth before editing, because recent stabilization may already have part of this behavior
- show WiFi hardware-only limitation as amber/informational rather than red/blocked when all software tooling is otherwise ready
- keep overall certification status from becoming `blocked` when the only blocker is WiFi hardware/lab availability
- add or preserve guidance text that explains the required monitor-mode WiFi adapter/lab condition
- preserve existing runner/tool certification, diagnostics, settings, approval, scope, runtime binding, ROE, credential, and kill-switch behavior

## Constraints

- Do not implement until this file is the single active task.
- Work only on WiFi readiness/certification blocker presentation and supporting API truth described by the active package.
- Do not weaken WiFi ROE, hardware, monitor-mode, adapter, scope, approval, or credential boundaries.
- Do not claim WiFi live support beyond software readiness unless an authorized adapter/lab proof exists.
- If the package is partially obsolete because current code already implements an item, document that truth in `DONE_LOG.md` and `CURRENT_STATE.md` rather than duplicating entries.

## Validation

- `python3 scripts/validate_backlog_tasks.py`
- `source .venv/bin/activate && python -m pytest api/tests/test_diagnostics.py -q`
- `git diff --check`

## Acceptance

- WiFi hardware blocker shows amber/informational, not red/blocked.
- Overall certification status is not `blocked` when only hardware limitations remain.
- Guidance text explains what adapter/lab condition is needed.
- Existing manual wizard path, runner/tool certification, diagnostics, approval model, scope enforcement, runtime binding, and kill switch remain intact.
