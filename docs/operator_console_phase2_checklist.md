# Operator Console Phase 2 Checklist

## Purpose

This document tracks the second stabilization slice for the operator console.

Phase 2 focuses on run dispatch and execution truth:

- the operator must see when a run is only queued
- the operator must see what tool is active or was just executed
- the operator must be warned when execution finished but produced thin or failure-heavy output
- the UI must refresh more aggressively while a run is active

## Validation status

- prepared on 2026-04-17
- completed on 2026-04-19
- current automation focus:
  - `ui/tests/test_operator_console_e2e.py`
  - `ui/tests/test_product_feature_matrix_e2e.py`
  - `api/tests/test_runs.py`
- approval-gated Mission Control truth revalidated on 2026-04-19 through:
  - `codex/results/live-host-pending-approval-run-activity-20260419.json`
  - `codex/results/live-host-pending-approval-run-activity-20260419.png`
- queued-web dispatch truth revalidated on 2026-04-19 through:
  - `codex/results/live-host-web-dispatch-truth-20260419.json`
  - `codex/results/live-host-web-dispatch-truth-20260419.png`
- full Phase 2 execution-truth signoff revalidated on 2026-04-19 through:
  - `scripts/run_product_e2e_matrix.py --lane all`
  - `codex/results/live-host-phase2-run-execution-signoff-20260419.json`
  - `codex/results/live-host-phase2-run-execution-blocked-20260419.png`
  - `codex/results/live-host-phase2-run-execution-dispatch-20260419.png`

## Control checklist

| Area | Expected behavior | Current status |
| --- | --- | --- |
| Create Mission handoff | wizard confirmation lands cleanly in Mission Control | covered |
| Queued state clarity | Mission Control shows that queued tasks still need explicit operator dispatch | covered |
| Approval-gated blocked state clarity | approval-required profiles show explicit blocked activity, approval counts, and no misleading `Start Validation` action while approvals are still pending | covered |
| Dispatch clarity | `Start Validation` pushes a visible live-state transition and post-dispatch refresh, and the temporary dispatch mask falls away once the run is observed beyond `queued` | covered |
| Faster live refresh | active or queued runs refresh faster than idle dossier browsing | covered |
| Current task focus | Mission Control shows the selected task, target, lane, last change, and latest execution result | covered |
| Failure honesty | failed tasks surface as operator-review-needed, not quiet success | covered |
| Thin-output honesty | runs with little or no reviewable output are flagged for dossier review in both Current Activity and Run Activity | covered |
| Inventory-first truth | discovery runs show asset completion rather than pretending findings should already exist | covered |
| Next-step continuity | the operator always has a logical next action after dispatch or completion | covered |
| Web target planning truth | web nuclei runs prefer explicit URL targets over derived host/IP duplicates when both are present | covered |

## Commands used for this slice

```bash
./.venv/bin/pytest -s ui/tests/test_operator_console_e2e.py
./.venv/bin/pytest -s ui/tests/test_product_feature_matrix_e2e.py
./.venv/bin/pytest -q -s api/tests/test_runs.py
```

Recent approval-gated signoff commands:

```bash
TMPDIR=/var/tmp ./.venv/bin/pytest -q -s api/tests/test_runs.py -k 'active_run_requires_approval_before_queueing'
TMPDIR=/var/tmp ./.venv/bin/pytest -q -s ui/tests/test_product_feature_matrix_e2e.py -k 'execution_outcome_matrix_surfaces_blocked_pending_approval_state'
curl -sS http://127.0.0.1:8000/health/live
TMPDIR=/var/tmp ./.venv/bin/python <live-host approval proof script>
```

Recent queued-web dispatch signoff commands:

```bash
TMPDIR=/var/tmp ./.venv/bin/pytest -q -s api/tests/test_nuclei_dispatch.py api/tests/test_task_dispatch.py -k 'inline_dispatch_executes_httpx_task or nuclei_prefers_explicit_url_targets_over_derived_hosts_for_web_runs or inline_dispatch_executes_nuclei_task'
TMPDIR=/var/tmp ./.venv/bin/pytest -q -s ui/tests/test_operator_console_e2e.py -k 'ready_to_start_and_thin_output_states_keep_one_dispatch_action_and_truthful_completion or dispatch_and_status_history_work_after_conversational_intake or manual_dispatch_mode_explains_why_start_validation_does_not_launch_work'
curl -sS http://127.0.0.1:8000/health/live
TMPDIR=/var/tmp ./.venv/bin/python <live-host queued-web dispatch proof script>
git diff --check
```

Full Phase 2 signoff rerun:

```bash
TMPDIR=/var/tmp ./.venv/bin/python scripts/run_product_e2e_matrix.py --lane all
curl -sS http://127.0.0.1:8000/health/live
TMPDIR=/var/tmp ./.venv/bin/python <live-host Phase 2 blocked + dispatch signoff proof script>
git diff --check
```

## Exit criteria

Phase 2 can only be treated as complete when:

1. Mission Control makes queued, running, completed, failed, and thin-output states understandable
2. task-level truth is visible without forcing the operator into a separate dossier first
3. dispatch and post-dispatch transitions are browser-validated
4. repo truth files and Mission Control docs reflect the new behavior

## Remaining follow-up after this slice

- richer true streaming telemetry remains future work
- Kali/live-host walkthroughs still need periodic operator reality checks
- the operator-console stabilization program is now signoff-complete through Phases 1-7 for the current repo-owned supported-path contract; remaining expansion work now lives in the general backlog and environment-dependent lab breadth
