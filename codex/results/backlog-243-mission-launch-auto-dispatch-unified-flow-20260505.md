# backlog-243 Mission Launch Auto-Dispatch Unified Flow

## Outcome

Completed the External Web launch-flow repair slice.

AegisPT now records wizard-requested `dispatch_after_create` intent on approval-gated runs and, after the single launch approval clears, auto-dispatches eligible web non-exploitation work through the existing dispatch, kill-switch, runtime settings, and audit path. Manual dispatch hosts now persist `runtime_dispatch.last_dispatch_mode=manual`, so Mission Control can explain that no inline runner or worker is attached instead of presenting a repeated dead `Start Queued Checks` click.

The Full External Web assessment chain now carries approved web scope into all web follow-up profiles, including `active-web-safe`, `passive-web-burp`, and `active-business-logic`. If httpx/profiling produces no discovered inventory, the chain falls back to the already approved configured URL/host/domain scope instead of silently starving phase 2.

## Files

- `api/app/routers/runs.py`
- `api/app/services/assessment_chain.py`
- `api/app/services/runs.py`
- `api/tests/test_assessment_chain.py`
- `api/tests/test_runs.py`
- `ui/assets/modules/mission-control.js`
- `ui/assets/modules/wizard.js`
- `ui/tests/test_operator_console_e2e.py`

## Validation

- Passed: `python3 scripts/validate_backlog_tasks.py` after queue sync with 249 queued task packages mapped one-to-one and exactly one active task
- Passed: `source .venv/bin/activate && python -m pytest api/tests/test_runs.py api/tests/test_assessment_chain.py -q`
- Passed: `source .venv/bin/activate && python -m pytest api/tests/ -q`
- Passed focused UI: `source .venv/bin/activate && python -m pytest ui/tests/test_operator_console_e2e.py::test_pending_approval_run_can_be_approved_from_mission_control ui/tests/test_operator_console_e2e.py::test_manual_dispatch_mode_explains_why_start_validation_does_not_launch_work ui/tests/test_operator_console_e2e.py::test_assessment_mode_internal_lan_surfaces_chain_progress -q`
- Passed: `git diff --check`
- Passed live health check: `curl -fsS http://127.0.0.1:8000/health/live`

## Not Claimed Green

- `source .venv/bin/activate && python -m pytest ui/tests/test_operator_console_e2e.py -q` was attempted and then stopped after running for several minutes with broad failures. A rerun with `-x` showed the first failure in `test_external_infrastructure_tile_routes_to_external_infrastructure_execution_lane`, where the wizard stayed on Authorise instead of navigating to Mission Control. That test is outside the External Web launch/dispatch changes in this slice, so it is recorded as unresolved UI-suite debt rather than claimed green.

## Safety Notes

- Exploitation, credential attacks, responder/network poisoning, Metasploit, NetExec, Impacket, scope expansion, failed-runner recovery, missing credentials, kill switch, pack validation, deployment, and runtime binding remain gated.
- Auto-dispatch after approval is limited to wizard-requested web launch work whose queued tools are in the explicit safe web set.
- No live external target was scanned in this build-lane task.
- Externally generated backlog-244 through backlog-249 packages appeared during final validation; `TASK_QUEUE.md` was synchronized so they remain queued and do not replace the active backlog-228 task.
