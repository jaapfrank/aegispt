# Backlog 180 Validation Evidence - Launch Authorization and Phase Auto-Advance Contract

## Outcome

Backlog 180 is complete. Assessment-chain launch authorization is now carried into durable chain metadata and serialized chain summaries. Pre-authorized non-exploitation phases can auto-advance without redundant operator confirmation, while intrusive exploitation remains manually gated unless the launch configuration records both Full typed scope authorization and the explicit exploit-confirmation unlocker.

## Product Behavior Proven

- Full launch authorization records `intrusive_lan_authorized` and `exploit_confirmation_authorized` in chain authorization metadata and audit events.
- Full authorization without the exploit unlocker auto-advances already-authorized non-exploitation phases but stops at the exploitation phase with a clear manual gate.
- Full authorization with the explicit exploit unlocker can pre-authorize the exploitation boundary, preserving the existing typed scope confirmation contract.
- Serialized chain phases include `authorization_state`, `pre_authorized`, `gate_reason`, and `safe_next_action` so Mission Control can explain what is authorized, next, or blocked.
- Mission Control phase cards expose pre-authorized, auto-advancing, waiting-on-prerequisite, and manual-approval-required states.
- Wizard copy now explains that Full pre-authorizes non-exploitation phases and that exploitation needs its own unlocker plus evidence/scope prerequisites.

## Validation

- Passed: `python3 scripts/validate_backlog_tasks.py`
- Passed: `source .venv/bin/activate && python -m py_compile api/app/services/assessment_chain.py api/tests/test_assessment_chain.py api/tests/test_runs.py ui/tests/test_operator_console_smoke_e2e.py`
- Passed: `node --input-type=module --check < ui/assets/modules/wizard.js && node --input-type=module --check < ui/assets/modules/mission-control.js`
- Passed: `source .venv/bin/activate && python -m pytest api/tests/test_assessment_chain.py -s -q`
- Passed: `source .venv/bin/activate && python -m pytest ui/tests/test_operator_console_smoke_e2e.py::test_mission_control_phase_badges_expose_nfir_tooltips -s -q`
- Passed: `source .venv/bin/activate && python -m pytest api/tests/test_runs.py::test_list_run_profiles -s -q`
- Passed: `source .venv/bin/activate && python -m pytest api/tests/test_assessment_chain.py api/tests/test_runs.py -s -q`
- Passed: `source .venv/bin/activate && python -m pytest ui/tests/test_operator_console_e2e.py::test_mission_preview_requires_typed_scope_for_full_authorization ui/tests/test_operator_console_smoke_e2e.py::test_mission_control_phase_badges_expose_nfir_tooltips -s -q`
- Passed: `curl -fsS http://127.0.0.1:8000/health/live`
- Passed: live Playwright smoke against `http://127.0.0.1:8000/app/` (`live_auth_contract_acceptance=ok`)

## Not Claimed Green

- Exact required API command `source .venv/bin/activate && python -m pytest api/tests/test_assessment_chain.py api/tests/test_runs.py -q` failed in pytest global capture teardown with `FileNotFoundError`; the same API tests passed with `-s -q`.
- Exact required UI command `source .venv/bin/activate && python -m pytest ui/tests/test_operator_console_e2e.py ui/tests/test_operator_console_smoke_e2e.py -q` failed in pytest global capture teardown with `FileNotFoundError`; the focused relevant UI checks passed with `-s -q`.
- Broad UI `-s -q` run was stopped after producing many failures across the existing UI suite. The task-focused browser checks for this slice passed; the broad instability remains a validation risk and is aligned with the next active runtime/audit resilience task.

## Notes

- A stale `api/tests/test_runs.py::test_list_run_profiles` expectation was updated to include the already-present `passive-wifi-survey` profile so the active task's required API suite can pass.
- No pack validation, runtime binding, scope enforcement, credential prerequisite, kill switch, or exploitation approval gate was bypassed.
