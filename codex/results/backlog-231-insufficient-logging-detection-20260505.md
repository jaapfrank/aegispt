# backlog-231 insufficient logging detection evidence

Date: 2026-05-05

## Implementation summary

- Added `logging-probe` as a detection-only runner for approved web/API roots.
- The runner emits `logging-probe-results.json` with checks, findings, safety metadata, and redacted excerpts.
- Coverage includes malformed-query and invalid-JSON error leakage checks, stack traces, internal file paths, database/framework errors, internal IP disclosure, common admin/debug/config paths, Spring Actuator paths, CRLF/log-format reflected marker checks, and a Log4Shell-style marker check.
- Safety metadata records no JNDI callback listener, no JNDI exploitation, no callback chain, no admin login/takeover, no debug chaining, no log-file read, no runtime mutation, and bounded response reads.

## Files touched

- `workers/runners/logging_probe/runner.py`
- `workers/runners/logging_probe/__init__.py`
- `workers/orchestration/tasks.py`
- `workers/orchestration/findings.py`
- `api/app/services/runs.py`
- `api/app/services/run_profiles.py`
- `api/app/services/assessment_chain.py`
- `api/app/routers/runs.py`
- `api/app/services/ai_agent.py`
- `api/app/methodology.py`
- `ui/assets/modules/packs.js`
- `ui/assets/modules/wizard.js`
- `scripts/acceptance_harness.py`
- `workers/tests/test_logging_probe_runner.py`
- `workers/tests/test_web_depth_runner.py`
- `api/tests/test_pentest_depth_registration.py`
- `api/tests/test_runs.py`
- `api/tests/test_assessment_chain.py`

## Focused validation

- `source .venv/bin/activate && python -m py_compile workers/runners/logging_probe/runner.py workers/orchestration/tasks.py workers/orchestration/findings.py api/app/services/runs.py api/app/services/run_profiles.py api/app/services/assessment_chain.py api/app/methodology.py api/app/services/ai_agent.py api/app/routers/runs.py scripts/acceptance_harness.py` passed.
- `source .venv/bin/activate && python -m pytest workers/tests/test_logging_probe_runner.py -q` passed.
- `source .venv/bin/activate && python -m pytest api/tests/test_pentest_depth_registration.py api/tests/test_assessment_chain.py::test_full_external_web_chain_includes_logging_probe_and_oauth_probe api/tests/test_runs.py::test_passive_logging_probe_profile_queues_logging_task_without_extra_approval -q` passed.
- `source .venv/bin/activate && python -m pytest api/tests/test_runs.py::test_list_run_profiles api/tests/test_runs.py::test_passive_logging_probe_profile_queues_logging_task_without_extra_approval -q` passed.
- `source .venv/bin/activate && python -m pytest workers/tests/test_web_depth_runner.py::test_web_depth_tools_are_supported -q` passed.
- `node --input-type=module --check < ui/assets/modules/wizard.js` passed.
- `node --input-type=module --check < ui/assets/modules/packs.js` passed.
- Extra `source .venv/bin/activate && python -m pytest ui/tests/test_wizard_input_prediction_matrix_e2e.py -q` was attempted but is not claimed green: the existing `run_create` rate limit blocked the 11th run in `test_wizard_launch_flow_matches_matrix_for_each_assessment_family` with HTTP 429 after 10 run creations in 60 seconds.

## Required validation

- `python3 scripts/validate_backlog_tasks.py` passed before implementation with 250 queued task packages and exactly one active task.
- `source .venv/bin/activate && python -m pytest api/tests/ -q` passed after updating the existing Full External Web chain test for the new Phase 1 logging step. Existing Alembic deprecation warnings appeared; the `AEGISPT_DB_KEY or --key is required.` line came from an existing negative startup test.

## Live/local acceptance

- Restarted the local inline host with `AEGISPT_LOCAL_ENSURE_ZAP=0 bash scripts/restart_local_inline_host.sh`.
- Final browser-backed read-only acceptance on `http://127.0.0.1:8000/app/` passed:
  - `/health/live` returned `status=ok`.
  - `/api/v1/run-profiles` exposed `passive-web-logging-probe` with `tools=["logging-probe"]` and `required_approvals=0`.
  - `buildWizardInputPredictionMatrix()` showed External Web passive and active paths include `passive-web-logging-probe`; API passive also resolves to `FULL-EXTERNAL-WEB` and includes `passive-web-logging-probe`.
  - `/app/assets/modules/packs.js` contained the Tool Library entry `id: "logging-probe"`.
- Earlier browser script attempts failed due an incorrect asset URL and then a missing script `json` import; those attempts are not counted as passed acceptance. The final rerun above passed.

Final browser output:

```json
{"health":"ok","passive_api_mode":"FULL-EXTERNAL-WEB","passive_external_mode":"FULL-EXTERNAL-WEB","passive_external_profiles":["passive-easm-discovery","passive-web-baseline","passive-web-logging-probe","passive-web-nuclei-audit","active-web-safe","passive-web-burp","active-business-logic","active-web-oauth-probe","active-llm-application-probe","intrusive-exploitation"],"profile":"passive-web-logging-probe","tool_library_asset":true,"tools":["logging-probe"]}
```

## Safety and limitations

- The runner does not exploit Log4Shell. It sends only a marker string and records no callback listener, no callback chain, and no JNDI exploitation.
- The runner does not log in to admin panels, download full heapdumps, read log files, or chain debug endpoints.
- No Gruyere, WebGoat, public internet target, or live third-party target was scanned in this build-lane slice; behavior proof is from deterministic local fixtures plus read-only local UI/API acceptance.
