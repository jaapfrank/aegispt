# Backlog 229 HTTP Smuggling Runner Evidence

## Scope

- Active task: `HTTP request smuggling runner: detect CL.TE, TE.CL, and TE.TE desync vulnerabilities in reverse proxy setups`.
- Implemented tool: `http-smuggling`.
- Validation target policy: deterministic fixtures plus read-only local API/UI acceptance only.
- No active scan was run against Gruyere, WebGoat, a public internet target, or a live proxy lab in this build-lane slice.

## Implemented Behavior

- Adds `workers/runners/http_smuggling/runner.py`.
- Enforces approved web/API scope before runtime probing.
- Performs a proxy-evidence gate before sending any CL/TE probe.
- Accepts proxy evidence only from `Via`, `Forwarded`, or `X-Forwarded-*` headers observed in response headers or explicitly configured evidence.
- Sends timing-only CL.TE, TE.CL, and TE.TE raw HTTP probes with a hard 5-second maximum timeout.
- Emits critical `HTTP Request Smuggling (CL.TE|TE.CL|TE.TE) - Timing Confirmed` findings when a timing threshold or timeout signal is observed.
- Records safety evidence in findings and payload:
  - `timing_based_detection_only=true`
  - `confirming_request_sent=false`
  - `visible_side_effect_request_sent=false`
  - `request_hijacking_attempted=false`
  - `cache_poisoning_attempted=false`
  - `waf_bypass_attempted=false`
  - `internal_endpoint_access_attempted=false`
  - `runtime_mutation=false`

## Registrations

- `workers/orchestration/tasks.py`: `http-smuggling` in supported tools, dispatch, and command preview.
- `workers/orchestration/findings.py`: standard JSON finding extraction for `http-smuggling-results.json`.
- `api/app/services/runs.py`: planning, configuration extraction, scope validation, proxy-evidence validation, and queued task params.
- `api/app/services/run_profiles.py`: `active-web-http-smuggling`.
- `api/app/services/ai_agent.py`: AI/manual proposal allowlists.
- `api/app/methodology.py`: WSTG/control-family/tool-tag mapping.
- `ui/assets/modules/packs.js`: Tool Library entry.

## Package Exception

The task package goal text referenced a `10+ second delay on the confirming request`, but both `NEXT_TASK.md` and the package constraints require a maximum 5-second timeout per probe and prohibit visible side-effect confirming requests. This implementation follows the stricter safety constraint: timing evidence is capped at 5 seconds and no confirming request is sent.

## Operator Complaint Boundary

The operator-reported Gruyere wizard issue, where a full pentest only uses a small subset of tools and still needs scattered approvals/starts, maps to queued backlog-250 runner/profile/wizard wiring. This active backlog-229 slice adds and registers one runner but does not claim to fix full-wizard coverage.

## Validation

- `python3 scripts/validate_backlog_tasks.py` passed before implementation with 250 queued task packages and exactly one active task.
- `source .venv/bin/activate && python -m compileall -q workers/runners/http_smuggling workers/orchestration/tasks.py workers/orchestration/findings.py api/app/services/runs.py api/app/services/run_profiles.py api/app/services/ai_agent.py api/app/methodology.py workers/tests/test_http_smuggling_runner.py api/tests/test_pentest_depth_registration.py api/tests/test_runs.py workers/tests/test_web_depth_runner.py` passed.
- `source .venv/bin/activate && python -m pytest workers/tests/test_http_smuggling_runner.py workers/tests/test_web_depth_runner.py::test_web_depth_tools_are_supported api/tests/test_pentest_depth_registration.py api/tests/test_runs.py::test_active_http_smuggling_profile_requires_approval_and_queues_smuggling_task -q` passed.
- `source .venv/bin/activate && python -m pytest api/tests/test_runs.py::test_list_run_profiles api/tests/test_pentest_depth_registration.py -q` passed.
- `source .venv/bin/activate && python -m pytest api/tests/ -q` passed; existing Alembic warnings appeared and the `AEGISPT_DB_KEY or --key is required.` line came from an existing negative startup test.
- Read-only live acceptance on `http://127.0.0.1:8000` passed after `AEGISPT_LOCAL_ENSURE_ZAP=0 scripts/restart_local_inline_host.sh`:
  - `/health/live` returned healthy.
  - `/app/assets/modules/packs.js` contained `http-smuggling` and `HTTP Smuggling`.
  - `/api/v1/run-profiles` contained `active-web-http-smuggling` with `tools=["http-smuggling"]`.
- Final `python3 scripts/validate_backlog_tasks.py` passed after promoting backlog-230 into `NEXT_TASK.md`.
- Final `git diff --check` passed.

## Residual Risk

- Timing-only request smuggling evidence is conservative and should be reviewed by a human before report wording implies exploitability beyond the timing signal.
- No legal live proxy-backed lab proof was executed in this slice.
- Full wizard/profile-chain coverage for all newly added runners remains pending until the queued runner/profile/wizard wiring task becomes active.
