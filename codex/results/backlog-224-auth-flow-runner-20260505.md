# backlog-224 auth-flow runner evidence

## Scope

Implemented the active `auth-flow` runner slice for password reset and authentication-flow security. The runner is approval-gated, requires configured test-account credentials, enforces approved web-root scope, caps failed-login validation at 10 attempts, and stores token/credential hashes or metadata rather than raw secrets.

## Product behavior added

- `auth-flow` detects predictable password-reset tokens from up to 5 bounded configured test-account reset requests.
- `auth-flow` detects reset-token reuse by submitting the first observed token twice to the configured reset-consume endpoint.
- `auth-flow` detects Host-header reset poisoning when a forged Host value appears in reset-link evidence.
- `auth-flow` detects username enumeration through response status/body/timing differences for valid versus invalid usernames.
- `auth-flow` detects missing brute-force protection after at most 10 failed login attempts and stops immediately if lockout/rate-limit signals appear.
- `auth-flow` detects configured login endpoints using HTTP or GET semantics for credential submission.

## Validation evidence

- `python3 scripts/validate_backlog_tasks.py` passed before implementation.
- `python3 -m py_compile workers/runners/auth_flow/runner.py workers/orchestration/tasks.py workers/orchestration/findings.py api/app/services/runs.py api/app/services/run_profiles.py api/app/services/ai_agent.py api/app/methodology.py` passed.
- `source .venv/bin/activate && python -m pytest workers/tests/test_auth_flow_runner.py api/tests/test_pentest_depth_registration.py::test_new_depth_profiles_are_declared api/tests/test_pentest_depth_registration.py::test_new_depth_tools_plan_expected_targets api/tests/test_pentest_depth_registration.py::test_tool_library_lists_all_depth_tools api/tests/test_pentest_depth_registration.py::test_auth_flow_validation_requires_credentials_and_scope api/tests/test_runs.py::test_active_auth_flow_profile_requires_approval_and_queues_authenticated_task api/tests/test_runs.py::test_list_run_profiles -q` passed after fixing the expected alphabetical run-profile order.
- `source .venv/bin/activate && python -m pytest api/tests/ -q` passed with existing Alembic deprecation warnings; the `AEGISPT_DB_KEY or --key is required.` line came from an existing negative startup test and the command exited 0.
- `python3 scripts/validate_backlog_tasks.py` passed after promoting backlog-225 into `NEXT_TASK.md`.
- `git diff --check` passed.
- `curl -fsS http://127.0.0.1:8000/health/live` returned healthy development runtime.
- `curl -fsS http://127.0.0.1:8000/app/assets/modules/packs.js | rg -n "auth-flow|Auth Flow"` confirmed the live-served Tool Library module contains the Auth Flow entry.

## Remaining risk

- No public WebGoat passwordreset/insecurelogin target was actively exercised in this build-lane slice.
- Reset-token reuse validation depends on a configured safe test account and reset-consume endpoint.
- Username-enumeration timing remains a signal and is strongest when repeated under stable local fixture conditions.
- Login brute-force validation is intentionally bounded to 10 failed attempts and cannot prove all rate-limit policies.
