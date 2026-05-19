# backlog-302 Stateful AI Credential & Token Vault

## Scope

Implemented the active task in `NEXT_TASK.md`: a run-scoped, ephemeral credential/token vault for `run_mode === "ai_loop"` runs.

This slice did not change `ui-v2/`, did not add a new runner, did not bypass runner registry, approval gates, scope/ROE, runtime binding, provenance, reports, or the kill switch, and did not perform live target actions.

## Implementation

- Added `api/app/services/run_credential_vault.py`.
- Added `GET /api/v1/runs/{run_id}/credential-vault`.
- Added `POST /api/v1/runs/{run_id}/credential-vault`.
- Stored vault values through existing encrypted `SecretRef` materialization with run-vault metadata and redacted API payloads.
- Automatically injects public secret bindings into subsequent ai_loop tasks for authenticated-capable web runners, including `zap`, `nuclei`, and `content-discovery`/ffuf.
- Runtime materialization resolves injected bindings only at execution time; task params and API responses do not contain plaintext credential values.
- ai_loop runner protected outputs with supported secret kinds are stored as ephemeral run-vault entries instead of persistent general protected-output refs.
- Vault entries clear on cancellation/rejection/failure and when an ai_loop reaches stopped terminal loop state.

## Files

- `api/app/services/run_credential_vault.py`
- `api/app/routers/runs.py`
- `api/app/schemas/runs.py`
- `api/app/services/assessment_loop.py`
- `api/app/services/ai_agent.py`
- `api/app/services/runs.py`
- `workers/orchestration/tasks.py`
- `api/tests/test_run_credential_vault.py`
- `codex/results/backlog-302-stateful-ai-credential-and-token-vault-20260508.md`

## Validation

- `python3 scripts/validate_backlog_tasks.py` passed before implementation.
- `python3 -m py_compile api/app/services/run_credential_vault.py api/app/services/runs.py api/app/services/assessment_loop.py api/app/services/ai_agent.py api/app/routers/runs.py workers/orchestration/tasks.py api/tests/test_run_credential_vault.py` passed.
- `source .venv/bin/activate && python -m pytest api/tests/test_run_credential_vault.py -q` passed: 2 passed.
- `source .venv/bin/activate && python -m pytest api/tests/test_assessment_loop.py api/tests/test_ai_planner.py api/tests/test_ai_agent_reasoning.py::test_ai_proposal_approval_is_auditable_and_queues_follow_up_task api/tests/test_runs.py -q` passed.
- `source .venv/bin/activate && python -m pytest api/tests/` passed: 534 passed, 4 warnings.
- Live API smoke on temporary port `http://127.0.0.1:8032` passed:
  - `GET /health/live` returned 200.
  - `GET /api/v1/runs/00000000-0000-0000-0000-000000000000/credential-vault` returned truthful 404.

## Evidence

- API regression proves an ai_loop run can store a session value through the vault API, receive a redacted vault payload, and clear entries on run cancellation.
- Runtime regression proves a subsequent `nuclei` task receives vault-derived `auth_contexts` as secret bindings without plaintext in `Task.params_json`; runtime materialization resolves the `Cookie` header only in memory.
- The ffuf/content-discovery and Nuclei command previews expose only auth-context counts, not credential values.

## Boundaries

- `http://127.0.0.1:8000` browser validation was not required because this was backend/API/runtime behavior only and no UI was touched.
- No Playwright acceptance was run because no browser UI changed.
- No live Gruyere/WebGoat/DVWA credential extraction was executed in this slice; this remains tracked in `extra_tests.md` XT-032 and `risico.md` R-024.
- The package's broad Gruyere autonomous chaining criterion is not fully satisfied here; this task implemented the credential/token vault slice only.
