# backlog-218 IDOR/BAC runner evidence

## Summary

Completed the dedicated `idor-bac` active runner for bounded insecure direct object reference and broken access-control checks.

The runner:

- enforces approved web-root scope with path-aware checks
- requires configured authenticated access accounts
- uses materialized credentials only through the existing task secret-binding path
- detects numeric and UUID-like object identifiers from approved endpoints, evidence hints, explicit candidate paths, and authenticated link discovery
- keeps numeric identifier substitution bounded to a maximum `±20`
- distinguishes confirmed IDOR evidence from potential access-control signals
- validates explicit role/admin parameter manipulation contexts in query or JSON body
- checks scoped method-override and common admin-path exposure
- emits `idor-bac-results.json` with structured findings, replay context, summary, and safety metadata

## Files

- `workers/runners/idor_bac/runner.py`
- `workers/runners/idor_bac/__init__.py`
- `workers/orchestration/tasks.py`
- `workers/orchestration/findings.py`
- `api/app/services/runs.py`
- `api/app/services/run_profiles.py`
- `api/app/services/ai_agent.py`
- `api/app/methodology.py`
- `ui/assets/modules/packs.js`
- `workers/tests/test_idor_bac_runner.py`
- `api/tests/test_pentest_depth_registration.py`
- `api/tests/test_runs.py`

## Validation

- `python3 scripts/validate_backlog_tasks.py`
  - passed before implementation
- `source .venv/bin/activate && python -m py_compile workers/runners/idor_bac/runner.py workers/orchestration/tasks.py workers/orchestration/findings.py api/app/services/runs.py api/app/services/run_profiles.py api/app/services/ai_agent.py api/app/methodology.py`
  - passed
- `source .venv/bin/activate && python -m pytest workers/tests/test_idor_bac_runner.py api/tests/test_pentest_depth_registration.py api/tests/test_runs.py::test_list_run_profiles api/tests/test_runs.py::test_active_idor_bac_profile_requires_approval_and_queues_authenticated_task -q`
  - passed
- `source .venv/bin/activate && python -m pytest api/tests/ -q`
  - passed with existing Alembic deprecation warnings
- `python3 scripts/validate_backlog_tasks.py`
  - passed during validation
- `git diff --check`
  - passed during validation
- `curl -sS http://127.0.0.1:8000/health/live`
  - returned healthy development runtime
- `curl -sS http://127.0.0.1:8000/app/assets/modules/packs.js | rg -n "idor-bac|IDOR / Broken Access Control"`
  - confirmed the live-served Tool Library module includes the IDOR/BAC entry

## Safe Fixture Proof

`workers/tests/test_idor_bac_runner.py` uses a local `httpx.MockTransport` fixture with two configured accounts:

- Alice owns object `100`.
- Bob owns object `120`.
- Alice can retrieve Bob's object by bounded identifier substitution.
- An explicit request context accepts `role=admin`.
- A scoped endpoint accepts `X-HTTP-Method-Override: DELETE`.
- A scoped admin path is exposed without authentication.

The fixture produced four structured findings:

- `IDOR - Horizontal Privilege Escalation`
- `Broken Access Control - Privilege Escalation via Parameter`
- `Broken Access Control - Method Override Accepted`
- `Broken Access Control - Admin Path Exposed`

## Remaining Risk

- No public WebGoat/Gruyere target was actively exercised in this build-lane slice; proof is from a deterministic local fixture.
- The running `127.0.0.1:8000` API process appears older than the current code because `/api/v1/run-profiles` did not expose the new profile during read-only checking; the static Tool Library asset is current. A normal service restart/redeploy is needed before the live API reflects the new default profile.
- Confirmed IDOR requires foreign ownership markers from configured access accounts or explicit evidence; otherwise the runner reports potential access-control signals at High severity.
