# backlog-226 headers-security runner evidence

## Scope

Implemented `headers-security` as a bounded HTTP security-header runner for approved web roots.

## Product behavior

- Performs passive baseline header analysis for CSP, clickjacking controls, HSTS, and disclosure headers.
- Performs active Origin reflection probes for attacker, `null`, regex-style bypass, and configured extra origins.
- Records redirect CORS header preservation checks without following redirects to extract cross-origin data.
- Emits `headers-security-results.json` with structured checks, findings, replay metadata, and safety metadata.
- Does not modify ZAP configuration or the SSL/TLS runner.

## Validation

- `python3 -m py_compile workers/runners/headers_security/runner.py workers/orchestration/tasks.py workers/orchestration/findings.py api/app/services/runs.py api/app/services/run_profiles.py api/app/services/ai_agent.py api/app/methodology.py workers/tests/test_headers_security_runner.py api/tests/test_pentest_depth_registration.py api/tests/test_runs.py` passed.
- `source .venv/bin/activate && python -m pytest workers/tests/test_headers_security_runner.py api/tests/test_pentest_depth_registration.py workers/tests/test_web_depth_runner.py api/tests/test_runs.py::test_list_run_profiles api/tests/test_runs.py::test_active_headers_security_profile_requires_approval_and_queues_header_task -q` passed.
- `source .venv/bin/activate && python -m pytest api/tests/ -q` passed with existing Alembic warnings; the `AEGISPT_DB_KEY or --key is required.` line is emitted by an existing negative startup test and the command exited 0.
- `python3 scripts/validate_backlog_tasks.py` passed.
- `git diff --check` passed.
- `curl -fsS --max-time 5 http://127.0.0.1:8000/health/live` returned healthy development runtime.
- `curl -fsS --max-time 5 http://127.0.0.1:8000/app/assets/modules/packs.js | rg -n "headers-security|HTTP Headers Security"` confirmed the live-served Tool Library module contains the new entry.

## Remaining Risk

- No public WebGoat/Gruyere or internet target was actively scanned during this build-lane slice.
- CORS and clickjacking acceptance is based on header/status/body evidence and does not prove exploitability through browser data extraction.
- CSP JSONP allowlist detection is a conservative signal, not full CSP bypass proof.

