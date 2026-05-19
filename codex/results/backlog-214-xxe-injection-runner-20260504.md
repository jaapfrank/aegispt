# backlog-214 XXE Injection Runner Evidence

## Scope

Implemented the active task from `NEXT_TASK.md`: `codex/tasks/backlog-214-xxe-injection-runner.json`.

The task package mentioned DoS/Billion-Laughs-style XXE in its broad benchmark context, but `NEXT_TASK.md` and the package constraints explicitly prohibit denial-of-service payloads. This slice therefore implements only read-only direct `file:///etc/passwd` validation and provided out-of-band evidence handling.

## Product Truth

- Added supported tool `xxe-probe`.
- Added active profile `active-web-xxe-probe`.
- Added path-aware XML endpoint scope validation for configured endpoints and evidence-derived endpoints.
- Added structured `xxe-results.json` with critical direct-file-read and blind/OOB XXE findings.
- Added methodology mapping to OWASP WSTG input validation and AegisPT input-validation control family.
- Added Tool Library entry for XXE Probe.
- Added explicit ZAP scanner `90023` activation for `active-web-zap-active` where the local ZAP policy supports it.
- No DoS XXE payloads, SSRF chaining, runtime self-modification, uncontrolled tool installation, scope bypass, approval bypass, deployment bypass, runtime binding bypass, credential bypass, or kill-switch bypass was introduced.

## Validation

- `python3 scripts/validate_backlog_tasks.py`
  - Passed before implementation.
  - Passed during validation.
- `source .venv/bin/activate && python -m pytest workers/tests/test_web_depth_runner.py api/tests/test_pentest_depth_registration.py api/tests/test_zap_dispatch.py::test_inline_dispatch_executes_active_zap_profile -q`
  - Passed: `16` tests.
- `source .venv/bin/activate && python -m pytest api/tests/ -q`
  - Passed with existing Alembic deprecation warnings.
- `curl --fail --silent --show-error --max-time 5 http://127.0.0.1:8000/health/live`
  - Returned healthy development runtime.
- `curl --fail --silent --show-error --max-time 5 http://127.0.0.1:8000/app/assets/modules/packs.js | rg -n "xxe-probe|XXE Probe"`
  - Confirmed the live-served Tool Library module contains the XXE entry.
- `git diff --check`
  - Passed after administrative updates.

## Safe Local Fixture Evidence

`workers/tests/test_web_depth_runner.py` includes a local `ThreadingHTTPServer` fixture that echoes a passwd-style marker only when it receives the read-only XXE probe. The test proves:

- `xxe-probe` produces `xxe-results.json`.
- direct file-read evidence is emitted as `XXE - File Read Possible (Direct)`.
- severity is `critical`.
- safety metadata records `dos_payloads_sent: 0` and payload family `read-only-file-uri`.
- out-of-scope XML endpoints are rejected before probing.

## Remaining Risks

- No external or live target XXE probe was executed in this build-lane validation.
- OOB XXE detection currently depends on operator-provided confirmation references.
- ZAP scanner `90023` depends on the installed ZAP version and active scan policy support.
