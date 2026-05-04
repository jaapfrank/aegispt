# backlog-222 Deserialization Probe Runner Evidence

## Scope

Implemented the active task from `NEXT_TASK.md`: `backlog-222-insecure-deserialization-runner`.

The slice adds an approval-gated `deserialization-probe` capability for approved web/API roots. The runner covers:

- Java serialized-object marker detection with URLDNS-only governed OOB confirmation
- PHP object-injection error analysis with bounded serialized-string probes
- Python pickle acceptance/error signals from explicit evidence or approved request contexts
- .NET ViewState unsigned/unencrypted indicators
- Node serialize usage signals as non-finding check records

## Safety

- Scope is enforced with approved web-root path matching before target execution.
- Java payload family is recorded as `ysoserial-url-dns-only`.
- Command execution payloads, CommonsCollections/RCE gadget chains, and exfiltration are disabled.
- Java URLDNS findings require governed OOB evidence or supplied interaction references.
- Validation used safe local fixtures and read-only local health/asset checks; no external live deserialization target was probed.

## Validation

- `python3 scripts/validate_backlog_tasks.py` passed before implementation.
- `python3 -m py_compile workers/runners/deserialization_probe/runner.py workers/orchestration/tasks.py workers/orchestration/findings.py api/app/services/runs.py api/app/services/run_profiles.py api/app/services/ai_agent.py api/app/methodology.py` passed.
- `source .venv/bin/activate && python -m pytest workers/tests/test_deserialization_probe_runner.py api/tests/test_pentest_depth_registration.py api/tests/test_runs.py::test_list_run_profiles api/tests/test_runs.py::test_active_deserialization_probe_profile_requires_approval_and_queues_task -q` passed.
- `source .venv/bin/activate && python -m pytest api/tests/ -q` passed with existing Alembic deprecation warnings. The `AEGISPT_DB_KEY or --key is required.` line was emitted by an existing negative startup test and the command exited 0.
- `python3 scripts/validate_backlog_tasks.py` passed during validation.
- `git diff --check` passed.
- `curl -sS --max-time 5 http://127.0.0.1:8000/health/live` returned a healthy development runtime.
- `curl -sS --max-time 5 http://127.0.0.1:8000/app/assets/modules/packs.js | rg -n "deserialization-probe|Deserialization Probe"` confirmed the live-served Tool Library module contains the Deserialization Probe entry.

## Remaining Risk

- No public WebGoat target was actively tested during this build-lane task; proof is from deterministic safe fixtures.
- Java confirmation depends on governed DNS/OOB evidence supplied by the runtime or validation fixture.
- Python pickle detection is intentionally signal-based and does not execute attacker-controlled pickle gadgets.
- ViewState detection is evidence-first and identifies unprotected indicators; it does not prove every ASP.NET validation setting.
