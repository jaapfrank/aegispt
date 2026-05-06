# backlog-247 sqlmap blind and advanced SQLi evidence

Date: 2026-05-06

## Scope

Implemented the active backlog-247 slice for bounded sqlmap blind/advanced SQLi coverage.

`http://127.0.0.1:8000` was not relevant for acceptance because this task changed the worker runner and command-preview text, not browser UI flows or live operator-console state.

## Implementation proof

- `execute_sqlmap_confirmation()` still requires explicit `injectable_parameters` or ZAP-flagged parameters before execution.
- Existing target scope checks and approved web-root checks remain before any sqlmap command is built.
- Phase A command uses:
  - `--batch`
  - `--smart`
  - `--identify-waf`
  - `--level 1`
  - `--risk 1`
- Phase B runs after Phase A does not confirm vulnerability and uses:
  - `--level 3`
  - `--risk 2`
  - `--technique T`
  - `--tamper=space2comment,between,randomcase`
  - `--identify-waf`
- Bounded safety posture:
  - no `--risk 3`
  - no `--dump`
  - no sqlmap OS-shell flags
  - no database content extraction flags
- Result artifacts now record Phase A/B status, WAF signals, blind signals, Phase B tamper use, and summary safety flags.
- Finding behavior stays evidence-backed:
  - confirmed basic SQLi is `critical`
  - confirmed blind SQLi is `high`
  - heuristic possible but unconfirmed SQLi is `medium`
  - findings store parameter/source/phase metadata, not database dump content.
- Command preview now describes the bounded two-phase sqlmap path.

## Validation

- `python3 scripts/validate_backlog_tasks.py` passed before implementation with 265 queued task packages and exactly one active task.
- `source .venv/bin/activate && python -m pytest workers/tests/test_web_depth_runner.py workers/tests/test_runner_contract.py -q` passed.
- `python3 -m compileall workers/runners/web_depth/runner.py workers/orchestration/tasks.py workers/tests/test_web_depth_runner.py workers/tests/test_runner_contract.py` passed.
- `source .venv/bin/activate && python -m pytest api/tests/ -q` passed with exit code 0. The only output after completion was the existing Alembic deprecation warning summary.
- `source .venv/bin/activate && python -m pytest workers/tests scripts/tests -q` initially exposed an unrelated local host-tool path assumption in `test_arp_spoof_proof_executes_only_with_explicit_intrusive_gate`: after `arpspoof` was installed, the runner correctly resolved `/usr/sbin/arpspoof` while the test expected the bare string `arpspoof`. The test assertion was repaired to accept either resolved path or bare binary while preserving the command arguments and 30-second cap, and the worker/script suite then passed.

## Acceptance evidence

- Deterministic runner tests prove:
  - Phase A stops after a confirmed basic injection.
  - Phase A includes WAF identification.
  - Phase B uses level 3/risk 2, `--technique T`, and the bounded tamper list.
  - Phase B detects a simulated time-based blind SQLi signal and emits a high-severity blind SQLi finding.
  - WAF output triggers the advanced tamper phase.
  - possible-but-unconfirmed output emits a medium-severity potential SQLi finding.
  - command preview contains Phase A/B details and excludes `--risk 3`, `--dump`, and `--os-shell`.

## Boundaries

No live customer, public, third-party, or database-dumping target was scanned. No pack registry, validation, approval, deployment, runtime binding, scope, ROE, credential, or kill-switch boundary was bypassed. No runtime self-modification or uncontrolled plugin installation occurred.

The only non-sqlmap code adjustment was a test-only compatibility repair for the existing network-capture ARP spoof proof test after local host readiness made `arpspoof` resolvable by absolute path.

## Remaining risk

This slice used deterministic runner evidence rather than a live AutoPenBench WS4 instance. A future benchmark-validation task should run the existing runner against an explicitly authorized local WS4 fixture when that fixture is available.
