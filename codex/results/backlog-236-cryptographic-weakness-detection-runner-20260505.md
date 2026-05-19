# backlog-236 Cryptographic Weakness Detection Runner Evidence

Date: 2026-05-05

## Scope

Implemented the `crypto-audit` runner and passive profile wiring for approved TLS, SSH, and captured token evidence. Validation stayed local/safe and did not run against external live targets.

## Implementation Proof

- `crypto-audit` is registered in `SUPPORTED_TOOLS` and dispatched through the existing runner orchestration path.
- Runner output is stored as `crypto-audit-results.json` with standard `findings` and `analysis_findings` extraction.
- `testssl.sh` command construction is used for TLS targets, with `--fast` in passive mode.
- `ssh-audit` is called for explicit SSH targets and host-target tasks.
- Findings cover export-grade ciphers, POODLE/SSLv3, BEAST, LUCKY13, RC4, TLS 1.0/1.1, weak DH, short certificate keys, HSTS preload absence, weak SSH KEX/MAC/host-key/cipher signals, RSA1_5 JWE, RSA PKCS#1 v1.5 JWS, short HS keys, and MD5/SHA1-length token signals.
- Findings include `why_weak`, `fix_recommendation`, and `better_alternative` fields.
- Safety metadata records no brute force, no decryption, no custom cipher analysis, no raw token storage, and scope enforcement.

## Wizard And Profile Proof

- Added `passive-crypto-audit` with `tools=["crypto-audit"]` and `required_approvals=0`.
- Full External Web Phase 1 now includes `passive-crypto-audit`.
- SSL/TLS wizard tile resolves to `passive-crypto-audit` for every depth.
- Browser matrix validation on a current-code local Uvicorn host at `http://127.0.0.1:8010/app/` observed:
  - SSL/TLS active depth expected execution profile: `passive-crypto-audit`
  - External Web active depth expected chain profiles include `passive-crypto-audit`
  - `/api/v1/run-profiles` includes `passive-crypto-audit` and `crypto-audit`

Note: the already-running `http://127.0.0.1:8000` process returned 200 for `/app/` and `/api/v1/run-profiles`, but it was serving old runtime state that did not include this change. Current-code local acceptance was therefore performed on temporary port `8010`, then the server was stopped.

## Validation

- `python3 scripts/validate_backlog_tasks.py` passed before implementation.
- `python3 scripts/validate_backlog_tasks.py` passed after implementation.
- `source .venv/bin/activate && python -m pytest workers/tests/test_crypto_audit_runner.py workers/tests/test_runner_contract.py -q` passed.
- `source .venv/bin/activate && python -m pytest ui/tests/test_wizard_input_prediction_matrix_e2e.py::test_ssl_tls_and_authenticated_app_tiles_reach_specialized_preview -q` passed.
- `source .venv/bin/activate && python -m pytest api/tests/ -q` passed.
- `git diff --check` passed.

## Risk Notes

- No live customer target or external target assessment was executed.
- This slice does not replace the existing `ssl-tls` runner or queued JWT runner.
- Runtime tool availability for `testssl.sh` and `ssh-audit` still depends on host installation/readiness; this task wires and certifies deterministic fixture behavior plus safe command construction.
- Transient `codex/tasks/task-20260505...pack-refinement...json` files appeared from the local Codex/planner runtime during final validation and were removed as out-of-scope because they were not `backlog-*.json` packages or `TASK_QUEUE.md` entries.
