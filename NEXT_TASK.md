# Active Task

## Title

Cryptographic weakness detection runner: weak key lengths, deprecated algorithms, TLS/SSH config, and captured traffic analysis

## Promoted From

`codex/tasks/backlog-236-cryptographic-weakness-detection-runner.json`

## Goal

Add the queued cryptographic weakness detection capability described in `codex/tasks/backlog-236-cryptographic-weakness-detection-runner.json`.

## Scope

Implement the active backlog package `codex/tasks/backlog-236-cryptographic-weakness-detection-runner.json`.

Expected slice:

- add a `crypto-audit` runner for approved web, TLS, and SSH targets
- use `testssl.sh` for HTTPS/TLS/SSL weakness checks beyond the existing basic `ssl-tls` runner
- use `ssh-audit` for SSH cryptographic configuration checks
- detect and normalize signals for export-grade ciphers, POODLE, BEAST, RC4, weak DH parameters, TLS 1.0/1.1, missing HSTS preload, and short certificate keys where applicable
- represent JWE/JWS weak-algorithm and token-hash-length signals only where safe and without duplicating the queued JWT runner scope
- include fix recommendations that explain why each weak algorithm/configuration is risky and name safer alternatives
- add the `passive-crypto-audit` run profile with `tools=["crypto-audit"]` and zero required approvals where the task package requires it
- wire the profile into web and TLS assessment Phase 1 paths and wizard surfaces for External Web and SSL/TLS tiles at any depth
- keep evidence, findings, methodology tags, provenance, reports, approvals, scope, runtime binding, and kill switch aligned with existing models and flows

## Constraints

- Keep Prompt 1 and Prompt 2 intact.
- Add only the cryptographic weakness detection capability from the task package.
- Do not bypass local provenance, scope, ROE, validation, approval, deployment, runtime binding, credential gates, or kill switch.
- No runtime self-modification.
- No uncontrolled plugin installation.
- Configuration and algorithm detection only.
- No brute-force attacks on live encryption.
- No decryption attempts.
- No custom cipher analysis.
- Do not change the existing `ssl-tls` runner unless strictly necessary for registration compatibility.
- Do not change the queued JWT runner.
- No live target actions outside safe/local/expliciet geautoriseerde validatie.

## Validation

- `python3 scripts/validate_backlog_tasks.py`
- `source .venv/bin/activate && python -m pytest api/tests/ -q`
- `git diff --check`

## Acceptance

- `crypto-audit` is registered in supported tools.
- `testssl.sh` and `ssh-audit` are used by the runner where applicable.
- Export-grade cipher, POODLE, BEAST, RC4, TLS 1.0/1.1, weak DH, short certificate key, and weak SSH algorithm findings are represented safely.
- Findings include remediation guidance with safer algorithm/configuration alternatives.
- `passive-crypto-audit` exists and is reachable through External Web and SSL/TLS wizard paths at any depth.
- Existing `ssl-tls`, JWT, runner, API, and assessment-chain tests do not regress.
