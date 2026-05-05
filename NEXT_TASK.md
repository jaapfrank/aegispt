# Active Task

## Title

Production-like deployment proof drill: prove hardened install assumptions instead of only documenting them

## Promoted From

`codex/tasks/backlog-238-production-deployment-proof-drill.json`

## Goal

Prove that AegisPT can be installed and operated in a production-like enterprise posture with TLS/proxy assumptions, database/artifact persistence, encryption, backup/restore, and offline-update boundaries evidenced rather than merely documented.

## Scope

Implement the active backlog package `codex/tasks/backlog-238-production-deployment-proof-drill.json`.

Expected slice:

- create or use a safe local production-like fixture for deployment proof
- validate health, migration state, configured public URL/TLS assumptions, secure cookie posture, database/artifact persistence, backup/restore smoke, and offline/manual update boundaries where available
- report unavailable infrastructure as exact blockers, not as readiness
- distinguish development-ready from enterprise-production-ready without shell spelunking
- do not add hosted SaaS, billing, external telemetry, production secret material, or unmanaged third-party plugins

## Constraints

- Keep Prompt 1 and Prompt 2 intact.
- Do not mutate active assessment runs.
- Do not touch live assessment targets.
- Do not print secrets, certificates, tokens, or customer evidence material.
- No runtime self-modification.
- No uncontrolled plugin installation.
- Do not remove finding schema fields.

## Validation

- `python3 scripts/validate_backlog_tasks.py`
- `source .venv/bin/activate && python -m pytest api/tests/test_settings.py -q`
- `bash scripts/verify_host.sh or documented production-like fixture equivalent`
- `git diff --check`

## Acceptance

- Production-like readiness is evidenced or blocked with exact missing prerequisites.
- Development-mode readiness is not confused with production hardening.
