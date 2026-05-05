# Backlog 238 - Production-Like Deployment Proof Drill

Date: 2026-05-05

## Scope

Active task: `codex/tasks/backlog-238-production-deployment-proof-drill.json`.

This slice added and executed a safe-local production-like deployment proof. It did not install infrastructure, pull images, start a Compose/PostgreSQL runtime, mutate active assessments, touch live assessment targets, or expose secret/certificate/token material.

## Implementation

- Added `scripts/run_production_deployment_proof.py`.
- Added explicit deployment-hardening metadata for `enterprise_production_ready`, `readiness_boundary`, `blocking_reasons`, and `warning_reasons` so Settings and Diagnostics distinguish development-ready from enterprise-production-ready.
- Added release-readiness consumption of `codex/results/production-deployment-proof-latest.json` and `.md` for the `enterprise_deployment_hardening` claim.
- Documented the proof command in `docs/host_service_install.md`.
- Added focused tests for production proof output and release-readiness consumption.

## Proof Output

`python3 scripts/run_production_deployment_proof.py --output-json codex/results/production-deployment-proof-latest.json --output-md codex/results/production-deployment-proof-latest.md` produced:

- overall proof status: `degraded`
- enterprise-production-ready claim allowed for current host: `false`
- development mode kept separate from production hardening: `true`
- production TLS/proxy/PostgreSQL/S3 fixture: `ready`
- production air-gapped/offline-update fixture: `ready`
- unsafe production fixture: `blocked` with exact blocking reasons
- static Compose declarations: `ready`
- safe local backup/restore drill: `ready`
- Compose/PostgreSQL runtime restore proven: `false`
- plaintext secrets exposed: `false`

The Compose/PostgreSQL runtime restore blocker is intentional: no live Compose stack was started in this build-lane slice. The recorded next step is to run an explicitly approved local Compose fixture and capture `pg_dump`/restore plus MinIO artifact restore evidence.

## Live Acceptance

- `http://127.0.0.1:8000/health/live` was relevant and returned healthy.
- A current-code temporary API on `http://127.0.0.1:8020` confirmed both `/api/v1/settings/readiness` and `/api/v1/diagnostics` expose `deployment_hardening.metadata.readiness_boundary=development_ready_not_enterprise_production` and `enterprise_production_ready=false`.
- The temporary API was shut down after validation.

## Validation

- `python3 scripts/validate_backlog_tasks.py` passed before implementation with 250 queued task packages and exactly one active task.
- `source .venv/bin/activate && python -m pytest api/tests/test_settings.py -q` passed.
- `source .venv/bin/activate && python -m pytest api/tests/test_release_readiness.py scripts/tests/test_production_deployment_proof.py -q` passed as focused extra coverage.
- `python3 scripts/run_production_deployment_proof.py --output-json codex/results/production-deployment-proof-latest.json --output-md codex/results/production-deployment-proof-latest.md` passed as the documented production-like fixture equivalent to the broad host-tool `verify_host.sh` command.
- `python3 scripts/run_enterprise_release_readiness.py --output-json codex/results/enterprise-release-readiness.json --output-md codex/results/enterprise-release-readiness.md` passed and kept enterprise release-readiness `blocked` / `no-go`.
- `git diff --check` passed.

## Remaining Risk

- Current local host is still development-grade and must not be called enterprise-production ready.
- Live Compose/PostgreSQL/MinIO restore was not proven because this slice did not start the Compose runtime or pull/build infrastructure.
- External TLS certificates, proxy policy, database encryption, object-store encryption, and offline bundle custody still require operator/platform evidence.
- Enterprise release-readiness remains blocked by the existing accuracy and FP/FN claims.
