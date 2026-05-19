# AegisPT Production-Like Deployment Proof

- Generated: `2026-05-05T18:39:50+00:00`
- Overall proof status: `degraded`
- Enterprise-production-ready claim allowed for current host: `false`
- Development mode kept separate from production hardening: `true`
- Compose/PostgreSQL runtime restore proven: `false`

## Current Host

- Deployment hardening status: `degraded`
- Boundary: `development_ready_not_enterprise_production`
- Summary: Development deployment is allowed, but production hardening is not fully declared.

## Fixture Proof

### production_tls_proxy_s3_postgres

- Status: `ready`
- Enterprise production ready: `true`
- Blocking reasons: none
- Warning reasons: none

### production_airgapped_offline_updates

- Status: `ready`
- Enterprise production ready: `true`
- Blocking reasons: none
- Warning reasons: none

### unsafe_production_blocks

- Status: `blocked`
- Enterprise production ready: `false`
- Blocking reasons: production public access must use HTTPS behind a declared trusted reverse proxy, secure browser cookie/session posture is not declared, SQLite database is not encrypted; set AEGISPT_DB_KEY or use a managed encrypted database., Production S3/MinIO artifact storage does not enforce or confirm encryption., air-gapped mode needs both offline feed/template and manual tool update paths
- Warning reasons: trusted enterprise CA bundle path is not declared

## Persistence

- Safe local backup/restore drill: `ready`
- Artifact hash verified: `true`
- Finding evidence reference verified: `true`
- Plaintext secrets exposed: `false`
- Compose/PostgreSQL runtime restore: `blocked`
- Compose/PostgreSQL next step: Run an explicitly approved local Compose fixture, capture pg_dump/restore and MinIO artifact restore evidence, then attach that output under codex/results/.

## Live Acceptance

- Live API status: `ready`
- Health status: `200`
- Runtime state: `healthy`

## Boundary

This proof is safe-local and fail-closed. It does not install infrastructure, pull images, run live targets, mutate active assessments, expose secret material, or turn development mode into an enterprise-production claim.
