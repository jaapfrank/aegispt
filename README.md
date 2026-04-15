# AegisPT

AegisPT is an evidence-first penetration testing orchestration platform for Kali Linux. It wraps proven security tools behind a controlled control plane, stores replayable evidence for every finding, and keeps approvals and scope enforcement ahead of automation.

## Current status

The repository now delivers the first operational platform slice, the first code-analysis pipeline and curated internal validation v1. The concept brief lives in `AegisPT.md`, the practical build plan lives in `docs/AegisPT-Implementation-Runbook.md`, and the current codebase provides:

- host bootstrap on Kali
- Docker Compose infrastructure
- a minimal FastAPI control plane
- default run profiles and approval-gated run requests
- executable `httpx`, `nuclei`, `semgrep` and ZAP API worker runners with task dispatch
- centralized policy limit normalization, an execution kill switch and run cancellation support
- MinIO-backed artifact persistence with API download support
- findings normalization for Nuclei matches, Semgrep matches and ZAP alerts
- finding status workflow and run-level finding counts
- on-demand Markdown and HTML run report export
- baseline redaction before storage for textual runner output and artifacts
- curated Nuclei template provenance metadata on stored evidence
- curated Semgrep rule provenance metadata on stored evidence
- curated internal validation scenarios with preflight checks, step approvals and step-to-run evidence linkage
- additive methodology alignment to PTES, OWASP WSTG, and NIST SP 800-115, with optional ASVS references on findings
- adaptive post-inventory testing support with inventory snapshots, threat intelligence records, relevance decisions, capability packs, validation gates, deployment records, and runtime pack binding
- CI and verification scripts

## Canonical Kali layout

Use these paths on the Kali VM so source, runtime data and environment files stay separated:

- `/opt/aegispt/repo` for the repository
- `/opt/aegispt/bootstrap` for copied bootstrap assets
- `/srv/aegispt/env` for env files and secret references
- `/srv/aegispt/postgres` for PostgreSQL data
- `/srv/aegispt/minio` for MinIO data
- `/srv/aegispt/reports` and `/srv/aegispt/artifacts` for operator outputs

## Design goals

- Evidence-first findings, not AI-first guessing
- Strict scope and approval controls
- Replayable runs with hashed artifacts
- Reusable Kali operator VM
- Gradual rollout from passive to active workflows

## Repository layout

```text
.
├── AegisPT.md
├── README.md
├── alembic.ini
├── api/
├── docs/
├── infra/
├── migrations/
├── requirements/
├── scripts/
└── workers/
```

## Quick start

### 1. Bootstrap the Kali host

Run the host scripts from the repository root on the Kali VM:

```bash
bash scripts/bootstrap_kali_host.sh
bash scripts/install_security_tools.sh
bash scripts/init_runtime_dirs.sh
bash scripts/verify_host.sh
```

### 2. Prepare the Python environment

```bash
bash scripts/setup_python_dev.sh
source .venv/bin/activate
alembic upgrade head
```

If you are upgrading an older Compose PostgreSQL database that was originally created with `AUTO_CREATE_TABLES=true` before Alembic state existed, verify the schema first and run `alembic stamp head` once before future upgrades.

### 3. Start the local stack

```bash
bash scripts/generate_compose_env.sh
docker-compose -f infra/compose/docker-compose.yml --env-file infra/compose/.env up --build
```

### 4. Run the tests

```bash
pytest
```

### 5. Inspect the catalogs

```bash
curl http://127.0.0.1:8000/api/v1/run-profiles
curl http://127.0.0.1:8000/api/v1/internal-validations/scenarios
```

### 6. Dispatch a queued passive run

The Compose stack is intended to use `TASK_DISPATCH_MODE=dramatiq`, so the API can hand queued tasks to the worker through Redis.

### 7. Export a run report

```bash
bash scripts/export_run_report.sh "${RUN_ID}" markdown
```

## First implementation slice

The first delivery slice is intentionally narrow:

1. Control plane skeleton
2. Postgres, Redis and MinIO wiring
3. Health endpoints
4. Engagement and scope endpoints
5. Run profile catalog and approval-gated run requests
6. Explicit run dispatch and task inspection
7. Executable `httpx`, `nuclei`, `semgrep` and ZAP API runners
8. Verification scripts and CI

This slice now includes passive web validation, approval-gated ZAP validation, passive Semgrep code scanning, evidence persistence, findings normalization and report export.

## Key documents

- `AegisPT.md`
- `docs/AegisPT-Implementation-Runbook.md`
- `docs/Kali-VM-Reuse-Guide.md`
- `docs/architecture.md`
- `docs/methodology_mapping.md`
- `docs/testing_coverage_matrix.md`
- `docs/methodology_alignment_summary.md`
- `docs/inventory_model.md`
- `docs/threat_intel_model.md`
- `docs/relevance_engine.md`
- `docs/capability_factory.md`
- `docs/testpack_registry.md`
- `docs/promotion_pipeline.md`
- `docs/codex_build_lane.md`
- `docs/runtime_pack_binding.md`
- `docs/operator_flow_adaptive_testing.md`
- `docs/adaptive_testing_summary.md`
- `docs/threat-model.md`
- `docs/runbooks/README.md`
- `docs/runbooks/passive-web-validation-workflow.md`
- `docs/runbooks/code-semgrep-validation-workflow.md`
- `docs/runbooks/internal-validation-workflow.md`

## Notes

- This scaffold defaults to a SQLite development database when no `DATABASE_URL` is configured, so local tests can run without Docker.
- Production intent remains PostgreSQL, Redis, MinIO and isolated runners.
- The current execution slice now covers `httpx`, `nuclei`, `semgrep`, an approval-gated ZAP API crawl with passive alert collection, MinIO-backed artifact persistence, redaction before storage and report export.
- Active ZAP scanning is now also available behind explicit approval through `active-web-zap-active`, while `EXECUTION_KILL_SWITCH=true` blocks new dispatches globally.
- Curated internal validation now reuses the same run, task, artifact and finding model through `curated-code-validation` and `curated-web-validation`.
- The methodology layer is an alignment patch, not a new subsystem: findings, reports, and workflow language now map cleanly to PTES, OWASP WSTG, and NIST SP 800-115 while preserving the current evidence-first architecture.
- The adaptive testing lane is also additive: inventory and threat intelligence can produce customer-specific packs, but only deployed pack versions can bind to runs and the runtime never self-modifies during an active assessment.
