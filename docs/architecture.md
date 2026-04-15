# Architecture

## Overview

AegisPT is organized into five planes:

- Control plane
- Reasoning plane
- Execution plane
- Evidence plane
- UI plane

The current scaffold implements the first operational slice of the control plane, seeded run profiles, approval-gated run planning, explicit dispatch, executable `httpx`, `nuclei`, `semgrep` and ZAP API execution paths, curated internal validation orchestration, centralized policy limits, a global execution kill switch, run cancellation, MinIO-backed artifact persistence, redaction before storage for textual evidence, curated provenance for Nuclei templates plus Semgrep rules, and additive methodology metadata aligned to PTES, OWASP WSTG, and NIST SP 800-115.

## Service map

### API service

Responsibilities:

- engagements
- scopes
- run profiles
- run requests
- internal validation scenarios and sessions
- internal validation step approvals and preflight checks
- approval-gated queueing
- cancellation and kill-switch enforcement
- readiness and liveness
- policy hooks
- methodology metadata normalization for findings and reports
- audit event creation

### Worker service

Responsibilities:

- receive structured jobs
- execute approved runners
- capture execution metadata
- emit evidence artifact metadata

### Postgres

Responsibilities:

- system of record for engagements, runs, approvals and findings

### Redis

Responsibilities:

- broker for asynchronous tasks

### MinIO

Responsibilities:

- object storage for artifacts, replay bundles and reports
- serve stored runner artifacts back through the API when the operator needs raw evidence

### ZAP daemon

Responsibilities:

- isolated DAST runner endpoint for approval-gated web validation
- API access stays behind the internal Compose network and still requires a ZAP API key

## Control flow

1. Operator creates an engagement.
2. Operator submits scope as code.
3. Operator selects a run profile.
4. Passive runs queue immediately; active and intrusive runs wait for approvals.
5. Control plane materializes structured tasks from the approved scope.
6. Operator or automation dispatches queued tasks explicitly.
7. Worker executes supported tasks through runner wrappers.
8. Artifacts are hashed and stored.
9. Findings link back to evidence and replay metadata.

For the current ZAP slice, overlapping scope seeds such as `example.com` and `https://example.com` collapse into one planned ZAP target, and active ZAP runs are dispatched as one consolidated task per run so the shared daemon session stays deterministic.
For the current active ZAP slice, `active-web-zap-active` adds a spider plus active scan path that still requires approval before dispatch and records its scan mode in execution metadata and artifacts.
For the current Nuclei slice, the worker only executes the curated built-in template and stores its template id, source and digest alongside the resulting evidence metadata.
For the current Semgrep slice, the worker accepts allowlisted `paths`, scans the read-only repository mount under `/workspace/repo`, stores JSON evidence in MinIO and normalizes findings into the same run-level model as the web pipelines.
For the current internal validation slice, curated sessions expose ordered scenario steps that each require their own approvals, launch standard run profiles and only unlock the next step after the previous launched run completes.
For the current methodology alignment slice, findings can additionally store PTES phase, NIST phase, WSTG references, optional ASVS references, control family, and methodology tags without changing the existing evidence-first execution flow.

## Current API slice

Current implemented endpoints:

- `GET /`
- `GET /health/live`
- `GET /health/ready`
- `POST /api/v1/engagements`
- `POST /api/v1/engagements/{engagement_id}/scope`
- `GET /api/v1/run-profiles`
- `GET /api/v1/engagements/{engagement_id}/runs`
- `POST /api/v1/engagements/{engagement_id}/runs`
- `GET /api/v1/runs/{run_id}`
- `POST /api/v1/runs/{run_id}/approvals`
- `POST /api/v1/runs/{run_id}/cancel`
- `POST /api/v1/runs/{run_id}/dispatch`
- `GET /api/v1/internal-validations/scenarios`
- `GET /api/v1/engagements/{engagement_id}/internal-validations`
- `POST /api/v1/engagements/{engagement_id}/internal-validations`
- `GET /api/v1/internal-validations/{session_id}`
- `POST /api/v1/internal-validations/{session_id}/steps/{step_id}/approvals`
- `POST /api/v1/internal-validations/{session_id}/steps/{step_id}/execute`
- `GET /api/v1/tasks/{task_id}`
- `GET /api/v1/artifacts/{artifact_id}/content`
- `GET /api/v1/runs/{run_id}/findings`
- `GET /api/v1/findings/{finding_id}`
- `PATCH /api/v1/findings/{finding_id}`
- `GET /api/v1/runs/{run_id}/report?format=markdown|html`

## Runner contract

All runners must follow these rules:

- accept structured input only
- re-check scope before execution
- capture tool version and runtime identity
- store stdout, stderr and exit code
- produce evidence artifact metadata with hashes
- redact sensitive textual output before storage
- preserve template provenance metadata for curated Nuclei evidence
- preserve rule provenance metadata for curated Semgrep evidence
- avoid free-form shell interpolation from user input

## Initial domain objects

- `engagements`
- `scopes`
- `run_profiles`
- `runs`
- `approvals`
- `internal_validation_sessions`
- `internal_validation_steps`
- `internal_validation_approvals`
- `audit_events`
- `secrets_refs`
- `tasks`
- `tool_executions`
- `evidence_artifacts`
- `findings`

## Deferred areas

These are intentionally not implemented in the first slice:

- multi-user UI
- Kubernetes manifests beyond placeholders
- deeper runner coverage beyond `httpx`, `nuclei`, `semgrep` and the first ZAP API slice
- multi-step approval workflows beyond `run.launch`
- free-form or agent-driven internal validation planning beyond curated scenarios
- external vault integration
