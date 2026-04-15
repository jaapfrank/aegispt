# Current State

## Architecture

AegisPT currently consists of:

- a FastAPI control plane
- SQLAlchemy models with Alembic migrations
- evidence-first runs, tasks, artifacts, findings, and report generation
- Prompt 1 methodology alignment across PTES, OWASP WSTG, NIST SP 800-115, and optional ASVS references
- Prompt 2 adaptive testing support through inventory, threat intelligence, relevance analysis, capability packs, validation, approval, deployment, and runtime pack binding
- a Prompt 3 Codex build lane that adds supervised pack refinement context, repository governance, and repo-backed Codex task management

## Implemented

- engagement and scope management
- run profiles, approvals, dispatch, cancellation, and kill switch handling
- evidence persistence and report export
- adaptive pack registry and promotion pipeline
- runtime pack binding and finding provenance
- read-only Codex pack review endpoints
- repo-backed Codex task files and safe task result planning
- workspace export and validation wrapper scripts for Codex-driven refinement
- a FastAPI-served operator console at `/app` with a mandatory assessment wizard, mission control, surface mapping, findings theater, evidence replay, pack forge, report center, explorer, and history/comparison views over existing backend contracts
- run-backed UI configuration storage through additive `configuration_json` on the existing run model
- report catalog metadata and report variants for executive, technical, evidence, and retest workflows
- finding theater and evidence replay API views derived from existing findings, tasks, artifacts, inventory, relevance, and pack provenance

## Partial

- Codex workspace export exists, but reviewed artifact re-import into existing pack artifacts is not yet implemented
- the operator console is now the primary product UI, but future work can still deepen live streaming, richer map overlays, and heavier dossier workflows
- future attack paths, identity awareness, risk scoring, continuous mode, customer memory, and integrations are prepared only as docs/placeholders

## Adaptive testing status

- inventory normalization: implemented
- threat intelligence ingestion: implemented
- relevance analysis: implemented
- capability factory: implemented
- pack validation / approval / deployment / rollback: implemented
- runtime binding: implemented
- adaptive provenance in findings and reports: implemented

## Capability factory status

The capability factory is operational and should remain authoritative for pack generation. Codex-driven work must layer on top of existing generated packs, not replace the capability factory or its metadata.

## Codex build lane status

- Codex build lane context endpoints: implemented
- repository governance files: implemented
- repo-backed Codex task interface: implemented
- safe export/validation wrappers: implemented
- sandbox: documented
- UI support requirements: documented and integrated into the primary operator console
- live runtime mutation from Codex: explicitly prohibited

## Known risks

- reviewed workspace artifacts still need a controlled import path back into the pack artifact store
- report-side PDF handling is still HTML-to-PDF oriented rather than a dedicated PDF generator
- task governance is file-backed and intentionally simple; future work may need stronger merge conflict handling
- future placeholder modules must not accidentally become de facto runtime systems before explicit activation
