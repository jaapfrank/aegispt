# Next Task

## Active Task

Controlled Codex Artifact Re-import

## Scope

Add a supervised mechanism to take reviewed Codex workspace artifacts and write them back into the existing capability pack artifact store before validation.

## Success Criteria

- reviewed exported artifacts can be re-imported into an existing capability pack without changing the pack registry or promotion model
- import stays inside the Codex build lane and does not affect active runtime behavior
- existing validation, approval, deployment, and runtime binding remain authoritative
- provenance and methodology metadata are preserved on re-imported artifacts
- regression tests cover the import path

## Files Likely Touched

- `api/app/routers/codex.py`
- `api/app/schemas/codex.py`
- `api/app/services/codex_tasks.py`
- `scripts/export_codex_pack_workspace.sh`
- `docs/codex_build_lane_architecture.md`
- `docs/codex_repo_working_conventions.md`

## Must Not Touch

- `api/app/methodology.py`
- `api/app/models/control.py`
- `api/app/schemas/findings.py`
- `api/app/services/reports.py`
- `migrations/versions/20260415_0003_methodology_alignment.py`
- existing Prompt 2 inventory, threat-intel, relevance, pack registry, promotion pipeline, and runtime binding logic except for narrowly scoped integration points
