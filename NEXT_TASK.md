# Active Task

## Title

Evidence-Graph Entity Ingestion Helpers Shared by Runners

## Goal

Implement a thin shared helper module that runners call to register structured graph entities (asset, identity, credential_ref, endpoint, finding) and relationships during execution, so the normalized graph accumulates first-class entities rather than being reconstructed from stdout heuristics.

## Scope

- Create `api/app/services/evidence_ingest.py` (helper module + typed contract)
- Extend `api/app/services/assessment_graph.py` to read emitted entities and merge with existing source-graph nodes
- Migrate 3-5 pilot runners (per Adoption Plan Section 6.1: target_intel, smart_web_probe, http_fetch_backend, xss_proof, exec_plan)
- Alembic migration for new `evidence_observations` table

## Constraints

- Additive only. Existing runners that do not opt in continue to work via source-graph reconstruction path.
- No picker changes (that is task #323).
- No new node types beyond those enumerated in Adoption Plan Section 5 (asset, api, identity, credential_hint, tech_signal, observed_url).
- Helper must be additive — existing runner contracts unchanged.

## Source Package

`codex/tasks/backlog-372-evidence-graph-entity-ingestion-helpers.json`

## Reference

`docs/evidence_graph_adoption_plan.md` — full audit and design

## Validation

- `python3 scripts/validate_backlog_tasks.py`
- `.venv/bin/pytest api/tests/test_evidence_ingest.py api/tests/test_assessment_graph.py`
- `python3 -m compileall -q api workers`
- `.venv/bin/ruff check api/app/services/evidence_ingest.py api/app/services/assessment_graph.py`
- `git diff --check`
