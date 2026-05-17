# Active Task

## Title

Cross-Target Provenance: Captured Values Carry Lineage Across Tasks (Phase 4 day 1)

## Goal

When a runner captures a value (JWT, cookie, internal hostname, credential) during one task, that value becomes a first-class graph entity with provenance pointing back to the originating task and the assistant decision that produced it. Subsequent tasks that use the value link to it explicitly so the AI can reason about cross-target chains (e.g. web token → internal hostname → port scan → SMB).

## Scope

- Extend `evidence_ingest` helpers (#322) to register captured values with `origin_task_id` and `origin_decision_id`.
- Update `exec_plan` runner to emit capture events as first-class graph entities (not just step-internal scratch).
- Update `target_intel` + `smart_web_probe` to consume captured values when present in the graph.
- Add a graph projection helper that shows captured-value lineage in the picker context.

## Constraints

- Extend existing evidence-graph + exec_plan surfaces — do NOT replace them. Per AGENT_SYSTEM_MAP §12 anti-pattern: don't write new evidence storage.
- Captured values include credentials/tokens — apply scope/ROE checks and credential vault patterns where they exist.
- Per `feedback_no_prescriptive_recipes` memory: emergent only; don't seed lineage patterns in code.

## Source Package

`codex/tasks/backlog-384-cross-target-provenance-tracking.json`

## Reference

- `api/app/services/evidence_ingest.py` (#322 — `make_observation`, `persist_runner_observations`, `load_run_observations`)
- `api/app/services/assessment_graph.py` (`build_normalized_evidence_graph`, `project_graph_for_picker` from #323)
- `workers/runners/exec_plan/runner.py` (the exec-plan engine with current per-step capture logic)
- `docs/checkpoints/2026-mythos-phase3-review.md` (Phase 3 GO decision; Phase 4 entry point)
- AGENT_SYSTEM_MAP §4 (Evidence model — what exists, post Phase-1 reality)

## Validation

- `python3 scripts/validate_backlog_tasks.py`
- `.venv/bin/pytest api/tests/test_cross_target_provenance.py api/tests/test_evidence_ingest.py`
- `python3 -m compileall -q api workers`
- `.venv/bin/ruff check api/app/services/evidence_ingest.py api/app/services/assessment_graph.py workers/runners/exec_plan/`
- `git diff --check`
