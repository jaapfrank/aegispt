# Codex Task Interface

## Purpose

Codex tasks must be structured and reviewable. The repository should define work clearly so Codex does not have to infer hidden scope.

## Canonical structure

```json
{
  "task_type": "...",
  "scope": "...",
  "inputs": {},
  "constraints": {},
  "expected_output": {}
}
```

## Required metadata

Prompt 3 extends the canonical task with controlled build-lane metadata:

- `generated_by`
- `generation_reason`
- `source_context`
- `validation_status`
- `approval_status`

Repo-backed backlog task packages should also add:

- `id`
- `task_file`
- `title`
- `goal`
- `status`
- `success_criteria`
- `likely_touched_files`
- `must_not_touch`
- `validation`
- `promotion_requirements`
- `out_of_scope`

## Source context

`source_context` should point back to existing Prompt 2 state where relevant:

- `pack_id`
- `pack_version`
- `inventory_snapshot_id`
- `relevance_decision_id`
- `threat_intel_refs`

## Example

```json
{
  "task_type": "pack_refinement",
  "scope": "Refine exported adaptive pack artifacts for a customer-specific authorization scenario.",
  "inputs": {
    "base_url": "http://127.0.0.1:8000"
  },
  "constraints": {
    "runtime_mutation": false,
    "protected_files": [
      "api/app/methodology.py",
      "api/app/models/control.py",
      "api/app/schemas/findings.py",
      "api/app/services/reports.py"
    ]
  },
  "expected_output": {
    "updated_artifacts": [
      "playwright_flow",
      "zap_job"
    ],
    "validation_required": true
  }
}
```

## Repo-backed storage

The repository-backed task interface uses:

- `codex/tasks/*.json` for task definitions
- `codex/results/*.json` for prepared run results
- `NEXT_TASK.md` for the single active human-readable task

For anti-drift backlog control:

- `TASK_QUEUE.md` should point one-to-one to queued `codex/tasks/backlog-*.json` task packages
- `NEXT_TASK.md` should remain the only active human-readable task
- `python3 scripts/validate_backlog_tasks.py` should pass before queue promotion or queue reordering

## API support

Minimal supporting endpoints:

- `POST /api/v1/codex/tasks`
- `GET /api/v1/codex/tasks/{id}`
- `POST /api/v1/codex/tasks/{id}/run`
- `GET /api/v1/codex/tasks/{id}/result`
- `POST /api/v1/packs/{pack_id}/codex-reimport`

The `run` endpoint prepares safe commands and validation handoff. It is not a live runtime mutation path.

## Controlled artifact reimport

Validated Codex workspace output may be staged back into the pack lifecycle only
through `POST /api/v1/packs/{pack_id}/codex-reimport`.

Required input:

- the source `pack_version`
- optional `codex_task_id`
- the `validation-result.json` payload from the existing pack validation lane
- one or more artifacts already present in the source pack, identified by
  `artifact_type` and `logical_name`
- optional operator notes and change summary

Safety rules:

- missing, failed, mismatched, or blocking validation-result data is rejected
- reimport does not edit the source pack in place
- reimport creates a generated child pack with `generation_mode = codex-reimport`
- imported artifacts preserve parent pack, parent artifact, task, validation, and
  operator-note provenance
- the child pack has no copied approval, deployment, or runtime binding state
- the child pack must still pass the normal validate, approve, deploy, and
  runtime binding gates before any assessment can use it
- deployed runtime packs are never mutated by Codex reimport

Pack Forge exposes this as a staged child-pack action after a Codex task is
prepared and a passing validation result exists. External workspace clients may
post edited artifact content directly to the same API, but the resulting pack
remains staged until the normal pack lifecycle completes.
