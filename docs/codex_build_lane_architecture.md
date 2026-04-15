# Codex Build Lane Architecture

## Purpose

The Codex build lane sits between the existing adaptive planning stack and the deterministic runtime. It prepares changes through the repository and existing pack lifecycle without changing runtime behavior during active assessments.

## Flow

```text
Inventory Snapshot
        |
        v
Threat Intel + Relevance
        |
        v
Capability Factory
        |
        v
Capability Pack Registry
        |
        v
Codex Build Lane
  - repo-backed task
  - workspace export
  - supervised refinement
  - validation handoff
        |
        v
Existing Validation / Approval / Deployment
        |
        v
Runtime Pack Binding
        |
        v
Deterministic Assessment Runtime
```

## Separation from runtime

The Codex build lane is not part of live execution.

It may:

- export existing packs for review
- generate or refine build-lane artifacts
- plan safe commands
- invoke existing validation hooks through the approved pipeline

It may not:

- mutate active runtime behavior
- hot-load new execution logic during a run
- bypass promotion or runtime binding

## Integration points

The lane reuses:

- Prompt 2 capability packs
- Prompt 2 pack registry states
- Prompt 2 validation, approval, deployment, and rollback flow
- Prompt 1 methodology metadata and Prompt 2 provenance fields

## Repository-driven control

Future Codex runs should be driven by:

- `AGENTS.md`
- `CURRENT_STATE.md`
- `NEXT_TASK.md`
- `TASK_QUEUE.md`
- `DONE_LOG.md`
- `DECISIONS.md`
- `codex/tasks/*.json`

## Minimal task API

Prompt 3 adds a minimal Codex task interface for repository-backed work:

- `POST /api/v1/codex/tasks`
- `GET /api/v1/codex/tasks/{id}`
- `POST /api/v1/codex/tasks/{id}/run`
- `GET /api/v1/codex/tasks/{id}/result`

These endpoints prepare and track build-lane work. They do not create a second runtime or second promotion system.
