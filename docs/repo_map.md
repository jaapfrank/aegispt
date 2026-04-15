# Repository Map

## Purpose

This map makes the repository easier for Codex to navigate while keeping Prompt 1 and Prompt 2 foundations intact.

## Core runtime and control plane

- `api/app/` - FastAPI app, routers, schemas, and services
- `api/app/services/` - canonical service layer
- `api/app/routers/` - canonical API endpoints
- `api/app/schemas/` - canonical API and placeholder schemas
- `workers/` - execution and finding normalization paths
- `migrations/` - Alembic migrations

## Canonical documentation

- `docs/` - primary product, methodology, adaptive testing, Codex, and future architecture documentation
- `docs/runbooks/` - operational runbooks

## Codex governance and repo-driven workflow

- `AGENTS.md` - top-level Codex behavior constraints
- `CURRENT_STATE.md` - current architecture and implementation summary
- `NEXT_TASK.md` - single active task
- `TASK_QUEUE.md` - ordered backlog
- `DONE_LOG.md` - append-only change log
- `DECISIONS.md` - durable architectural decisions

## Codex working directories

- `codex/tasks/` - repo-backed structured task definitions
- `codex/results/` - prepared task results and safe command plans
- `codex/packs/` - future exported or staged pack workspaces
- `codex/templates/` - future template candidates
- `codex/flows/` - future Playwright/browser flow candidates
- `codex/rules/` - future Semgrep rule candidates

## Supporting scripts

- `scripts/export_codex_pack_workspace.sh` - export current pack context into a supervised workspace
- `scripts/validate_codex_pack.sh` - hand a pack back into the existing validation lane

## Duplication guidance

- methodology remains in the existing Prompt 1 layer
- adaptive pack lifecycle remains in the existing Prompt 2 layer
- Codex repo files supplement those layers and must not duplicate them
