# Codex UI Support

## Purpose

This document defines light operator-support requirements for the Codex build lane without turning Prompt 3 into a full UI build.

## Current implementation status

The repository now includes an initial operator console served by the FastAPI app at `/app`.

That console already exposes:

- a mandatory wizard for engagement, scope, inventory, adaptive planning, pack promotion, and run launch
- mission control summaries for runs, packs, inventory, relevance, internal validation, and Codex tasks
- drilldowns for findings, tasks, pack review, and report/evidence access
- a Codex build-lane panel that stays separate from active runtime execution
- operator-facing Pack Forge visibility for:
  - proposal / validation / approval / deployment lifecycle state
  - Codex suggestions tied to the selected pack and linked Codex task
  - generated-pack artifact preview with provenance and methodology tags
  - prepared-task commands, output files, guardrails, and the expected `validation-result.json` handoff after dry-run preparation

This baseline should be extended additively and should continue to reuse the existing pack registry, promotion flow, provenance model, and report services.

The Report Center now also surfaces a compact adaptive-change summary when a selected run is backed by a Codex-reviewed pack refinement task. That summary is derived from the existing pack binding, validation/approval/deployment trail, and repo-backed Codex task state instead of introducing a second reporting model.

The prepared-task result now also keeps the workspace export and validation-handoff path explicit:

- the dry-run command list includes the exact `scripts/export_codex_pack_workspace.sh` and `scripts/validate_codex_pack.sh` invocation
- the output-file list includes the expected workspace-side `validation-result.json`
- the exported workspace README repeats that same validation capture path so an operator can follow the handoff without guessing
- artifact-specific validation expectations now surface for the current supported rich artifacts:
  - `playwright_flow`: `has steps array`
  - `zap_job`: `has tool` and `has targets or note`
- the same expectations now appear in:
  - `GET /api/v1/packs/{id}/codex-context`
  - `GET /api/v1/packs/{id}/codex-review-bundle`
  - prepared task output inside Pack Forge

## Required support elements

- Codex suggestions panel
- generated pack preview
- validation status summary
- approve / reject actions that still use the existing pack lifecycle

## Suggestions panel

The Pack Forge suggestions panel now shows:

- active Codex task id and type
- linked pack id and version
- generation reason
- source inventory snapshot and relevance decision through the selected pack summary
- safe next actions derived from the existing pack lifecycle and prepared task result
- required operator-visibility badges and review sections from `operator_visibility`

## Generated pack preview

The Pack Forge generated-pack preview now shows:

- artifact list
- artifact type
- checksum
- provenance summary
- methodology tags
- content-shape hints (`text`, `json`, or metadata-only) without turning the preview into a second artifact editor

## Validation status

The Pack Forge lifecycle view now shows:

- latest validation result
- blocking issues
- whether approval is currently allowed
- whether deployment has already happened

## Report-side visibility

Report variants and the operator-facing Report Center now reuse the same governed adaptive-pack state to show:

- whether adaptive coverage is standard-only or bound through a reviewed pack
- the latest linked Codex task id, type, and prepared-review state when present
- the current pack governance status across validation, approval, and deployment
- whether any findings in the run currently inherit bound-pack provenance

This stays intentionally compact. Pack Forge remains the place for deep artifact review, while reports only summarize the approved change context that shaped adaptive coverage.

## Approve / reject actions

The UI should not invent a second approval model.

It should reuse:

- pack validation result
- pack approval history
- pack deployment status

## Validation evidence

The current Codex-visibility slice was revalidated on 2026-04-20 through:

- `api/tests/test_codex_tasks.py`
- `api/tests/test_codex_lane.py`
- targeted Pack Forge browser coverage in `ui/tests/test_product_feature_matrix_e2e.py`
- shell-script integration coverage in `api/tests/test_codex_tasks.py` against a live temporary FastAPI host
- an independent host-path validation through `scripts/run_host_api.sh` plus a real Playwright browser session against the started host
- an independent live-host HTTP/workspace proof for the richer `playwright_flow` and `zap_job` validation cues at `codex/results/live-host-codex-validation-hooks-20260420-014016.json`

## Non-goal

This document still does not authorize a second approval lane, a UI-only data model, or any live runtime mutation. Future UI work should deepen the current console rather than replacing the existing backend contracts.
