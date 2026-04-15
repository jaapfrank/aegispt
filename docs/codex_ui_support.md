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

This baseline should be extended additively and should continue to reuse the existing pack registry, promotion flow, provenance model, and report services.

## Required support elements

- Codex suggestions panel
- generated pack preview
- validation status summary
- approve / reject actions that still use the existing pack lifecycle

## Suggestions panel

Show:

- active Codex task id and type
- linked pack id and version
- generation reason
- source inventory snapshot and relevance decision
- safe next actions from the prepared task result

## Generated pack preview

Show:

- artifact list
- artifact type
- checksum
- provenance summary
- methodology tags

## Validation status

Show:

- latest validation result
- blocking issues
- whether approval is currently allowed

## Approve / reject actions

The UI should not invent a second approval model.

It should reuse:

- pack validation result
- pack approval history
- pack deployment status

## Non-goal

This document still does not authorize a second approval lane, a UI-only data model, or any live runtime mutation. Future UI work should deepen the current console rather than replacing the existing backend contracts.
