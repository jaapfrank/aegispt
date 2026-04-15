# Codex Operator Visibility

## Purpose

The Codex build lane should be visible to operators as a supervised pack-refinement step, not as a hidden automation layer.

## Minimum UI visibility

For any customer-specific pack under Codex refinement, the operator view should show:

- pack id, name, version, and current status
- generation mode
- latest validation status
- source inventory snapshot id
- relevance decision id
- threat-intel references
- methodology tags inherited by the pack
- runtime mutation blocked state

## Review panels

The operator-facing review view should expose:

- pack overview
- exported artifact list with type, checksum, and current status
- generated-versus-refined notes or diff summaries
- validation blockers and latest validation summary
- approval history
- deployment and rollback state

## Findings and report visibility

When a finding comes from adaptive coverage, the operator should still see the existing provenance fields:

- `finding_origin`
- `source_pack_id`
- `source_pack_version`
- `source_pack_artifact_id`
- `source_inventory_snapshot_id`
- `source_relevance_decision_id`

This keeps Prompt 2 provenance visible without introducing a second reporting layer.

## API support added for Prompt 3

The following read-only endpoints support UI and supervised build-lane views:

- `GET /api/v1/packs/{id}/codex-context`
- `GET /api/v1/packs/{id}/codex-review-bundle`

These endpoints do not mutate runtime state. They surface existing pack, artifact, validation, approval, and deployment data in a Codex-oriented review shape.

## UX guidance

The operator should feel like they are reviewing a controlled plan extension:

- show guardrails clearly
- show validation hooks clearly
- show approval/deploy actions separately from Codex refinement
- avoid presenting the build lane as autonomous runtime adaptation
