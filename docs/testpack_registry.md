# Testpack Registry

## Purpose

The registry is the system of record for generated and approved adaptive packs.

It exists so operators can answer:

- what was generated
- from which evidence and planning inputs
- which validation result applied
- who approved it
- where it was deployed
- what can be rolled back

## Registry entities

Primary records:

- `capability_packs`
- `capability_pack_artifacts`
- `capability_pack_validation_results`
- `capability_pack_approvals`
- `capability_pack_deployments`

## Status model

Supported pack statuses:

- `proposed`
- `generated`
- `validation_failed`
- `validated`
- `approved`
- `deployed`
- `retired`
- `superseded`

## Required traceability

Each pack tracks:

- `pack_id`
- `version`
- `parent_pack_id`
- `engagement_id`
- `generated_by`
- `generated_at`
- `source_inventory_snapshot_id`
- `source_threat_intel_refs`
- `methodology_tags`
- `validation_results`
- `approval history`
- `deployment targets`
- `rollback information`

## Registry behavior

- generation creates a versioned pack record and artifact set
- validation appends a validation result and updates pack state
- approval appends approval history and updates pack state
- deployment creates an explicit deployment record
- rollback creates a new deployment record that points back to the rolled-back pack

