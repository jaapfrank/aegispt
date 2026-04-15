# Capability Factory

## Purpose

The Capability Factory turns a relevance decision into a versioned, reviewable, reproducible customer-specific pack.

It runs after inventory and relevance analysis, but before active validation.

## What a capability pack is

A capability pack is a generated bundle of assessment artifacts tied to one engagement context.

Current supported artifact classes:

- `nuclei_template`
- `zap_job`
- `playwright_flow`
- `semgrep_rule`
- `scanner_profile`
- `workflow`
- `metadata`

## Pack record

Each `capability_pack` stores:

- `engagement_id`
- `relevance_decision_id`
- `source_inventory_snapshot_id`
- `parent_pack_id`
- `name`
- `version`
- `status`
- `generated_by`
- `generation_mode`
- `description`
- `source_threat_intel_refs_json`
- `methodology_tags`
- `manifest_json`
- `provenance_json`

## Lifecycle

Pack lifecycle states:

- `proposed`
- `generated`
- `validation_failed`
- `validated`
- `approved`
- `deployed`
- `retired`
- `superseded`

## Provenance

Every pack must remain traceable back to:

- the inventory snapshot used
- the relevance decision used
- the threat intel references used
- the actor and generation mode used

That provenance is stored in `manifest_json` and `provenance_json`, and later surfaced in reporting.

## Methodology mapping

Packs do not define a new methodology layer.

They inherit and carry the Prompt 1 fields already used by findings and reports:

- PTES phase
- NIST phase
- WSTG reference and version where applicable
- optional ASVS reference
- methodology tags
- control family

## Non-goals

The Capability Factory does not:

- deploy directly into a live assessment runtime
- hot-install plugins mid-run
- bypass validation or approval

