# UI Run Configuration Flow

## Purpose

This document explains how UI decisions become durable run configuration without introducing a second planning model outside the existing run architecture.

## Flow

1. Operator completes the Assessment Wizard
2. UI derives the execution lane from the selected profile and safety settings
3. UI creates or reuses the engagement
4. UI persists scope through the existing scope contract
5. UI seeds inventory from reviewed target input
6. UI creates the run with:
   - `profile_name`
   - `source_inventory_snapshot_id`
   - `configuration_json`

## Stored run configuration

`configuration_json` is the UI-facing source of truth for:

- assessment type
- test profile
- execution profile mapping
- targets
- access references
- enabled modules
- safety limits
- ETA estimate

## Non-goals

- no parallel run planner model
- no runtime mutation from UI state
- no replacement of existing scope, pack, or approval flows

## Report inheritance

Reports now read the stored run configuration so the report center, mission control, and exported outputs stay aligned on the same mission definition.
