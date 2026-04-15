# UI Assessment Wizard

## Purpose

The Assessment Wizard is the mandatory entry point for a new mission. It is the first screen at `/app` and it must be completed before the operator has a mission dossier with a run-backed source of truth.

## Steps

1. Assessment Type
2. Scope Input
3. Credentials / Access
4. Test Profile
5. Test Modules
6. Safety / Limits
7. Review / Confirm

## Source of truth

On confirmation, the wizard:

- creates or reuses the engagement
- records scope through the existing scope endpoint
- seeds the inventory model from reviewed wizard input
- creates the run with `configuration_json` on the existing run record

The run configuration now carries:

- assessment type
- target inputs
- access context references
- selected profile
- enabled modules
- safety settings
- ETA estimate

## UX rules

- guided language first
- only relevant scope fields shown
- live summary panel always visible
- validation errors shown inline
- smart profile presets allowed, but operator decisions stay explicit

## Security note

The current UI slice stores references and operator notes for credentials and sessions, not raw secret material. This keeps the wizard compatible with the current backend and evidence-first model without pretending a vault already exists.
