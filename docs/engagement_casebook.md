# Engagement Memory and Casebook

The engagement casebook stores non-secret, evidence-linked memory for one tenant-bound engagement. It helps AI planning reuse known architecture, blocked paths, accepted gaps, resolved findings, target context, and operator constraints without treating memory as proof.

## Boundaries

- Casebook entries are scoped to `engagement_id` and `tenant_id`.
- Every entry requires at least one source reference.
- Casebook memory is planning input only.
- Casebook memory must not broaden scope, grant approvals, dispatch work, mutate runtime state, or bypass the kill switch.
- Credential values, session material, tokens, cookies, private keys, authorization headers, and secret-like fields are rejected.

## Entry Types

Supported entry types are:

- `architecture_note`
- `blocked_path`
- `accepted_gap`
- `resolved_finding`
- `operator_constraint`
- `target_context`

## Planner Use

`api/app/services/ai_planner.py` includes casebook context in target context document provenance under `casebook_context`. That context is marked `planning_input_only=true` and `not_evidence=true`. Source references from the casebook are not copied into the target context document evidence refs, so reports and findings still need direct evidence IDs.

## Service

The service lives in `api/app/services/engagement_casebook.py`.

It provides:

- `create_casebook_entry()`
- `build_casebook_from_engagement()`
- `list_casebook_entries()`
- `casebook_context_for_run()`

The implementation uses the existing SQLAlchemy model layer and does not touch secret storage or runner execution code.
