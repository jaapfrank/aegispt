# Secret Handling Baseline

## Purpose

This hardening phase adds a safer baseline for wizard-entered credentials and run access context without turning AegisPT into a full vault platform.

## What changed

Wizard access inputs may still accept:

- usernames and role labels
- passwords
- API keys
- bearer tokens
- cookie or session material
- explicit external secret references

When a run is created, raw sensitive values are no longer meant to stay in normal run configuration state. They are materialized into `SecretRef` records and the run configuration keeps only protected bindings and storage metadata.

## Storage modes

Two storage modes now exist:

- `external_pointer`
  - for values already expressed as references such as `vault://...`, `env://...`, `ref://...`
- `encrypted_local`
  - for direct secret material that needs a protected local baseline instead of plaintext persistence

## Where data lives

- displayable run configuration:
  - `runs.configuration_json`
  - contains usernames, roles, operator notes, and `secret_bindings`
  - raw secret values are sanitized out of normal API responses
- sensitive secret records:
  - `secrets_refs`
  - track purpose, kind, storage backend, label, and encrypted value when locally protected

## Encryption baseline

- local encrypted storage uses Fernet-compatible encryption
- set `LOCAL_SECRET_ENCRYPTION_KEY` explicitly in real deployments
- a local fallback key exists only as a development baseline and should not be treated as enterprise secret management

## Operator-facing impact

- the wizard can still accept direct values when needed for practical operator workflows
- after run creation, the UI and normal run API surface protected bindings rather than plaintext
- Explorer and run summaries can show protected binding counts without revealing secret content

## Non-goals

This baseline does not add:

- a multi-tenant enterprise vault
- external secret rotation
- HSM or cloud KMS integration
- fine-grained secret lease workflows

Those can be layered later without changing the existing evidence-first run model.
