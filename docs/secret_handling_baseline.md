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

Three storage modes now exist:

- `external_pointer`
  - for values already expressed as references such as `vault://...`, `env://...`, `ref://...`
- `encrypted_local`
  - for direct secret material that needs a protected local baseline instead of plaintext persistence
- `deployment_key_encrypted`
  - for direct secret material encrypted with an explicit deployment key rather than the local development key

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
- `SECRET_MATERIALIZATION_MODE=deployment_key` enables deployment-key-backed encryption for direct secret material when `DEPLOYMENT_SECRET_ENCRYPTION_KEY` is set
- `REQUIRE_DEPLOYMENT_SECRET_ENCRYPTION_KEY=true` makes missing deployment-key configuration fail safely for direct secret material instead of falling back to local encryption
- if deployment-key mode is requested without a deployment key and `REQUIRE_DEPLOYMENT_SECRET_ENCRYPTION_KEY` is false, AegisPT falls back to `encrypted_local` and marks that fallback in safe `secret_storage` metadata
- external pointers such as `vault://...` remain references and do not require the deployment encryption key because AegisPT is not storing their raw value
- a local fallback key exists only as a development baseline and should not be treated as enterprise secret management
- display labels never include suffixes from direct secret material; they only identify the protected binding kind and backend

## Operator-facing impact

- the wizard can still accept direct values when needed for practical operator workflows
- after run creation, the UI and normal run API surface protected bindings rather than plaintext
- Explorer and run summaries can show protected binding counts without revealing secret content
- external pointers such as `vault://...` remain references, while direct passwords, API keys, bearer tokens, and session material are encrypted behind `SecretRef` records

## ChatGPT OAuth token handling

`AI_PROVIDER=chatgpt_oauth` uses the same encrypted `SecretRef` materialization path. The OAuth flow stores the temporary PKCE verifier as `purpose = chatgpt_oauth.pkce_state` and the connected ChatGPT token set as `purpose = ai_provider.chatgpt_oauth`.

When an encrypted ChatGPT OAuth token set already exists for another engagement, AegisPT may reuse that provider session for the selected engagement instead of forcing another browser login. Reuse copies the decrypted token set only inside the backend and immediately stores it as a separate encrypted `SecretRef` for the target engagement. Raw token material is still never returned to APIs, UI, reports, MCP context, logs, or tests.

The encrypted token set contains `access_token`, `refresh_token`, `expires_at`, and `account_id`. Safe metadata may expose only provider name, account identifier, expiry timestamp, and `token_exposed = false`; raw tokens are not returned from auth status, run APIs, reports, MCP context, UI surfaces, or tests.

Automatic refresh updates the same encrypted token sink before expiry. If `EXECUTION_KILL_SWITCH=true`, ChatGPT OAuth provider calls are blocked before token refresh or `chatgpt.com/backend-api` requests are attempted.

The browser authorization flow uses the Codex-compatible local callback URL by default: `http://localhost:1455/auth/callback`. AegisPT starts a local listener for that callback during connection setup and still stores only the exchanged token set in encrypted `SecretRef` records.

## Instance settings secret handling

The operator Settings screen stores tenant-scoped defaults in `instance_settings`. Non-sensitive defaults are persisted as typed JSON values, while sensitive provider and integration fields store only encrypted material plus safe labels and metadata.

Sensitive settings use the same Fernet-backed encryption helpers and deployment-key mode as run secret materialization: `encrypted_local` by default, or `deployment_key_encrypted` when `SECRET_MATERIALIZATION_MODE=deployment_key` and `DEPLOYMENT_SECRET_ENCRYPTION_KEY` are configured. API reads return `configured`, `masked_value`, storage source, and `sensitive_plaintext_exposed = false`; they never return the raw secret.

## Non-goals

This baseline does not add:

- a multi-tenant enterprise vault
- a vault administration UI
- external secret rotation
- HSM or cloud KMS integration
- fine-grained secret lease workflows

Those can be layered later without changing the existing evidence-first run model.
