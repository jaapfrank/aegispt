# Active Task

## Title

Operator-credentialed auth path for login-only targets (closes the \#328/\#329 emergent-registration-only gap) (backfill 4 of 6)

## Goal

`auth_discoverer.acquire_session()` currently does EMERGENT registration only — it creates a new user via the discovered register form, then attaches the resulting session to the http client. Real-world live targets (DVWA, customer staging, internal corporate apps) frequently have NO registration flow; they only expose login with pre-existing credentials. `acquire_session` correctly returns None on those, but the entire universal-auth pipeline (the 5 migrated probes from \#328, all downstream cross-target tasks) silently no-ops. This task adds a second strategy — operator-supplied credentials — wired through the existing `acquire_session` contract, so the same probes work on login-only targets.

## Scope

- Extend `api/app/services/auth_discoverer.py` with `acquire_session_with_credentials(base_url, *, username, password, scope_allowlist=None, ...)` that re-uses `fingerprint_application` + `build_recipe` but POSTs to the LOGIN form (not register) with operator-provided credentials.
- Credentials are pulled from the existing `run_credential_vault` keyed by (run_id, target_id).
- Update `acquire_session()` to: (1) check if credentials are present in the vault for the target, (2) if yes, prefer the login path, (3) if no, fall back to the existing emergent-registration path.
- Per `feedback_no_prescriptive_recipes` memory: no app-specific seeds. The LOGIN recipe is built by Claude Haiku from the fingerprint exactly like the REGISTER recipe is. Operator-supplied credentials are per-run inputs, not app-specific seeds.

## Constraints

- New strategy + vault integration ONLY. Do NOT change `fingerprint_application`, `build_recipe`, or the existing emergent-registration code path. Do NOT add a new fingerprint shape. Do NOT touch the 5 migrated probes — they consume `acquire_session` unchanged.
- Credentials NEVER appear in graph entities (captured_value, observation attributes) per the \#334 redaction policy. Full values stay in `run_credential_vault`. Recipe execution carries them only as in-memory POST body fields.
- Per-engagement only — credential lookup is keyed by (run_id, target_id), inherits memory_backend isolation.
- Must NOT touch: `fingerprint_application` (\#325 contract), `build_recipe` register-strategy logic (\#326 contract), auth-recipe cache layer (\#327 contract), the 5 migrated probe runners (\#328 contract), `workers/runners/`, `workers/orchestration/`, `_AI_PICKER_SYSTEM_PROMPT` body.

## Source Package

`codex/tasks/backlog-395-operator-credentialed-auth-path.json`

## Reference

- `api/app/services/auth_discoverer.py` — existing `acquire_session`, `fingerprint_application`, `build_recipe`, `_resolve_field_value` intent vocabulary
- `api/app/services/run_credential_vault.py` — read-only consumer; vault lookup API to consult
- `api/tests/test_auth_discoverer_acquire_session.py` — existing 16 tests must continue to pass
- DONE_LOG entry for \#329 post-merge addendum (the original mention of "Phase 2.5 / Phase 4 enhancement worth filing") + \#328 (5 probes that consume `acquire_session`)

## Validation

- `python3 scripts/validate_backlog_tasks.py`
- `.venv/bin/pytest api/tests/test_auth_discoverer_acquire_session.py api/tests/test_auth_discoverer_credentialed.py api/tests/test_auth_discoverer_cache.py api/tests/test_auth_discoverer_recipe.py api/tests/test_auth_discoverer.py`
- `python3 -m compileall -q api`
- `.venv/bin/ruff check api/app/services/auth_discoverer.py`
- `git diff --check`
