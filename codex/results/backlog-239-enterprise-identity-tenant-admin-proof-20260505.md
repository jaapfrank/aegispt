# Backlog 239 Enterprise Identity And Tenant-Admin Proof Evidence

Date: 2026-05-05

## Scope

Active task: `backlog-239-enterprise-identity-tenant-admin-proof`

This slice makes the existing enterprise identity surface prove or explicitly gate:

- browser SSO enforcement
- tenant membership
- API-key role enforcement
- session expiry/logout behavior
- SCIM provisioning
- tenant administration

No live target actions, plugin installs, runtime self-modification, pack-gate bypasses, credential bypasses, approval bypasses, or ChatGPT OAuth semantic changes were performed.

## Implementation Evidence

- `/api/v1/auth/identity/status` now returns `access_boundaries` for `browser_sso`, `tenant_membership`, `role_enforcement`, `session_enforcement`, `scim`, and `tenant_admin`.
- Settings readiness now keeps `enterprise_identity` at `degraded` unless `metadata.enterprise_ready=true`; OIDC/SAML configuration alone no longer reports ready.
- `session_policy` explicitly reports `expiry_enforced=false`, `logout_audit_backed=true`, and `logout_mutates_active_runs=false`.
- Settings UI now renders an `Enterprise Boundary Proof` section with enforced, blocked, disabled, or unsupported status per identity boundary.
- Admin-only API-key routes reject non-admin API-key actors with `403`.
- Logout audit behavior is tested against an existing run and the run status remains unchanged.
- First-run onboarding no longer auto-opens above the Settings screen, while explicit rerun from Settings remains available.

## Local Runtime Acceptance

`http://127.0.0.1:8000` was relevant because this task changes auth, session, Settings, readiness, and browser UI surfaces. The running process on `8000` responded healthy but served stale identity-status fields, so it was not claimed as current-code proof for the new behavior.

Current-code acceptance was performed on temporary port `8022` with a temporary SQLite database:

- `GET /health/live`: `status=ok`, `runtime_state=healthy`
- `GET /api/v1/auth/identity/status` with `X-Actor: codex-identity-proof` returned:
  - `access_boundaries.browser_sso.status=disabled`
  - `access_boundaries.tenant_membership.status=blocked`
  - `access_boundaries.role_enforcement.status=enforced`
  - `access_boundaries.session_enforcement.status=configured_not_enforced`
  - `access_boundaries.scim.status=unsupported`
  - `access_boundaries.tenant_admin.status=unsupported`
  - `metadata.enterprise_ready=false`
  - `metadata.readiness_boundary=local_dev_identity_only`
- `GET /api/v1/settings/readiness` returned `enterprise_identity.status=degraded`.
- Browser acceptance against `/app/` showed the Settings Enterprise Identity panel with `Enterprise Boundary Proof`, `Tenant Membership blocked`, `Role Enforcement enforced`, and `SCIM Provisioning unsupported`.

The temporary Uvicorn process was stopped after acceptance.

## Validation

- `python3 scripts/validate_backlog_tasks.py`: passed with 250 queued task packages mapped one-to-one and exactly one active task.
- `source .venv/bin/activate && python -m pytest api/tests/test_auth.py -q`: passed.
- `source .venv/bin/activate && python -m pytest ui/tests/test_operator_console_smoke_e2e.py -q`: passed.
- Extra regression guard: `source .venv/bin/activate && python -m pytest ui/tests/test_operator_console_e2e.py::test_first_run_onboarding_prefills_wizard_defaults -q`: passed.
- `git diff --check`: passed.

## Remaining Risks

- Browser SSO callback enforcement remains unimplemented and must not be claimed from OIDC/SAML configuration alone.
- Tenant organization, tenant membership, invitations, SCIM, tenant switching, and tenant-admin workflows remain blocked or unsupported.
- Server-side browser session expiry is not enforced for the local X-Actor fallback path.
- The existing local fallback remains available only as a labelled supervised development path.
- The operator-reported Gruyere full-pentest wizard/all-tools issue remains outside this active task and queued separately.
