# Active Task

## Title

Enterprise identity and tenant-admin proof: move SSO/RBAC/tenant boundaries from configured-state to enforceable truth

## Promoted From

`codex/tasks/backlog-239-enterprise-identity-tenant-admin-proof.json`

## Goal

Close the gap between visible enterprise identity settings and enterprise-ready access control by proving or explicitly gating browser SSO, tenant membership, role enforcement, session expiry/logout, and SCIM/tenant-admin boundaries.

## Scope

Implement the active backlog package `codex/tasks/backlog-239-enterprise-identity-tenant-admin-proof.json`.

Expected slice:

- build the next governed identity proof slice on top of existing OIDC/SAML settings and RBAC foundations
- add enforceable or clearly blocked operator paths for tenant membership and role boundaries
- prove or explicitly gate browser-session enforcement where configured
- prove session expiry/logout behavior without corrupting active missions or runs
- surface SCIM, invitation, and tenant-admin status honestly as configured, disabled, or unsupported
- keep local development fallback available only as a clearly labelled development path

## Constraints

- Keep Prompt 1 and Prompt 2 intact.
- Do not weaken ROE, scope boundaries, API-key revocation, tenant isolation, or local development safety labels.
- Do not bypass scope enforcement, secret materialization, validation, approval, deployment, runtime binding, credentials, or kill switch.
- No runtime self-modification.
- No uncontrolled plugin installation.
- Do not change ChatGPT OAuth provider semantics.
- Do not remove finding schema fields.

## Validation

- `python3 scripts/validate_backlog_tasks.py`
- `source .venv/bin/activate && python -m pytest api/tests/test_auth.py -q`
- `source .venv/bin/activate && python -m pytest ui/tests/test_operator_console_smoke_e2e.py -q`
- `git diff --check`

## Acceptance

- Enterprise identity readiness does not imply SSO enforcement unless enforcement is proven.
- Tenant/admin/RBAC limits are visible, tested, and audit-backed.
