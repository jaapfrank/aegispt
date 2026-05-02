# Active Task

## Title

Enterprise SSO, session, and identity administration

## Promoted From

`codex/tasks/backlog-182-enterprise-sso-session-identity-administration.json`

## Goal

Move AegisPT from local actor/API-key basics toward enterprise identity controls that operators can understand, configure, and audit.

## Scope

Implement the active backlog package `codex/tasks/backlog-182-enterprise-sso-session-identity-administration.json`.

Expected slice:

- add the first governed enterprise identity administration surface
- expose OIDC/SAML disabled, configured, and error states in Settings
- keep local development mode working without implying actor text is enterprise authentication
- make session timeout and logout behavior explicit
- persist SSO configuration safely without exposing secrets
- audit login, logout, key, and identity administration events
- document what is supported now and what remains future work

## Constraints

- Keep Prompt 1 and Prompt 2 intact.
- Do not bypass pack registry, validation, approval, deployment, runtime binding, scope enforcement, credential gates, or kill switch behavior.
- No runtime self-modification.
- Do not install uncontrolled plugins.
- Do not replace or remove the local development authentication fallback.
- Do not weaken ROE, tenant isolation, API-key revocation, secret materialization, or ChatGPT OAuth provider semantics.
- Do not change finding schema fields.
- Do not run live customer or intrusive targets.

## Validation

- `python3 scripts/validate_backlog_tasks.py`
- `source .venv/bin/activate && python -m pytest api/tests/test_auth.py -q`
- `source .venv/bin/activate && python -m pytest ui/tests/test_operator_console_smoke_e2e.py -q`
- `git diff --check`

## Acceptance

- Operators can see whether enterprise SSO is disabled, configured, or failing.
- Logout/session timeout behavior is visible and does not corrupt active run state.
- Identity admin actions are auditable.
