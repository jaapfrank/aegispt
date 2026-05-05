# Active Task

## Title

OAuth2/OIDC misconfiguration runner: detect redirect_uri bypass, PKCE absence, state parameter missing, and token leakage

## Promoted From

`codex/tasks/backlog-230-oauth2-oidc-misconfiguration-runner.json`

## Goal

Add the queued OAuth2/OIDC misconfiguration capability described in `codex/tasks/backlog-230-oauth2-oidc-misconfiguration-runner.json`.

## Scope

Implement the active backlog package `codex/tasks/backlog-230-oauth2-oidc-misconfiguration-runner.json`.

Expected slice:

- add an `oauth-probe` runner for approved web/API roots with OAuth/OIDC evidence
- discover OAuth/OIDC endpoints from target application metadata, JavaScript, login buttons, and `.well-known/openid-configuration`
- detect redirect URI bypass, missing state parameter, absent PKCE for SPA-style authorization-code flows, token leakage in URL/fragment/redirect parameters, and implicit-flow support
- add the `active-web-oauth-probe` run profile and required operator surfaces
- wire the profile into the Full External Web/API wizard and assessment-chain surfaces required by the task package
- keep evidence, findings, methodology tags, approvals, and runtime dispatch paths aligned with existing models and flows

## Constraints

- Keep Prompt 1 and Prompt 2 intact.
- Add only the OAuth2/OIDC misconfiguration detection capability from the task package.
- Do not bypass local provenance, scope, ROE, validation, approval, deployment, runtime binding, credential gates, or kill switch.
- No runtime self-modification.
- No uncontrolled plugin installation.
- Test only OAuth flows of the approved target application.
- Do not interact directly with third-party IdP infrastructure such as Google or Microsoft endpoints.
- Do not exploit found OAuth vulnerabilities or perform account takeover.
- Do not change existing auth runners or the JWT runner unless the package explicitly requires integration points.
- No live target actions outside safe/local/expliciet geautoriseerde validatie.

## Validation

- `python3 scripts/validate_backlog_tasks.py`
- `source .venv/bin/activate && python -m pytest api/tests/ -q`
- `git diff --check`

## Acceptance

- `oauth-probe` is registered in supported tools.
- Missing state parameter detection is proven on a deterministic test OAuth app/fixture.
- Redirect URI bypass, absent PKCE, token-in-URL, and implicit-flow support checks are represented safely.
- `active-web-oauth-probe` exists and requires active approval.
- The runner is reachable through the wizard when Web or API tile plus active/full depth is selected.
- Existing runner/API tests do not regress.
