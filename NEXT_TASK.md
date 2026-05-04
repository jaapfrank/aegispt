# Active Task

## Title

Session security deep analysis: session fixation, token entropy, cookie flags, and session invalidation after logout

## Promoted From

`codex/tasks/backlog-223-session-security-deep-analysis.json`

## Goal

Add the queued session-security dedicated capability described in `codex/tasks/backlog-223-session-security-deep-analysis.json`.

## Scope

Implement the active backlog package `codex/tasks/backlog-223-session-security-deep-analysis.json`.

Expected slice:

- detect session fixation when a pre-login token persists after authenticated login
- check Set-Cookie headers for Secure, HttpOnly, SameSite, and HTTP exposure weaknesses
- estimate session token entropy across consecutive issued tokens
- detect post-logout session replay when a captured session token remains accepted
- identify session token leakage in URL parameters
- require configured credentials for authenticated session lifecycle checks
- emit structured findings for session fixation, cookie flag gaps, low entropy, post-logout replay, and token-in-URL weaknesses
- expose the capability through the supported execution registry and operator surfaces required by the package
- keep validation safe and local unless an explicitly authorized target fixture is present

## Constraints

- Keep Prompt 1 and Prompt 2 intact.
- Add only the session-security capability from the task package.
- Do not bypass local provenance, scope, ROE, validation, approval, deployment, runtime binding, credential gates, or kill switch.
- No runtime self-modification.
- No uncontrolled plugin installation.
- Use configured credentials only for authenticated checks.
- Do not attempt to hijack sessions of other users.
- No live target actions outside safe/local/explicitly authorized validation.

## Validation

- `python3 scripts/validate_backlog_tasks.py`
- `source .venv/bin/activate && python -m pytest api/tests/ -q`
- `git diff --check`

## Acceptance

- Session-security runner is registered in supported tools and requires configured credentials for authenticated lifecycle checks.
- Session fixation, cookie flag, post-logout replay, token entropy, and token-in-URL variants are covered by tests and safe local fixture evidence.
- Session findings are structured and evidence-first.
- Existing runner/API tests do not regress.
