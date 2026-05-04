# Active Task

## Title

Password reset and authentication flow security: detect predictable tokens, token reuse, and reset poisoning

## Promoted From

`codex/tasks/backlog-224-password-reset-authentication-flow-runner.json`

## Goal

Add the queued auth-flow dedicated capability described in `codex/tasks/backlog-224-password-reset-authentication-flow-runner.json`.

## Scope

Implement the active backlog package `codex/tasks/backlog-224-password-reset-authentication-flow-runner.json`.

Expected slice:

- detect predictable password reset tokens from bounded configured test-account resets
- detect password reset token reuse after a token has already been consumed
- detect host-header injection/reset poisoning when a forged Host header appears in the reset link evidence
- detect username enumeration through response/timing/content differences on login/reset flows
- detect missing brute-force protection with a maximum of 10 failed login attempts and immediate stop
- detect credentials submitted over HTTP or via GET parameters
- require configured test account credentials and active approval
- emit structured findings for auth-flow weaknesses
- expose the capability through the supported execution registry and operator surfaces required by the package
- keep validation safe and local unless an explicitly authorized target fixture is present

## Constraints

- Keep Prompt 1 and Prompt 2 intact.
- Add only the auth-flow capability from the task package.
- Do not bypass local provenance, scope, ROE, validation, approval, deployment, runtime binding, credential gates, or kill switch.
- No runtime self-modification.
- No uncontrolled plugin installation.
- Test only with configured test accounts.
- Brute-force validation is capped at 10 attempts and must stop immediately.
- Do not perform real account takeover.
- No live target actions outside safe/local/explicitly authorized validation.

## Validation

- `python3 scripts/validate_backlog_tasks.py`
- `source .venv/bin/activate && python -m pytest api/tests/ -q`
- `git diff --check`

## Acceptance

- Auth-flow runner is registered in supported tools and requires configured credentials plus active approval.
- Predictable reset tokens, token reuse, missing brute-force protection, username enumeration, credentials-over-HTTP/GET, and host-header reset poisoning variants are covered by tests and safe local fixture evidence.
- Auth-flow findings are structured and evidence-first.
- Existing runner/API tests do not regress.
