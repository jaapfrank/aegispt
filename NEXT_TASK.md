# Active Task

## Title

Client-state manipulation and server-side authorization bypass: detect privilege escalation via parameter/cookie tampering

## Promoted From

`codex/tasks/backlog-225-client-state-manipulation-server-auth-bypass.json`

## Goal

Add the queued client-state manipulation capability described in `codex/tasks/backlog-225-client-state-manipulation-server-auth-bypass.json`.

## Scope

Implement the active backlog package `codex/tasks/backlog-225-client-state-manipulation-server-auth-bypass.json`.

Expected slice:

- detect hidden field privilege manipulation on vulnerable in-scope forms
- detect cookie-based role or privilege manipulation
- detect request parameter privilege manipulation in approved POST/PUT contexts
- detect price or amount manipulation in configured order/payment contexts
- detect step-skipping in configured multi-step workflow contexts
- cover Gruyere-style client-state manipulation patterns where an admin-style cookie or parameter unlocks server-side actions
- require configured credentials and active approval
- emit structured findings for client-state/server-side authorization bypass weaknesses
- expose the capability through the supported execution registry and operator surfaces required by the package
- keep validation safe and local unless an explicitly authorized target fixture is present

## Constraints

- Keep Prompt 1 and Prompt 2 intact.
- Add only the client-state capability from the task package.
- Do not bypass local provenance, scope, ROE, validation, approval, deployment, runtime binding, credential gates, or kill switch.
- No runtime self-modification.
- No uncontrolled plugin installation.
- Test parameter/cookie manipulation only.
- Do not chain into post-exploitation.
- Use only in-scope credentials.
- No live target actions outside safe/local/explicitly authorized validation.

## Validation

- `python3 scripts/validate_backlog_tasks.py`
- `source .venv/bin/activate && python -m pytest api/tests/ -q`
- `git diff --check`

## Acceptance

- Client-state runner is registered in supported tools and requires configured credentials plus active approval.
- Hidden field privilege manipulation, cookie-based role manipulation, request parameter privilege manipulation, price manipulation, and step-skipping variants are covered by tests and safe local fixture evidence.
- Gruyere-style client-state manipulation patterns are represented in the fixture proof or documented as an explicit remaining validation gap.
- Client-state findings are structured and evidence-first.
- Existing runner/API tests do not regress.
