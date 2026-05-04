# Active Task

## Title

JWT vulnerability runner: detect algorithm confusion, weak secrets, and none algorithm attacks in JWT-based applications

## Promoted From

`codex/tasks/backlog-216-jwt-vulnerability-runner.json`

## Goal

Add the queued `jwt-probe` capability described in `codex/tasks/backlog-216-jwt-vulnerability-runner.json`.

## Scope

Implement the active backlog package `codex/tasks/backlog-216-jwt-vulnerability-runner.json`.

Expected slice:

- identify JWT-bearing responses and JavaScript references from approved web/API targets
- add bounded JWT validation for none-algorithm acceptance, weak HMAC secrets, algorithm confusion where key material is explicitly available, and claims manipulation where replay context is explicitly authorized
- emit structured JWT findings with methodology mapping and standard evidence references
- expose the capability in the Tool Library and supported execution registry
- keep validation safe and local unless an explicitly authorized target fixture is present

## Constraints

- Keep Prompt 1 and Prompt 2 intact.
- Do not implement unrelated auth or API runners.
- Do not brute-force beyond the package's bounded weak-secret list.
- Do not replay modified tokens unless the target, endpoint, and replay context are in approved scope.
- Do not bypass scope, ROE, validation, approval, deployment, runtime binding, credential gates, or kill switch.
- No runtime self-modification.
- No uncontrolled plugin installation.
- No live target actions outside safe/local/explicitly authorized validation.

## Validation

- `python3 scripts/validate_backlog_tasks.py`
- `source .venv/bin/activate && python -m pytest api/tests/ -q`
- `git diff --check`

## Acceptance

- `jwt-probe` runner is listed in supported tools.
- JWT detection and bounded vulnerability checks are covered by tests and safe local fixture evidence.
- Structured JWT findings use appropriate severity and methodology metadata.
- Tool Library lists the JWT capability.
- Existing runner/API tests do not regress.
