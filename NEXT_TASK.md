# Active Task

## Title

IDOR and broken access control runner: detect insecure direct object references and horizontal/vertical privilege escalation

## Promoted From

`codex/tasks/backlog-218-idor-broken-access-control-runner.json`

## Goal

Add the queued `idor-bac` capability described in `codex/tasks/backlog-218-idor-broken-access-control-runner.json`.

## Scope

Implement the active backlog package `codex/tasks/backlog-218-idor-broken-access-control-runner.json`.

Expected slice:

- identify numeric and UUID-like object identifiers from approved web/API endpoints and existing evidence
- test bounded in-scope ID substitution only with configured accounts and approved authentication context
- test role/admin parameter manipulation where explicit request context is available
- test method-override and common admin path exposure only within approved scope
- emit structured broken-access-control findings with clear confirmed-versus-potential evidence
- expose the capability in the Tool Library and supported execution registry
- keep validation safe and local unless an explicitly authorized target fixture is present

## Constraints

- Keep Prompt 1 and Prompt 2 intact.
- Do not brute-force identifiers beyond the package limit.
- Do not use credentials outside engagement configuration.
- Do not bypass local CVE/feed provenance, scope, ROE, validation, approval, deployment, runtime binding, credential gates, or kill switch.
- No runtime self-modification.
- No uncontrolled plugin installation.
- No live target actions outside safe/local/explicitly authorized validation.

## Validation

- `python3 scripts/validate_backlog_tasks.py`
- `source .venv/bin/activate && python -m pytest api/tests/ -q`
- `git diff --check`

## Acceptance

- `idor-bac` runner is listed in supported tools.
- Bounded IDOR/BAC checks are covered by tests and safe local fixture evidence.
- Structured findings distinguish confirmed unauthorized access from potential access-control signals.
- Tool Library lists the IDOR/BAC capability.
- Existing runner/API tests do not regress.
