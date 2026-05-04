# Active Task

## Title

SSRF dedicated runner: server-side request forgery detection via OOB callbacks and internal service probing

## Promoted From

`codex/tasks/backlog-221-ssrf-dedicated-runner.json`

## Goal

Add the queued SSRF dedicated capability described in `codex/tasks/backlog-221-ssrf-dedicated-runner.json`.

## Scope

Implement the active backlog package `codex/tasks/backlog-221-ssrf-dedicated-runner.json`.

Expected slice:

- detect parameter-based SSRF in common URL-consuming parameters
- detect header-based SSRF candidates for Host and forwarding headers
- support blind/OOB SSRF evidence through a governed callback context
- detect approved internal service or cloud-metadata exposure only within the task safety constraints
- emit structured findings for blind SSRF, internal service access, and cloud metadata exposure
- expose the capability through the supported execution registry and operator surfaces required by the package
- keep validation safe and local unless an explicitly authorized target fixture is present

## Constraints

- Keep Prompt 1 and Prompt 2 intact.
- Add only the SSRF capability from the task package.
- Do not change existing ZAP scanner configuration.
- Do not bypass local provenance, scope, ROE, validation, approval, deployment, runtime binding, credential gates, or kill switch.
- No runtime self-modification.
- No uncontrolled plugin installation.
- No SSRF-to-RCE escalation or internal pivoting.
- No live target actions outside safe/local/explicitly authorized validation.
- Never use real internal IPs outside the engagement's approved CIDR.
- Cloud metadata probes only when the target is confirmed cloud-hosted and the task safety controls allow it.

## Validation

- `python3 scripts/validate_backlog_tasks.py`
- `source .venv/bin/activate && python -m pytest api/tests/ -q`
- `git diff --check`

## Acceptance

- SSRF probe is registered in supported tools and requires active approval.
- Parameter, header, OOB, internal service, and cloud metadata variants are covered by tests and safe local fixture evidence.
- SSRF findings are structured and evidence-first.
- Existing runner/API tests do not regress.
