# Active Task

## Title

HTTP request smuggling runner: detect CL.TE, TE.CL, and TE.TE desync vulnerabilities in reverse proxy setups

## Promoted From

`codex/tasks/backlog-229-http-request-smuggling-runner.json`

## Goal

Add the queued HTTP request smuggling capability described in `codex/tasks/backlog-229-http-request-smuggling-runner.json`.

## Scope

Implement the active backlog package `codex/tasks/backlog-229-http-request-smuggling-runner.json`.

Expected slice:

- add an `http-smuggling` runner for approved web/API roots behind a proxy
- detect CL.TE, TE.CL, and TE.TE request desynchronization signals through timing-based detection only
- run only when proxy evidence is present, such as `Via` or `X-Forwarded-*` headers from the approved target
- cap probe timing/timeout according to the package and stop after timing confirmation
- produce critical HTTP request smuggling findings with timing and proxy evidence
- expose the capability through the supported execution registry and operator surfaces required by the package

## Constraints

- Keep Prompt 1 and Prompt 2 intact.
- Add only the HTTP request smuggling detection capability from the task package.
- Do not bypass local provenance, scope, ROE, validation, approval, deployment, runtime binding, credential gates, or kill switch.
- No runtime self-modification.
- No uncontrolled plugin installation.
- HTTP request smuggling probing must stay within approved scope.
- Timing-based detection only.
- Only probe targets identified as being behind a proxy.
- Max 5-second timeout per probe.
- Do not construct confirming requests that cause visible side effects for other users.
- Do not perform request hijacking, cache poisoning, WAF bypass, or internal endpoint access chains.
- Do not change ZAP config, SSL/TLS runner, Metasploit, or intrusive-tier behavior.
- No live target actions outside safe/local/explicitly authorized validation.

## Validation

- `python3 scripts/validate_backlog_tasks.py`
- `source .venv/bin/activate && python -m pytest api/tests/ -q`
- `git diff --check`

## Acceptance

- `http-smuggling` is registered in supported tools.
- CL.TE, TE.CL, and TE.TE timing probes are represented safely on deterministic test targets.
- The runner refuses targets without proxy evidence.
- Critical severity findings are produced for timing-confirmed request smuggling.
- Existing runner/API tests do not regress.
