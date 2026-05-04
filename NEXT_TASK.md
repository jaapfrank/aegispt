# Active Task

## Title

Insecure deserialization runner: detect vulnerable Java, PHP, Python, and .NET deserialization endpoints

## Promoted From

`codex/tasks/backlog-222-insecure-deserialization-runner.json`

## Goal

Add the queued deserialization dedicated capability described in `codex/tasks/backlog-222-insecure-deserialization-runner.json`.

## Scope

Implement the active backlog package `codex/tasks/backlog-222-insecure-deserialization-runner.json`.

Expected slice:

- detect Java serialized-object markers in request parameters, cookies, or headers
- support Java URLDNS-only OOB evidence without command execution payloads
- detect PHP object injection through bounded serialized-string probes and error analysis
- detect Python pickle acceptance signals from explicit evidence or approved request contexts
- detect unsigned or unencrypted .NET ViewState indicators
- emit structured findings for Java URLDNS-confirmed, PHP object-injection, Python pickle, and ViewState weaknesses
- expose the capability through the supported execution registry and operator surfaces required by the package
- keep validation safe and local unless an explicitly authorized target fixture is present

## Constraints

- Keep Prompt 1 and Prompt 2 intact.
- Add only the deserialization capability from the task package.
- Do not bypass local provenance, scope, ROE, validation, approval, deployment, runtime binding, credential gates, or kill switch.
- No runtime self-modification.
- No uncontrolled plugin installation.
- Detection only: Java ysoserial payloads must be URLDNS/DNS-callback style only.
- No CommonsCollections or other RCE gadget chains.
- No live target actions outside safe/local/explicitly authorized validation.
- No exfiltration or command execution via deserialization.

## Validation

- `python3 scripts/validate_backlog_tasks.py`
- `source .venv/bin/activate && python -m pytest api/tests/ -q`
- `git diff --check`

## Acceptance

- Deserialization probe is registered in supported tools and requires active approval.
- Java URLDNS, PHP object injection, Python pickle, and .NET ViewState variants are covered by tests and safe local fixture evidence.
- Deserialization findings are structured and evidence-first.
- Existing runner/API tests do not regress.
