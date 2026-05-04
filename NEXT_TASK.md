# Active Task

## Title

Vulnerable components runner: detect known CVEs in running web application libraries via response fingerprinting and dependency analysis

## Promoted From

`codex/tasks/backlog-217-vulnerable-components-dependency-check.json`

## Goal

Add the queued `vuln-components` capability described in `codex/tasks/backlog-217-vulnerable-components-dependency-check.json`.

## Scope

Implement the active backlog package `codex/tasks/backlog-217-vulnerable-components-dependency-check.json`.

Expected slice:

- fingerprint web application framework and JavaScript library versions from approved web/API responses, headers, comments, and linked scripts
- check explicitly exposed dependency files such as `package.json`, lockfiles, and `pom.xml` only within approved scope
- match detected products and versions against the existing local CVE/threat-intel infrastructure
- emit structured vulnerable-component findings with CVE references and methodology metadata
- expose the capability in the Tool Library and supported execution registry
- keep validation safe and local unless an explicitly authorized target fixture is present

## Constraints

- Keep Prompt 1 and Prompt 2 intact.
- Do not implement exploitation of found vulnerabilities.
- Do not implement broad SAST/source-code review.
- Do not bypass local CVE/feed provenance, scope, ROE, validation, approval, deployment, runtime binding, credential gates, or kill switch.
- No runtime self-modification.
- No uncontrolled plugin installation.
- No live target actions outside safe/local/explicitly authorized validation.

## Validation

- `python3 scripts/validate_backlog_tasks.py`
- `source .venv/bin/activate && python -m pytest api/tests/ -q`
- `git diff --check`

## Acceptance

- `vuln-components` runner is listed in supported tools.
- Version fingerprinting and local CVE matching are covered by tests and safe local fixture evidence.
- Structured vulnerable-component findings include CVE references and appropriate methodology metadata.
- Tool Library lists the vulnerable-components capability.
- Existing runner/API tests do not regress.
