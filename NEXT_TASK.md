# Active Task

## Title

SSTI runner: Server-Side Template Injection detection via mathematical expression payloads

## Promoted From

`codex/tasks/backlog-228-ssti-server-side-template-injection.json`

## Goal

Add the queued SSTI capability described in `codex/tasks/backlog-228-ssti-server-side-template-injection.json`.

## Scope

Implement the active backlog package `codex/tasks/backlog-228-ssti-server-side-template-injection.json`.

Expected slice:

- add an `ssti-probe` runner for approved web/API roots
- detect Jinja2, Twig, Freemarker, Smarty, Velocity, and similar SSTI signals using mathematical expression payloads only
- check reflected string parameters and explicitly configured stored-form contexts
- include Gruyere-style custom template-language detection where safely represented by the package
- produce critical SSTI findings with engine evidence when expression output confirms execution
- expose the capability through the supported execution registry and operator surfaces required by the package

## Constraints

- Keep Prompt 1 and Prompt 2 intact.
- Add only the SSTI detection capability from the task package.
- Do not bypass local provenance, scope, ROE, validation, approval, deployment, runtime binding, credential gates, or kill switch.
- No runtime self-modification.
- No uncontrolled plugin installation.
- SSTI probing must stay within approved scope.
- Mathematical expression detection only.
- Do not send OS command execution payloads.
- Do not use `__import__`, `os.system`, shell, file-read, config-dump, or RCE payloads.
- Do not change existing injection runners, Metasploit, or intrusive-tier behavior.
- No live target actions outside safe/local/explicitly authorized validation.

## Validation

- `python3 scripts/validate_backlog_tasks.py`
- `source .venv/bin/activate && python -m pytest api/tests/ -q`
- `git diff --check`

## Acceptance

- `ssti-probe` is registered in supported tools.
- Jinja2/Twig/Freemarker-style SSTI is detected on safe test targets using only math-expression payloads.
- Engine identification appears in produced findings.
- Critical severity findings are produced for confirmed SSTI.
- Existing runner/API tests do not regress.
