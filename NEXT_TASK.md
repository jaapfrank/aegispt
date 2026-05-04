# Active Task

## Title

XXE injection runner: detect XML External Entity vulnerabilities in web applications and APIs

## Promoted From

`codex/tasks/backlog-214-xxe-injection-runner.json`

## Goal

Add the queued `xxe-probe` capability described in `codex/tasks/backlog-214-xxe-injection-runner.json`.

## Scope

Implement the active backlog package `codex/tasks/backlog-214-xxe-injection-runner.json`.

Expected slice:

- add an `xxe-probe` runner for approved web/API targets
- discover XML-consuming endpoints from existing in-scope evidence where available
- add bounded, read-only XXE probes for direct file-read style detection and blind/OOB-ready evidence handling
- explicitly wire ZAP XXE scanner coverage where the existing ZAP flow supports it
- emit structured XXE findings with methodology mapping and standard evidence references
- expose the capability in the Tool Library

## Constraints

- Keep Prompt 1 and Prompt 2 intact.
- Do not implement unrelated injection runners.
- Do not change core dispatch logic beyond additive runner registration and routing.
- Do not bypass scope, ROE, validation, approval, deployment, runtime binding, credential gates, or kill switch.
- No runtime self-modification.
- No uncontrolled plugin installation.
- No live target actions outside safe/local/explicitly authorized validation.
- No denial-of-service XXE payloads, no SSRF chaining, and no internal-system probing outside approved scope.

## Validation

- `python3 scripts/validate_backlog_tasks.py`
- `source .venv/bin/activate && python -m pytest api/tests/ -q`
- `git diff --check`

## Acceptance

- `xxe-probe` runner is listed in supported tools.
- XXE direct-file-read detection is covered by tests and safe local fixture evidence.
- Structured XXE findings use appropriate severity and methodology metadata.
- ZAP XXE scanner wiring is explicit where applicable.
- Tool Library lists the XXE capability.
- Existing runner/API tests do not regress.
