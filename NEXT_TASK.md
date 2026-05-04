# Active Task

## Title

XSS completeness: dedicated file-upload XSS, AJAX/JSON XSS, and XSSI detection

## Promoted From

`codex/tasks/backlog-220-xss-file-upload-ajax-xssi-runner.json`

## Goal

Add the queued XSS completeness capability described in `codex/tasks/backlog-220-xss-file-upload-ajax-xssi-runner.json`.

## Scope

Implement the active backlog package `codex/tasks/backlog-220-xss-file-upload-ajax-xssi-runner.json`.

Expected slice:

- detect stored XSS via unrestricted same-domain HTML file upload
- detect AJAX/JSON XSS response contexts that basic ZAP coverage may miss
- detect XSSI/data-leakage exposure for unprotected sensitive JSON endpoints
- emit structured findings for all three variants
- expose the capability through the supported execution registry and operator surfaces required by the package
- keep validation safe and local unless an explicitly authorized target fixture is present

## Constraints

- Keep Prompt 1 and Prompt 2 intact.
- Add only the three specific XSS variants from the task package.
- Do not change existing ZAP runner configuration unless the package and repo-truth require it through the existing registry path.
- Do not bypass local provenance, scope, ROE, validation, approval, deployment, runtime binding, credential gates, or kill switch.
- No runtime self-modification.
- No uncontrolled plugin installation.
- No live target actions outside safe/local/explicitly authorized validation.

## Validation

- `python3 scripts/validate_backlog_tasks.py`
- `source .venv/bin/activate && python -m pytest api/tests/ -q`
- `git diff --check`

## Acceptance

- File upload XSS, AJAX/JSON XSS, and XSSI checks are covered by tests and safe local fixture evidence.
- All three variants produce structured findings.
- The active capability requires one approval.
- Existing runner/API tests do not regress.
