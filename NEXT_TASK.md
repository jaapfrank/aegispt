# Active Task

## Title

Authorized Gruyere XSS Extended validation: derive contexts from official codelab and prove detection on approved instance root

## Promoted From

`codex/tasks/backlog-241-authorized-gruyere-xss-extended-validation.json`

## Goal

Use the official Google Gruyere codelab documentation and source guidance to derive the concrete XSS/XSSI validation contexts that backlog-220 should have exercised, then run the existing xss-extended capability only against the explicitly authorized Gruyere instance root `https://google-gruyere.appspot.com/482338906867472456097470474631954304306/`.

Produce evidence showing whether file-upload XSS, AJAX/JSON XSS, and XSSI are detected on the real lab target. If the current runner needs narrow context-discovery or parsing repair to detect those documented Gruyere cases, implement only that repair.

## Scope

Implement the active backlog package `codex/tasks/backlog-241-authorized-gruyere-xss-extended-validation.json`.

Expected slice:

- use official Gruyere documentation/source pages to derive concrete file-upload XSS, AJAX/JSON XSS, and XSSI contexts
- validate only against the explicitly authorized Gruyere instance root `https://google-gruyere.appspot.com/482338906867472456097470474631954304306/`
- run a safe direct runner validation or existing approved AegisPT run path for the three backlog-220 variants
- record all outbound validation requests or a summary proving they stayed under the authorized instance root
- state detected/missed status for all three variants with structured output or honest miss reasons
- if needed, implement only narrow xss-extended context-discovery/parsing repair for these documented variants

## Constraints

- Do not implement until this file is the single active task.
- Validate only the three backlog-220 variants: file-upload XSS, AJAX/JSON XSS, and XSSI.
- Do not add unrelated Gruyere vulnerability coverage.
- Live target actions are allowed only for the explicitly authorized Gruyere instance root and only for the documented XSS/XSSI validation steps in this task.
- All validation requests must stay under `https://google-gruyere.appspot.com/482338906867472456097470474631954304306/`.
- Do not test `https://google-gruyere.appspot.com/` outside that instance root except read-only codelab/source documentation pages.
- Do not call resetbutton, quit, overload, or denial-of-service endpoints.
- Do not attempt code execution, path traversal, SQL injection, or account takeover.
- Do not bypass approvals, scope, ROE, deployment, runtime binding, credential gates, or kill switch.
- No runtime self-modification.
- No uncontrolled plugin installation.

## Validation

- `python3 scripts/validate_backlog_tasks.py`
- `source .venv/bin/activate && python -m pytest workers/tests/test_xss_extended_runner.py api/tests/test_pentest_depth_registration.py -q`
- `source .venv/bin/activate && python -m pytest api/tests/ -q`
- `git diff --check`

## Acceptance

- The authorized Gruyere instance root is the only live target root used for validation.
- Evidence includes official Gruyere documentation-derived contexts and real-lab results for file-upload XSS, AJAX/JSON XSS, and XSSI.
- Any miss is recorded as product truth with a bounded next action rather than hidden behind green fixture tests.
