# Active Task

## Title

Finding quality: add CVSS score, OWASP mapping, business impact, step-by-step remediation, and proof-of-concept reference to every finding

## Promoted From

`codex/tasks/backlog-212-finding-quality-enrichment-and-remediation-proof.json`

## Goal

Enterprise pentest reports require structured finding quality that AegisPT only partially provides today: CVSS, OWASP mapping, business impact, concrete remediation, and reproduce/proof references.

## Scope

Implement the active backlog package `codex/tasks/backlog-212-finding-quality-enrichment-and-remediation-proof.json`.

Expected slice:

- add CVSS score support for findings, using NVD-sourced values for CVE findings and deterministic fallback calculation for non-CVE findings
- add deterministic OWASP category mapping by finding type and surface
- add AI business impact and stack-aware remediation fields when ChatGPT is connected
- show CVSS, OWASP mapping, business impact, remediation, and reproduce/proof reference in the Finding drawer
- keep this within existing finding/evidence/report structures

## Constraints

- Keep Prompt 1 and Prompt 2 intact.
- Do not restructure finding storage.
- Do not change the existing finding severity model.
- Do not add new finding types.
- Do not change evidence storage.
- Do not change report generation in this task.
- Do not bypass scope, ROE, validation, approval, deployment, runtime binding, credential gates, or kill switch.
- No runtime self-modification.
- Do not run live target actions.

## Validation

- `python3 scripts/validate_backlog_tasks.py`
- `source .venv/bin/activate && python -m pytest api/tests/ -q`
- `git diff --check`

## Acceptance

- Every finding has a CVSS score.
- OWASP mapping is present on findings.
- AI business impact and remediation are available when ChatGPT is connected.
- Finding drawer shows CVSS gauge, OWASP badge, business impact, remediation, and a reproduce/proof reference.
- Findings E2E tests do not regress.
