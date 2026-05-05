# Active Task

## Title

HTTP security headers comprehensive check: CORS misconfiguration, CSP bypass, Clickjacking, HSTS, and information disclosure headers

## Promoted From

`codex/tasks/backlog-226-http-security-headers-cors-csp-clickjacking.json`

## Goal

Add the queued HTTP security headers capability described in `codex/tasks/backlog-226-http-security-headers-cors-csp-clickjacking.json`.

## Scope

Implement the active backlog package `codex/tasks/backlog-226-http-security-headers-cors-csp-clickjacking.json`.

Expected slice:

- detect CORS credential reflection with active Origin probes
- detect null-origin acceptance, wildcard plus credentials, and regex-style Origin bypass patterns
- parse CSP and report unsafe-inline, unsafe-eval, wildcard script sources, missing default-src, data: script sources, and JSONP-style allowlist risks
- detect clickjacking exposure when frame protections are missing on sensitive/login/form pages
- detect missing or incomplete HSTS on HTTPS targets
- detect information-disclosure headers such as Server version strings, X-Powered-By, and X-AspNet-Version
- check redirect/CORS header preservation without extracting actual cross-origin data
- expose the capability through the supported execution registry and operator surfaces required by the package

## Constraints

- Keep Prompt 1 and Prompt 2 intact.
- Add only the headers-security capability from the task package.
- Do not bypass local provenance, scope, ROE, validation, approval, deployment, runtime binding, credential gates, or kill switch.
- No runtime self-modification.
- No uncontrolled plugin installation.
- Header analysis and Origin reflection probes only.
- Do not exploit CORS to extract actual data.
- Do not implement CSP nonce bypasses or full clickjacking PoC creation.
- Do not change the existing ZAP passive scanner or SSL/TLS runner.
- No live target actions outside safe/local/explicitly authorized validation.

## Validation

- `python3 scripts/validate_backlog_tasks.py`
- `source .venv/bin/activate && python -m pytest api/tests/ -q`
- `git diff --check`

## Acceptance

- `headers-security` is registered in supported tools.
- CORS credential reflection is detected correctly.
- CSP, clickjacking, HSTS, and information-disclosure header findings are structured and evidence-first.
- Passive header analysis and active CORS reflection behavior are represented without actual data extraction.
- Existing runner/API tests do not regress.
