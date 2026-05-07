# Active Task

## Title

Technology and signal fingerprinting: extract structured evidence signals from recon artifacts to feed the adaptive planner

## Promoted From

`codex/tasks/backlog-256-technology-fingerprinting-stack-detection.json`

## Goal

Implement the active backlog package `codex/tasks/backlog-256-technology-fingerprinting-stack-detection.json` so AegisPT extracts concrete technology and security signals from existing recon artifacts for later adaptive planning.

## Scope

Implement the active backlog package `codex/tasks/backlog-256-technology-fingerprinting-stack-detection.json`.

Expected slice:

- add a SignalProfile / technology-fingerprinting layer using existing recon response data
- extract concrete signals such as server/language/CMS, login forms, file upload endpoints, JWT presence, GraphQL endpoints, Java/Spring indicators, URL parameters, SQL error patterns, and serialized-cookie hints
- store the profile with inventory/recon state without changing existing finding schema fields
- expose the profile in the Mission Control recon summary when relevant
- use existing httpx/nmap/artifact data only; do not add extra active fingerprinting requests
- preserve existing runner registry, approvals, scope, ROE, credentials, runtime binding, reports, provenance, and kill switch

## Constraints

- Do not implement until this file is the single active task.
- Work only on technology/signal extraction and presentation for existing recon data.
- Do not add active probing beyond already collected httpx/nmap/recon artifacts.
- Do not treat PHP+MySQL or broad stack labels alone as injectable-parameter evidence.
- Do not bypass pack registry, validation, approval, deployment, runtime binding, scope, ROE, credentials, or kill switch.
- Keep the existing manual/wizard path intact.

## Validation

- `python3 scripts/validate_backlog_tasks.py`
- `source .venv/bin/activate && python -m pytest api/tests/ -q`
- `git diff --check`

## Acceptance

- Inventory/recon state includes a structured signal profile with concrete evidence-backed signals.
- WordPress can be detected from `wp-content` or generator evidence.
- PHP can be detected from `X-Powered-By` or `PHPSESSID` evidence.
- Java/Spring can be detected from `JSESSIONID` or Spring-style headers.
- JWT presence can be detected from bearer/cookie token patterns.
- GraphQL endpoints can be detected from existing route/content evidence.
- File upload and login forms are extracted from existing form evidence.
- No extra HTTP requests are required for the fingerprinting layer.
