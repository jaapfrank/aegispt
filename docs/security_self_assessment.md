# AegisPT Security Self-Assessment

Date: 2026-04-28

## Scope

This assessment covers AegisPT itself on the local build-lane host only:

- Base URL: `http://127.0.0.1:8000`
- Environment: local inline host restarted from the current repository state
- No external targets, production data, or live customer systems were tested
- Focus areas: input validation, SSRF/scope bypass, command-injection-style target strings, path traversal, IDOR/tenant isolation, security headers, and dependency audit readiness

## Changes Made

- Run and scheduled-run target overrides are now checked against the active engagement scope before any tasks are queued.
- Engagement create payloads now reject oversized names/client/ROE values and null bytes.
- API responses now include baseline security headers: `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`, and `Permissions-Policy`.
- Added automated malicious-input regression coverage in `api/tests/test_input_validation_security.py`.
- Added `scripts/run_dependency_audit.py` to produce a local dependency-audit report without installing or mutating dependencies.

## Automated Validation

Command:

```bash
source .venv/bin/activate && python -m pytest --capture=no api/tests/test_input_validation_security.py
```

Result:

- Passed: 10 tests in 8.29s
- Covered: oversized input rejection, null-byte rejection, SQLi-style name storage as data, SSRF metadata URL rejection, out-of-scope URL rejection, command-injection-style host rejection, in-scope URL path acceptance, scheduled-run SSRF rejection, tenant IDOR rejection, inline artifact path traversal rejection, and baseline security headers.

## Local API Scan

Local host restart:

```bash
AEGISPT_LOCAL_ENSURE_ZAP=0 bash scripts/restart_local_inline_host.sh
```

Result:

- `http://127.0.0.1:8000/health/live` returned HTTP 200 from the restarted current branch.
- Response headers included the new baseline security headers.

Focused nuclei command:

```bash
timeout 60s nuclei -u http://127.0.0.1:8000 -silent -jsonl -o codex/results/aegispt-selftest-nuclei-focused-20260428.jsonl -t /home/administrator/nuclei-templates/http/exposures/apis/openapi.yaml -t /home/administrator/nuclei-templates/http/exposures/apis/swagger-api.yaml -t /home/administrator/nuclei-templates/http/misconfiguration/http-missing-security-headers.yaml -t /home/administrator/nuclei-templates/http/vulnerabilities/generic/cors-misconfig.yaml -rate-limit 5 -timeout 5 -retries 0
```

Result:

- Exit code: 0
- Findings: 10 informational findings
- No medium, high, or critical findings were emitted.
- Remaining informational findings: local OpenAPI/Swagger exposure and headers that are not appropriate to force globally for the development API, such as HSTS on plain HTTP and CSP that would need docs/UI-specific policy work.

ZAP quick scan command:

```bash
timeout 120s zap.sh -dir /tmp/aegispt-zap-selftest -port 8090 -cmd -quickurl http://127.0.0.1:8000 -quickout "/home/administrator/project/automation skill/AegisPT/codex/results/aegispt-selftest-zap-20260428.xml" -quickprogress
```

Result:

- Exit code: 0
- Alerts: 0

Artifacts:

- `codex/results/aegispt-selftest-nuclei-focused-20260428.jsonl`
- `codex/results/aegispt-selftest-zap-20260428.xml`

## Dependency Audit

Command:

```bash
python3 scripts/run_dependency_audit.py --output codex/results/dependency-audit-latest.json
```

Result:

- Python audit status: `tool_unavailable`
- Reason: neither `pip-audit` nor `safety` is installed in this environment.
- Frontend audit status: `not_applicable`
- Reason: no `package.json` or `package-lock.json` exists at the repository root.

Artifact:

- `codex/results/dependency-audit-latest.json`

## Residual Risk

- The local development API exposes `/docs` and `/openapi.json`; nuclei reports this as informational. This should become an environment-gated production setting before external deployment.
- HSTS is not set on the local HTTP development endpoint. This is expected for `http://127.0.0.1`; production TLS termination should enforce it.
- A real dependency CVE verdict still requires installing or providing `pip-audit` or `safety` in the validation environment. The audit script now records that gap explicitly instead of silently passing.
