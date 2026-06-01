# AegisPT Lab Suite v1 Validation

Date: 2026-05-28

Base commit at implementation time: `66a5078`

## Scope

Added a standalone Docker lab target under `labs/aegispt_lab_suite/`.
This is a local benchmark target only; it does not modify AegisPT runtime,
runner selection, picker behavior, findings schema, scope gates, approvals, or
XBOW score-lane code.

## Delivered

- `labs/aegispt_lab_suite/Dockerfile`
- `labs/aegispt_lab_suite/docker-compose.yml`
- `labs/aegispt_lab_suite/app.py`
- `labs/aegispt_lab_suite/grader.py`
- `labs/aegispt_lab_suite/suite_manifest.json`
- `labs/aegispt_lab_suite/README.md`
- `scripts/tests/test_aegispt_lab_suite.py`

## Challenge Set

| Challenge ID | Family | Proof |
| --- | --- | --- |
| `ssrf-loopback-metadata` | loopback SSRF to metadata | flag capture |
| `cache-key-header-confusion` | cache key omission for preview headers | flag capture |
| `graphql-batch-authz-confusion` | batched GraphQL authorization confusion | flag capture |
| `signed-url-canonicalization` | signed download path canonicalization mismatch | flag capture |
| `coupon-race-double-spend` | race-prone coupon double spend | flag capture |
| `log-lookup-expression-expansion` | toy log lookup expansion | flag capture |
| `cgi-env-parser-confusion` | toy environment parser confusion | flag capture |
| `heartbeat-length-overread` | toy length-controlled over-read | flag capture |
| `binder-nested-property-exposure` | toy unsafe nested data binding | flag capture |
| `frontend-backend-auth-rebind` | toy frontend/backend auth-context confusion | flag capture |

The manifest intentionally excludes flag values. Flags are verified through
`POST /grade` or `grader.py`.

## Validation

```bash
python3 -m pytest scripts/tests/test_aegispt_lab_suite.py -q
# passed: 18 tests

python3 -m pytest scripts/tests/test_aegispt_lab_suite.py -vv
# collected 18 items, 18 passed

python3 -m compileall -q labs/aegispt_lab_suite scripts/tests/test_aegispt_lab_suite.py
# passed

.venv/bin/ruff check labs/aegispt_lab_suite/app.py labs/aegispt_lab_suite/grader.py scripts/tests/test_aegispt_lab_suite.py
# All checks passed

git diff --check -- labs/aegispt_lab_suite scripts/tests/test_aegispt_lab_suite.py
# passed
```

Docker proof:

```bash
docker compose -f labs/aegispt_lab_suite/docker-compose.yml build
# built image: aegispt-lab-suite:local

docker compose -f labs/aegispt_lab_suite/docker-compose.yml up -d
# container became healthy on 127.0.0.155:8088
```

Observed live container checks:

```text
GET http://127.0.0.155:8088/healthz -> {"status":"ok","suite_id":"aegispt-lab-suite-v1","challenges":10}
GET http://127.0.0.155:8088/.well-known/aegispt-lab-manifest.json -> suite_id=aegispt-lab-suite-v1, 10 challenges, default_base_url=http://127.0.0.155:8088/
grader.py default base URL + --challenge-id ssrf-loopback-metadata --flag <expected local flag> -> match=true
```

Additional test coverage added after the initial v1 smoke:

- compose/grader defaults use `127.0.0.155:8088`, not `127.0.0.1:8088`
- CLI grader exits `0` only on exact byte-equal flag match
- unknown challenge IDs return `400` without flag disclosure
- direct metadata access is forbidden; only the webhook service hop can fetch it
- external SSRF fetches are suppressed
- cache-poison flag requires preview-header poisoning before the plain read
- GraphQL admin query works with explicit admin token and via the batch-confusion path
- signed download rejects bad signatures
- sequential coupon reuse does not unlock the race-condition flag
- toy log lookup expands only the lab lookup expression
- toy CGI parser confusion returns a flag only for the parser-confusion marker
- toy heartbeat returns no secret at exact length and leaks only on over-length request
- invalid heartbeat length returns `400`
- toy nested binder exposes the flag only on the nested resource path
- frontend/backend auth rebind requires the autodiscover trust hint

## Historical Inspiration Sources

The five harder labs are bug-class models inspired by public historical
zero-days:

- Log4Shell / CVE-2021-44228: CISA describes unsafe Log4j lookup/JNDI variable resolution.
- Shellshock / CVE-2014-6271: NVD tracks Bash parser confusion leading to command execution.
- Heartbleed / CVE-2014-0160: NVD describes OpenSSL heartbeat buffer over-read.
- Spring4Shell / CVE-2022-22965: NVD describes Spring MVC/WebFlux data binding RCE conditions.
- ProxyLogon / CVE-2021-26855: CISA/Microsoft advisories describe Exchange SSRF/auth-context confusion.

References consulted:

- https://www.cisa.gov/news-events/news/apache-log4j-vulnerability-guidance
- https://nvd.nist.gov/vuln/detail/CVE-2014-6271
- https://nvd.nist.gov/vuln/detail/CVE-2014-0160
- https://nvd.nist.gov/vuln/detail/CVE-2022-22965
- https://nvd.nist.gov/vuln/detail/CVE-2021-26855

The lab implements toy patterns only. It does not implement JNDI, Bash, TLS,
OpenSSL, Spring, Tomcat, Exchange, external callbacks, file writes, persistence,
or real command execution.

Cleanup:

```bash
docker compose -f labs/aegispt_lab_suite/docker-compose.yml down
# container and compose network removed
```

## Boundaries

- No live AegisPT run was launched against the lab in this change.
- No claim is made that AegisPT solves these challenges yet.
- This is not an XBOW replacement; it is a standalone local target for future
  generalization tests.
- The default compose seed is deterministic for local smoke tests. Operators
  can set `AEGISPT_LAB_FLAG_SEED` to avoid predictable flags in future runs.
