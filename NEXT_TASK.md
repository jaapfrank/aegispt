# Active Task

## Title

Authorized DVGA GraphQL live-lab validation: prove graphql-probe against a real vulnerable GraphQL target

## Promoted From

`codex/tasks/backlog-242-authorized-dvga-graphql-live-lab-validation.json`

## Goal

Launch a local Damn Vulnerable GraphQL Application (DVGA) lab target and prove the completed graphql-probe runner against a real intentionally vulnerable GraphQL service, not only deterministic fixtures. Use the official DVGA documentation and repository as the benchmark source, then run only bounded, scope-enforced GraphQL validation against localhost/127.0.0.1.

## Scope

Implement the active backlog package `codex/tasks/backlog-242-authorized-dvga-graphql-live-lab-validation.json`.

Expected slice:

- launch DVGA locally using documented Docker or equivalent local command, or record the exact blocker if local launch is impossible
- cite the official DVGA repository/documentation that establishes the target as intentionally vulnerable and intended for GraphQL security practice
- validate only backlog-227 GraphQL coverage against the local DVGA lab: endpoint discovery, GraphiQL/IDE exposure, introspection, field suggestions, bounded depth-limit signal, batching capability signal, and argument-injection error signal
- run `graphql-probe` only against `http://127.0.0.1:5013/` or `http://localhost:5013/` with approved scope and structured artifacts
- record expected-vs-actual detection for each required GraphQL behavior
- normalize findings through the existing extraction path, or record any miss honestly as product truth with a bounded follow-up

## Constraints

- Do not implement until this file is the single active task.
- Do not add unrelated GraphQL exploitation families in this task.
- Live target actions are allowed only against a locally launched DVGA container on localhost/127.0.0.1 and only for bounded GraphQL validation.
- Public DVGA or PortSwigger URLs may be used as read-only documentation unless the operator explicitly authorizes a specific ephemeral lab URL.
- All active validation requests must stay under `http://127.0.0.1:5013/` or `http://localhost:5013/`.
- Do not scan `dvga.tools.escape.tech` or PortSwigger lab hosts unless separately and explicitly authorized in the active task.
- Do not execute OS command, arbitrary file write, denial-of-service, resource exhaustion, subscription flooding, credential attack, account takeover, or persistence scenarios.
- Query-depth and batching probes must remain bounded to the existing graphql-probe safety limits.
- Use the existing active approval/run safety model where the product path supports it.
- Direct runner validation is allowed only as local lab proof and must still use approved-scope configuration.
- No runtime self-modification.
- No uncontrolled plugin installation.

## Validation

- `python3 scripts/validate_backlog_tasks.py`
- `source .venv/bin/activate && python -m pytest workers/tests/test_graphql_probe_runner.py api/tests/test_pentest_depth_registration.py -q`
- `source .venv/bin/activate && python -m pytest api/tests/ -q`
- `git diff --check`

## Acceptance

- The local DVGA lab root is the only active target root used for validation.
- Evidence includes official DVGA source references, exact local target URL, command/results summary, produced artifact paths, and expected-vs-actual GraphQL coverage.
- Any detection gap is recorded honestly and converted into a bounded next action rather than hidden behind green fixture tests.
