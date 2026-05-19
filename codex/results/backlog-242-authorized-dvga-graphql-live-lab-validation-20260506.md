# Backlog 242 - Authorized DVGA GraphQL Live-Lab Validation

Timestamp: 2026-05-06T10:45:00+02:00

## Scope Decision

- Active task: `codex/tasks/backlog-242-authorized-dvga-graphql-live-lab-validation.json`
- Authorized active roots: `http://127.0.0.1:5013/` and `http://localhost:5013/`
- Active validation target used: `http://127.0.0.1:5013/`
- `http://127.0.0.1:8000` relevance: not used. This task required local DVGA live-lab proof for the direct `graphql-probe` runner, not an AegisPT UI/API browser validation path.
- Public DVGA, Docker Hub, GitHub, and PortSwigger pages were used only as read-only documentation. No public GraphQL target was scanned.

## Official DVGA Sources

- GitHub repository: `https://github.com/dolevf/Damn-Vulnerable-GraphQL-Application`
  - The README describes DVGA as an intentionally vulnerable GraphQL implementation for learning and practicing GraphQL security.
  - It documents GraphQL scenarios covering discovery, batch query, deep recursion, introspection, GraphiQL interface, field suggestions, and SQL injection.
  - It documents Docker execution on port `5013`.
- Docker Hub image: `https://hub.docker.com/r/dolevf/dvga`
  - Documents `docker run -t -p 5013:5013 -e WEB_HOST=0.0.0.0 dolevf/dvga`.
  - Pulled digest: `sha256:040aa33c199d99f3380c9ff9a1ee5d725e9abca7b189c63a35a2a73bda79c957`.
- DVGA local source in the launched container confirmed:
  - `/graphql` and `/graphiql` routes in `/opt/dvga/core/views.py`
  - GraphiQL protection behavior in `/opt/dvga/core/middleware.py`
  - SQL injection challenge source in `/opt/dvga/templates/partials/solutions/solution_15.html`
  - GraphiQL challenge source in `/opt/dvga/templates/partials/solutions/solution_7.html` and `solution_16.html`

## Local Lab Launch

Command used:

```bash
docker run -d --rm -p 127.0.0.1:5013:5013 -e WEB_HOST=0.0.0.0 --name aegispt-dvga-backlog242 dolevf/dvga
```

Container proof:

```text
6b4bcef94af7 aegispt-dvga-backlog242 dolevf/dvga 127.0.0.1:5013->5013/tcp
```

Readiness proof:

```text
GET http://127.0.0.1:5013/ -> 200 OK
title: Damn Vulnerable GraphQL Application
```

## Narrow Runner Repair

The first live runner run found `/graphql`, introspection, field suggestions, bounded depth, and batching, but missed GraphiQL exposure because DVGA renders GraphiQL only when the client requests HTML and supplies a query string. It also did not produce the documented DVGA SQL backend-error signal with the previous payload set.

The repair was limited to:

- probe IDE paths with `Accept: text/html,application/xhtml+xml` and a safe `query AegisPTGraphiQL { __typename }` query string
- add a bounded syntax-error payload `aegispt '` that triggers DVGA's documented `pastes(filter:)` SQL error path
- filter argument-injection candidates away from dangerous DVGA fields such as `systemDiagnostics`, `systemDebug`, upload/import/delete/create/edit/login/admin/command surfaces

The live post-repair request log confirms `unsafe_system_diagnostics_probe: false`.

## Expected vs Actual

Full structured evidence is in:

- `codex/results/backlog-242-authorized-dvga-graphql-live-lab-validation-20260506.json`

Summary:

```json
{
  "candidate_endpoint_count": 4,
  "check_count": 20,
  "depth_findings": 1,
  "discovered_endpoint_count": 1,
  "finding_count": 5,
  "injection_findings": 1,
  "introspection_findings": 1,
  "schema_map_count": 1,
  "suggestion_findings": 1,
  "target_count": 1
}
```

Expected-vs-actual:

```json
{
  "argument_injection_error_signal": true,
  "batching_capability": true,
  "bounded_depth_signal": true,
  "endpoint_discovery": true,
  "field_suggestions": true,
  "graphiql_exposure": true,
  "introspection": true
}
```

Normalized findings through the existing extraction path: `5`.

Detected findings:

- `GraphQL Playground or IDE Exposed`
- `GraphQL Introspection Enabled - Full Schema Disclosed`
- `GraphQL Field Suggestion Leakage`
- `GraphQL Missing Query Depth Limit`
- `GraphQL Argument Injection Error Signal`

Batching is recorded as an accepted capability check with batch size `2`, not as a rate-limit bypass finding.

## Outbound Active Request Summary

All active validation requests stayed under `http://127.0.0.1:5013/`.

- `GET /graphiql?query=query+AegisPTGraphiQL+%7B+__typename+%7D`
- `GET /playground?query=query+AegisPTGraphiQL+%7B+__typename+%7D`
- repeated bounded `POST /graphql` probes for detection, introspection, field suggestion, depth, argument injection, and batch size `2`
- `POST /api/graphql`, `POST /v1/graphql`, and `POST /gql` endpoint-discovery candidates, all returning non-detected 404s

No request targeted a public GraphQL service. No OS command, arbitrary file write, denial-of-service, resource exhaustion, subscription flooding, credential attack, account takeover, persistence scenario, mutation execution, or public target scan was performed.
