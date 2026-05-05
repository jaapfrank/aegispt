# Active Task

## Title

GraphQL security runner: introspection abuse, query depth attacks, field suggestion, injection via GraphQL

## Promoted From

`codex/tasks/backlog-227-graphql-security-runner.json`

## Goal

Add the queued GraphQL security capability described in `codex/tasks/backlog-227-graphql-security-runner.json`.

## Scope

Implement the active backlog package `codex/tasks/backlog-227-graphql-security-runner.json`.

Expected slice:

- detect GraphQL endpoints such as `/graphql`, `/api/graphql`, `/v1/graphql`, and `/gql`
- detect GraphQL playground or IDE exposure such as `/graphiql` and `/playground`
- detect successful introspection and produce schema-disclosure findings
- use schema enumeration for subsequent bounded field testing
- detect missing query depth limiting with a bounded depth probe
- detect field suggestion leakage
- test injection payloads in GraphQL string arguments
- represent batching and authorization-bypass checks safely within the package constraints
- expose the capability through the supported execution registry and operator surfaces required by the package

## Constraints

- Keep Prompt 1 and Prompt 2 intact.
- Add only the GraphQL security capability from the task package.
- Do not bypass local provenance, scope, ROE, validation, approval, deployment, runtime binding, credential gates, or kill switch.
- No runtime self-modification.
- No uncontrolled plugin installation.
- GraphQL detection and probing must stay within approved scope.
- Depth attack probe is capped at max 20 levels and must stop immediately.
- No batching attacks that could overwhelm the server.
- Do not change the existing API assessment runner or ZAP config.
- No live target actions outside safe/local/explicitly authorized validation.

## Validation

- `python3 scripts/validate_backlog_tasks.py`
- `source .venv/bin/activate && python -m pytest api/tests/ -q`
- `git diff --check`

## Acceptance

- `graphql-probe` is registered in supported tools.
- GraphQL endpoints are detected automatically.
- Introspection findings are produced on a test GraphQL endpoint.
- Schema enumeration is used for subsequent field testing.
- GraphQL argument injection is tested in a bounded active tier requiring approval.
- Existing runner/API tests do not regress.
