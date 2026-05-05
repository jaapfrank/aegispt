# backlog-227 GraphQL Probe Runner Evidence

## Scope

Implemented the active task from `NEXT_TASK.md`: `codex/tasks/backlog-227-graphql-security-runner.json`.

The slice adds `graphql-probe` as an approval-gated GraphQL security capability for approved web/API roots. It does not change the existing API assessment runner or ZAP configuration.

## Product Behavior

- `graphql-probe` discovers GraphQL endpoints from common/configured paths such as `/graphql`, `/api/graphql`, `/v1/graphql`, and `/gql`.
- It detects exposed GraphQL IDE/playground interfaces from common/configured paths.
- It sends a bounded introspection query and builds a schema map with query/mutation fields and string/ID arguments.
- It uses the schema map for bounded field suggestion, depth-limit, and argument-injection checks.
- Depth probing is capped at 20 levels.
- Batching is represented with a two-query capability check only; no rate-limit bypass or high-volume batching is attempted.
- Authorization-bypass candidates are recorded as safe check records; no unauthenticated data extraction or type-confusion exploitation is attempted.

## Validation

- `python3 scripts/validate_backlog_tasks.py` passed before implementation.
- `python3 -m py_compile workers/runners/graphql_probe/runner.py workers/orchestration/tasks.py workers/orchestration/findings.py api/app/services/runs.py api/app/services/run_profiles.py api/app/services/ai_agent.py api/app/methodology.py workers/tests/test_graphql_probe_runner.py api/tests/test_pentest_depth_registration.py api/tests/test_runs.py workers/tests/test_web_depth_runner.py` passed.
- `source .venv/bin/activate && python -m pytest workers/tests/test_graphql_probe_runner.py api/tests/test_pentest_depth_registration.py workers/tests/test_web_depth_runner.py api/tests/test_runs.py::test_list_run_profiles api/tests/test_runs.py::test_active_graphql_probe_profile_requires_approval_and_queues_graphql_task -q` passed.
- `source .venv/bin/activate && python -m pytest api/tests/ -q` passed with existing Alembic deprecation warnings; the `AEGISPT_DB_KEY or --key is required.` line is emitted by an existing negative startup test and the command exited 0.
- `git diff --check` passed.
- `curl -fsS --max-time 5 http://127.0.0.1:8000/health/live` returned healthy development runtime.
- `curl -fsS --max-time 5 http://127.0.0.1:8000/app/assets/modules/packs.js | rg -n "graphql-probe|GraphQL Probe"` confirmed the live-served Tool Library module contains the new entry.

## Evidence Boundary

The functional proof uses deterministic safe fixtures and read-only local UI asset acceptance. No public GraphQL lab, Gruyere/WebGoat, or internet target was actively scanned during this build-lane task.

Remaining risks:

- real-world GraphQL coverage depends on target-specific schema, authentication context, and safe operator-approved scope
- authorization-bypass and batching checks are safe representation checks, not exploit attempts
- argument injection findings are backend-error/evidence signals and do not extract records or perform database exploitation
