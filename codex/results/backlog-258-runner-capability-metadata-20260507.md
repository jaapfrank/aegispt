# backlog-258 Runner Capability Metadata Evidence

Date: 2026-05-07

## Scope

Implemented machine-readable capability metadata for the registered runner set, loaded it through `RunnerRegistry`, and exposed it through `GET /api/v1/runners/capabilities`.

The metadata is additive and informational only. Runner implementations, run profiles, dispatch, approvals, scope, ROE, credentials, reports, provenance, runtime binding, and kill-switch behavior were not changed for this task.

## Registry Evidence

- Registered runner count: 58
- Capability metadata count: 58
- Missing tools: none
- Unexpected tools: none
- Registry `complete`: true
- Metadata source: `workers/runners/capabilities.json`

Planner-gate signal checks:

- `sqlmap` triggers: `injectable_parameter`, `sql_error_pattern`, `form_with_post_action`
- `sqlmap` blockers include `no_injectable_parameter`
- `sqlmap` triggers do not include PHP/MySQL technology labels as sufficient evidence
- `jwt-probe` triggers include `jwt_in_response`
- `deserialization-probe` triggers include `java_indicators`

## API Acceptance

`http://127.0.0.1:8000` was relevant because the task adds an API endpoint. The already-running server on port 8000 was stale relative to the current checkout and returned 404 for the new endpoint, so it was not used as current-code proof.

Current-code acceptance used a temporary API server on `http://127.0.0.1:8018` with a temporary SQLite database. The endpoint returned:

```text
complete True
registered 58
capabilities 58
missing []
unexpected []
has_sqlmap True
sqlmap_triggers ['injectable_parameter', 'sql_error_pattern', 'form_with_post_action']
has_jwt_trigger True
has_java_trigger True
```

The temporary server was shut down after acceptance.

## Validation

- `python3 scripts/validate_backlog_tasks.py` passed before implementation with exactly one active task.
- `source .venv/bin/activate && python -m pytest api/tests/test_runner_capabilities.py -q` passed.
- `source .venv/bin/activate && python -m pytest api/tests/ -q` passed with exit code 0.
- Current-code API acceptance passed on `127.0.0.1:8018`.
- Final `git diff --check` and post-promotion backlog validation are recorded in `DONE_LOG.md`.

## Runtime Note

During pre-validation inspection, the existing long-running local mission showed a Website/Web App run routed into `FULL-EXTERNAL-WEB` phase 1 at `passive-easm-discovery`, with stale running task state and no execution evidence. That behavior was not changed in this metadata-only task and is tracked separately in `risico.md` / `extra_tests.md`.
