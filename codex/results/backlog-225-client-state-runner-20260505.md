# backlog-225 Client-State Runner Evidence

## Scope

Implemented the active backlog-225 slice as a dedicated `client-state` runner for approved web roots. The capability validates server-side authorization weaknesses exposed by client-controlled state, while staying inside the existing approval, credential materialization, scope, task dispatch, and finding extraction paths.

## Implemented Behavior

- Hidden field privilege manipulation from configured form contexts.
- Cookie-based role/admin manipulation, including a Gruyere-style admin cookie context for `/newsnippet`-style patterns.
- Request parameter privilege manipulation in configured POST/PUT-style contexts.
- Price, amount, total, and quantity manipulation in configured order/payment contexts.
- Direct later-step workflow access for configured multi-step flow contexts.
- Structured `client-state-results.json` output with summary counts, replay metadata, methodology tags, and safety metadata.

## Safety Evidence

- The runner requires at least one configured authenticated access context.
- Approved web-root path scope is enforced before execution and for configured endpoints/actions.
- Runtime execution uses only parameter, form, and cookie mutation probes.
- No post-exploitation chaining is implemented.
- Raw credential values and raw cookie values are not stored in artifacts.
- The run profile is active-tier and requires one approval before queueing.

## Fixture Proof

`workers/tests/test_client_state_runner.py` uses a deterministic local `httpx.MockTransport` fixture that proves:

- a hidden `role=user` field changed to admin creates a hidden-field finding
- an `admin=false` cookie changed to true creates a cookie privilege finding
- an `is_admin=False` Gruyere-style cookie changed to true creates an additional cookie privilege finding for a `/newsnippet`-style endpoint
- an `isAdmin=false` JSON request field changed to true creates a server-side authorization bypass finding
- a `price=99.00` order value changed to a lower amount creates a price manipulation finding
- direct access to `checkout/confirm` creates a workflow step-skipping finding

## Validation Commands

- `python3 scripts/validate_backlog_tasks.py`
- `python3 -m py_compile workers/runners/client_state/runner.py workers/orchestration/tasks.py workers/orchestration/findings.py api/app/services/runs.py api/app/services/run_profiles.py api/app/services/ai_agent.py api/app/methodology.py workers/tests/test_client_state_runner.py api/tests/test_pentest_depth_registration.py api/tests/test_runs.py`
- `source .venv/bin/activate && python -m pytest workers/tests/test_client_state_runner.py api/tests/test_pentest_depth_registration.py workers/tests/test_web_depth_runner.py -q`
- `source .venv/bin/activate && python -m pytest api/tests/test_runs.py::test_list_run_profiles api/tests/test_runs.py::test_active_client_state_profile_requires_approval_and_queues_authenticated_task -q`

The full required API-suite, final backlog validator, `git diff --check`, and live read-only acceptance checks are recorded in `DONE_LOG.md` for the completed task.

## Remaining Gaps

- No public Gruyere or WebGoat target was actively scanned during this build-lane slice; proof is deterministic safe fixture evidence.
- Real client-state findings depend on operators supplying valid in-scope authenticated access contexts plus explicit form/cookie/request/price/workflow contexts.
- The runner validates server-side acceptance signals and does not attempt account takeover or post-exploitation.
