# Active Task

## Title

DVGA GraphQL command-injection runner: approval-gated OS command evidence on local lab only

## Promoted From

`codex/tasks/backlog-251-dvga-graphql-command-injection-runner.json`

## Goal

Implement the active backlog package `codex/tasks/backlog-251-dvga-graphql-command-injection-runner.json` so DVGA GraphQL command-injection validation is a separate governed local-lab capability with approval, scope, provenance, reporting, and kill-switch boundaries.

## Scope

Implement the active backlog package `codex/tasks/backlog-251-dvga-graphql-command-injection-runner.json`.

Expected slice:

- add a dedicated command-injection runner or clearly named GraphQL command-injection mode separate from generic `graphql-probe`
- wire it through existing orchestration, finding extraction, provenance, report/replay recipe, approval validation, and run profile flows
- require explicit intrusive/exploitation authorization before command-bearing payloads are sent
- enforce a minimal harmless command allowlist for the local DVGA proof
- prove the documented DVGA `systemDiagnostics` command-injection challenge against only the local authorized DVGA root

## Constraints

- Do not implement until this file is the single active task.
- Work only on governed GraphQL command-injection detection and DVGA local-lab proof.
- Do not add arbitrary shell, persistence, credential attacks, public target execution, reverse shells, file write, lateral movement, privilege escalation, or broad RCE exploitation families.
- Use existing approval, scope, ROE, runtime binding, credential, provenance, reporting, and kill-switch gates.
- Keep generic `graphql-probe` safe discovery behavior separate.
- Use only a local DVGA instance at `http://127.0.0.1:5013/` or `http://localhost:5013/` for live command-injection acceptance unless a future active task explicitly authorizes another target.

## Validation

- `python3 scripts/validate_backlog_tasks.py`
- `source .venv/bin/activate && python -m pytest workers/tests/test_graphql_command_injection_runner.py workers/tests/test_graphql_probe_runner.py api/tests/test_pentest_depth_registration.py -q`
- `source .venv/bin/activate && python -m pytest api/tests/ -q`
- `git diff --check`

## Acceptance

- Only the local DVGA lab root is used for live command-injection acceptance.
- The command-bearing payload uses an allowlisted harmless command and produces structured proof without destructive effects.
- The run path remains approval-gated, scope-enforced, provenance-backed, report-backed, and kill-switch compatible.
- Unsupported command-injection scenarios are recorded as product truth with bounded follow-up rather than hidden behind green fixtures.
