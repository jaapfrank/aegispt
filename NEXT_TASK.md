# Active Task

## Title

Gruyere multi-step chain acceptance test: prove all 6 Gruyere vulnerability layers detectable by chaining AI proposals and Free Bash execution

## Promoted From

`codex/tasks/backlog-254-gruyere-multi-step-chain-acceptance-test.json`

## Goal

Implement the active backlog package `codex/tasks/backlog-254-gruyere-multi-step-chain-acceptance-test.json` so AegisPT has a local-only Gruyere acceptance test proving how chained AI proposals plus approved execution discover all six Gruyere vulnerability layers.

## Scope

Implement the active backlog package `codex/tasks/backlog-254-gruyere-multi-step-chain-acceptance-test.json`.

Expected slice:

- add a safe local Docker Gruyere lab target for acceptance validation
- add a test script or pytest coverage that runs AegisPT against the local Gruyere fixture and records per-layer detection status
- verify layers 1-2 through existing scanner paths without AI shell execution
- verify layers 3-6 through AI proposal -> approval -> registered execution chain when the existing Free Bash/AI shell capability is available
- produce `gruyere-chain-acceptance-report.json` with per-layer status, proposal rationale, approved execution steps, findings, and evidence links
- preserve existing AI proposal review, runner registry, approval gates, scope enforcement, ROE, credentials, runtime binding, provenance, reporting, and kill-switch behavior

## Constraints

- Do not implement until this file is the single active task.
- Work only against the local Gruyere Docker instance; never test against `google-gruyere.appspot.com` or any other live public target.
- Do not bypass AI Free Bash approval gates, runner registration, scope enforcement, ROE, credential prerequisites, provenance, report generation, or kill switch behavior.
- Do not silently mark layers 3-6 green if the AI proposal/execution prerequisite is missing, skipped, blocked, timed out, or not executed.
- All shell/proof steps must stay inside explicit local engagement scope.
- If the package is partially blocked or obsolete because current code has different prerequisites, document that truth in `DONE_LOG.md`, `CURRENT_STATE.md`, `risico.md`, and `extra_tests.md` rather than faking acceptance.

## Validation

- `python3 scripts/validate_backlog_tasks.py`
- `source .venv/bin/activate && python -m pytest ui/tests/test_gruyere_chain_acceptance.py -v`
- `git diff --check`

## Acceptance

- Local Gruyere Docker instance runs in the test environment.
- Layers 1-2, reflected XSS and stored XSS, are found without AI shell execution.
- Layers 3-6 are found through AI proposal, operator/test approval, and registered shell execution chain.
- `gruyere-chain-acceptance-report.json` documents all six layers, proposal rationale, executed commands, and evidence/finding links.
- No live public Gruyere target is touched.
