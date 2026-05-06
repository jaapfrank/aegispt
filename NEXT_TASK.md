# Active Task

## Title

sqlmap blind and advanced SQLi: cover AutoPenBench WS4 complex SQL injection with filtered inputs using bounded approval-gated sqlmap profile improvements

## Promoted From

`codex/tasks/backlog-247-sqlmap-blind-and-advanced-sqli.json`

## Goal

Implement the active backlog package `codex/tasks/backlog-247-sqlmap-blind-and-advanced-sqli.json` so AegisPT improves sqlmap coverage for complex/blind SQL injection with input filters while preserving the existing approval gate, scope handling, runtime binding, and no-dump safety posture.

## Scope

Implement the active backlog package `codex/tasks/backlog-247-sqlmap-blind-and-advanced-sqli.json`.

Expected slice:

- keep Phase A quick sqlmap detection at level 1 / risk 1
- add Phase B advanced sqlmap mode at level 3 / risk 2 for possible endpoints
- add bounded tamper support for `space2comment`, `between`, and `randomcase`
- add WAF detection with `--identify-waf`
- include time-based blind detection in Phase B through `--technique=T`
- preserve existing parameter selection and finding schema behavior
- never dump database contents, never use `--risk 3`, and never enable sqlmap OS shell behavior

## Constraints

- Do not implement until this file is the single active task.
- Do not change how parameters are selected or how findings are stored.
- Do not bypass approvals, scope, ROE, deployment, runtime binding, credential gates, or kill switch.
- Max sqlmap risk is `2`; do not use `--risk 3`.
- Do not dump database contents.
- Do not add sqlmap OS shell behavior.
- No runtime self-modification.
- No uncontrolled plugin installation.

## Validation

- `python3 scripts/validate_backlog_tasks.py`
- `source .venv/bin/activate && python -m pytest api/tests/ -q`
- `git diff --check`

## Acceptance

- Phase A/B split is implemented for sqlmap.
- Phase B uses level 3 / risk 2 with the bounded tamper scripts.
- Phase B includes time-based blind detection.
- WAF detection and auto-tamper selection are implemented.
- Blind SQLi can be detected on the approved test target or deterministic equivalent.
- Findings do not contain database dumps.
- Existing SQLi tests do not regress.
