# Active Task

## Title

Recon-first wizard flow: wizard default starts low-impact recon, then shows evidence-based assessment plan before any active scanning

## Promoted From

`codex/tasks/backlog-257-adaptive-recon-first-wizard-flow.json`

## Goal

Implement the active backlog package `codex/tasks/backlog-257-adaptive-recon-first-wizard-flow.json` so the wizard can start with honest low-impact active recon, then show SignalProfile and AssessmentPlan before deeper assessment launch.

## Scope

Implement the active backlog package `codex/tasks/backlog-257-adaptive-recon-first-wizard-flow.json`.

Expected slice:

- add a wizard option for quick low-impact active recon using nmap + httpx language that clearly says it sends network traffic
- require explicit operator approval before the recon step runs
- show SignalProfile summary after recon completes
- show the backlog-255 AssessmentPlan after SignalProfile evidence exists
- keep the existing `I already know what to test` depth-selection path fully functional
- preserve existing runner registry, approval gates, provenance, reports, runtime binding, scope, ROE, credentials, and kill switch

## Constraints

- Do not implement until this file is the single active task.
- Prerequisites are hard-gated: backlog-255, backlog-256, and backlog-258 must be complete in `DONE_LOG.md`.
- Do not describe nmap or httpx as passive; use low-impact active recon language.
- Do not remove or regress existing depth selection.
- Do not create new runners.
- Do not change approval gate thresholds or phase runner implementations.
- Do not auto-dispatch deeper assessment tools without operator review/approval.

## Validation

- `python3 scripts/validate_backlog_tasks.py`
- `source .venv/bin/activate && python -m pytest api/tests/ -q`
- `source .venv/bin/activate && python -m pytest ui/tests/ -q`
- `git diff --check`

## Acceptance

- Wizard Step 2 shows a `Start with quick recon (recommended)` option with honest copy: sends network traffic to target, nmap port scan + HTTP fingerprinting, no exploitation, approximately five minutes.
- Recon step requires approval before running.
- SignalProfile appears after recon.
- AssessmentPlan renders after SignalProfile.
- Existing depth selection remains unchanged.
- No UI copy labels nmap or httpx as passive.
- Existing wizard flow tests do not regress.
