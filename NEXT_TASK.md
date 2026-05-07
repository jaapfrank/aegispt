# Active Task

## Title

Evidence-driven Adaptive Assessment Planner: scores runners using signal evidence and runner metadata, produces run/skip/wait/approval plan with reasoning

## Promoted From

`codex/tasks/backlog-255-ai-adaptive-assessment-planner.json`

## Goal

Implement the active backlog package `codex/tasks/backlog-255-ai-adaptive-assessment-planner.json` so AegisPT can produce an operator-reviewed assessment plan from `SignalProfile` plus `RunnerCapabilityMetadata`.

## Scope

Implement the active backlog package `codex/tasks/backlog-255-ai-adaptive-assessment-planner.json`.

Expected slice:

- create the evidence-driven planner service that reads existing SignalProfile data and runner capability metadata
- produce per-runner RUN / SKIP / WAIT / NEEDS_APPROVAL decisions with confidence and concise evidence-backed reasons
- ensure sqlmap waits when there is no injectable parameter or SQL error pattern evidence, even if PHP/MySQL technology is detected
- ensure JWT and deserialization decisions follow the runner metadata signals
- expose planner output through the existing run/API surface needed by Mission Control
- render the operator-reviewed plan before Phase 2 launch
- dispatch only operator-approved RUN items through existing registered runners and approval gates
- preserve existing manual/wizard paths, fixed-chain flows, runner registry, approval gates, provenance, reports, runtime binding, scope, ROE, credentials, and kill switch

## Constraints

- Do not implement until this file is the single active task.
- Prerequisites are hard-gated: backlog-256 SignalProfile and backlog-258 RunnerCapabilityMetadata must be complete in `DONE_LOG.md`.
- Planner selects from existing approved runners only.
- Do not create new runners.
- Do not bypass or weaken approval gates, especially intrusive approvals.
- Do not auto-dispatch without operator review/approval.
- Do not change runner implementations.
- Do not change intrusive approval gates or run profile definitions.
- Keep the existing manual/wizard path and fixed-chain flows intact.

## Validation

- `python3 scripts/validate_backlog_tasks.py`
- `source .venv/bin/activate && python -m pytest api/tests/ -q`
- `git diff --check`

## Acceptance

- AssessmentPlan is produced after recon phase with RUN / SKIP / WAIT / NEEDS_APPROVAL decision per runner.
- Each decision includes one concise plain-language reason grounded in SignalProfile and RunnerCapabilityMetadata.
- sqlmap decision is WAIT when no injectable parameter or SQL error pattern evidence exists.
- jwt-probe decision is SKIP when JWT response/token signals are absent.
- Intrusive runners always show NEEDS_APPROVAL regardless of evidence score.
- Mission Control shows the operator-reviewed plan before launch.
- Only operator-approved RUN items are dispatched.
- Existing chain and assessment tests do not regress.
