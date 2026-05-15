# Active Task

## Title

Review Checkpoint: Evidence-Graph Foundation On Target

## Goal

Step back after #321-#323 and verify the evidence-graph adoption work is on track. Confirm graph entities flow end-to-end from runners through ingestion helpers into the picker context. Catch architectural drift before committing to Phase 2.

## Scope

Operator + agent review of work merged from backlog-371, -372, -373. Live test on at least 2 contrasting targets (Gruyere + one non-Gruyere) showing graph-aware picker decisions. Written checkpoint report with go/no-go on Phase 2.

## Constraints

- Review only. No production code changes. Output is a checkpoint report and a yes/no decision on Phase 2 promotion.
- Decision gate: if review surfaces architectural drift or scope creep, the report must identify the corrective task before #325 is promoted.

## Source Package

`codex/tasks/backlog-374-review-checkpoint-foundation.json`

## Reference

- `docs/evidence_graph_adoption_plan.md` (#321 audit output)
- `docs/MYTHOS_PLAN_FINALITY.md` (governance contract)

## Validation

- `python3 scripts/validate_backlog_tasks.py`
- `test -f docs/checkpoints/2026-mythos-phase1-review.md`

## REVIEW CHECKPOINT — STOP

This is a Phase 1 review checkpoint per the Mythos plan. Per the universal session prompt:
- The agent must NOT auto-execute this checkpoint without operator authorization.
- Live runs against contrasting targets need operator decision on which targets are in scope.
- The checkpoint report itself is a deliberation document, not a coding task.

Operator action required before this task can proceed: say "go" and confirm which non-Gruyere target to run against (juice-shop / testfire / testasp / your lab AD).
