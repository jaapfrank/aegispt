# Active Task

## Title

Review Checkpoint: Picker Reliable, Cost-Controlled, On Target (Phase 3 close-out)

## Goal

After #330-#332, confirm the picker is now (a) parse-failure-free, (b) resilient to transient failures, (c) measurably cheaper per advance. Decide go/no-go for Phase 4 (cross-target + verifier).

## Scope

- Live run for at least 30 picker advances across 2 different runs (one Gruyere, one non-Gruyere) — observable from `/tmp/aegispt-api.log` AI-loop hop usage lines.
- Measure parse-fail rate (target: 0%), retry rate (any `retries_this_advance > 0` events), and cost per advance from logged `input + cache_read + cache_creation + output` token counts.
- Written checkpoint report at `docs/checkpoints/2026-mythos-phase3-review.md` with explicit GO/NO-GO on Phase 4.

## REVIEW CHECKPOINT — AGENT MUST STOP

**This is a review checkpoint (#333 in the Mythos plan; #324 was Phase 1's, #329 was Phase 2's).** Per the universal prompt rule, the agent **STOPS** here and asks operator for explicit go/no-go before executing the checkpoint body (live runs, log mining, cost extrapolation, report generation, Phase 4 promotion).

When operator approves: agent proceeds to (1) execute 30+ picker advances across one Gruyere + one non-Gruyere target (operator should confirm Anthropic credits + target reachability), (2) extract parse-fail count, retry count, avg tokens per hop from `/tmp/aegispt-api.log`, (3) write `docs/checkpoints/2026-mythos-phase3-review.md` citing real numbers, (4) emit GO/NO-GO with justification, (5) on GO: promote backlog-384 (#334 Phase 4 day 1) into NEXT_TASK; on NO-GO: name + queue a corrective task.

## Constraints

- Review only. NO production code changes. Output is a checkpoint report and a yes/no decision on Phase 4 promotion.
- Evidence requirement: report must cite real numbers from logs (parse-fail count, retry count, avg input/output/cache tokens per hop, estimated daily cost) — no aspirational claims.
- Must NOT touch: `api/app/services/`, `workers/runners/`, `workers/orchestration/`, `ui-v2/` — review-only task.

## Source Package

`codex/tasks/backlog-383-review-checkpoint-picker-reliable.json`

## Reference

- `DONE_LOG.md` entries for #330 (structured outputs), #331 (soft retry), #332 (memory truncation)
- `docs/AGENT_SYSTEM_MAP.md` section 2 (all three Phase-3 known issues now resolved) + section 6 (memory truncation paragraph)
- `docs/checkpoints/2026-mythos-phase2-review.md` (template format for the Phase 3 checkpoint report)
- Cost baseline: ~$300/day pre-Phase 3 per AGENT_SYSTEM_MAP section 5; target ≤35% of that (~$100/day) per success criterion #3.

## Validation

- `python3 scripts/validate_backlog_tasks.py`
- `test -f docs/checkpoints/2026-mythos-phase3-review.md`
- Acceptance: parse-fail rate is 0% over the test window; estimated daily cost ≤35% of pre-Phase-3 baseline.
