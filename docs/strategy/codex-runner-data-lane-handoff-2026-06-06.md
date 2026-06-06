# Codex Runner/Data-Lane Handoff - 2026-06-06

Purpose: keep the Codex-side work for the Trace -> Jury -> Factory loop explicit
and separate from Claude's training/decision-lane work. This file is a handoff
note, not an active `NEXT_TASK.md` promotion and not a runtime permission change.

## Boundary

- Active score-lane task remains T-CHAIN1 in `NEXT_TASK.md`; do not mark it done
  without the live XBEN-024 proof artifact required there.
- Claude owns the training/decision-lane Phase-1 pieces already committed in:
  - `65fe05c` trace recorder contract and deep-chain side
  - `0250114` training factory and held-out guard
  - `36dea16` `jury_pipeline.py` Phase-1 capstone
- Codex owns the runner/data-side inputs that make real AegisPT/XBEN/lab runs
  jury-consumable.

## Codex Task Map

| # | Codex task | Current status | Next Codex action |
|---|---|---|---|
| 1 | Runner-side trace recorder for `assessment_loop` / stored `tool_executions` into `run_trace.jsonl` using `jury_review.TRACE_FIELDS` | Foundation done in `4730591`: `from_runner_tasks(...)` and read-only `--run-id` exporter convert persisted Task/ToolExecution records into the frozen trace schema. | Add a governed, opt-in artifact path after run completion so real runs can persist/export `run_trace.jsonl` without changing dispatch behavior. |
| 2 | `lab_truth` tagging: `known_clean` / `known_vulnerable` / `live_no_oracle` | TODO. Current default is safely `live_no_oracle`; known-vulnerable lab traces can be passed explicitly. | Add canonical lab/target metadata for generated lab specs and local benchmark suites so no-finding traces get the right oracle label. |
| 3 | No-finding artifact from runner state: coverage, untested boundaries, blockers | Partial. `from_runner_tasks(...)` derives tool-level coverage, blockers, untested task states, and evidence refs from stored executions. | Feed richer coverage from existing `coverage_truth` / assessment-plan state: routes, auth state, inputs tested, blocked prerequisites, and explicitly untested boundaries. |
| 4 | Held-out registry of scenario IDs for Claude's `load_held_out()` / pipeline guard | TODO from Codex side. Claude's guard exists, but it needs the canonical scenario IDs for eval/test/lab holdouts. | Create a tracked registry of held-out scenario IDs spanning deep-chain eval, LLMSVS eval, iter6 eval/test, and benchmark/lab holdouts; wire exporters to write scenario IDs consistently. |
| 5 | Reviewer rubric/prompts for structured verdicts by perspective | Fase-3 prep, gated. No reviewer model calls should be wired before capability and real trajectories exist. | Draft structured verdict rubrics only: Codex code/logical consistency, Claude reasoning/safety, DeepSeek/Grok alternate routes, local judge schema checks. Keep execution disabled until Phase 3. |

## Current Contract

The shared trace contract is:

- `scripts/training/jury_review.py`
- `scripts/training/trace_record.py`
- `scripts/training/jury_pipeline.py`

The fixed validation command for this data lane is:

```bash
bash scripts/run_data_lane_tests.sh
```

## Important No-Finding Rule

No-finding is not clean truth by default.

- `known_clean` plus sufficient coverage may become positive SFT.
- `known_vulnerable` plus no finding is a missed finding and can become DPO /
  contrastive data.
- `live_no_oracle` plus no finding remains inconclusive / `do_not_reward`.

Codex tasks #2 and #3 are therefore high leverage: without lab truth and real
coverage evidence, the coverage arbiter must stay conservative.
