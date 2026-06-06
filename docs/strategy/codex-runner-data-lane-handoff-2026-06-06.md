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
| 2 | `lab_truth` tagging: `known_clean` / `known_vulnerable` / `live_no_oracle` | DONE for current generated lab specs and local benchmark suites. `scripts/training/make_lab_truth_heldout_registry_iter6.py` emits a lab-truth registry; generated live-lab specs and the standalone lab suite are `known_vulnerable`, and unknown live targets still default to `live_no_oracle`. | Later slice: wire runner export to look up this registry automatically when a run has a canonical lab/target ID. |
| 3 | No-finding artifact from runner state: coverage, untested boundaries, blockers | Partial. `from_runner_tasks(...)` derives tool-level coverage, blockers, untested task states, and evidence refs from stored executions. | Feed richer coverage from existing `coverage_truth` / assessment-plan state: routes, auth state, inputs tested, blocked prerequisites, and explicitly untested boundaries. |
| 4 | Held-out registry of scenario IDs for Claude's `load_held_out()` / pipeline guard | DONE for current eval/lab assets. The registry has exact IDs for `deep_chain_eval`, LLMSVS adversarial eval, iter6 multi-turn eval/test, and standalone lab-suite benchmark challenges. `jury_factory.load_held_out(...)` can now read the registry JSON directly as well as JSONL files. | Later slice: keep adding new eval/test scenario IDs to the registry whenever new held-out families are introduced. |
| 5 | Reviewer rubric/prompts for structured verdicts by perspective | Fase-3 prep, gated. No reviewer model calls should be wired before capability and real trajectories exist. | Draft structured verdict rubrics only: Codex code/logical consistency, Claude reasoning/safety, DeepSeek/Grok alternate routes, local judge schema checks. Keep execution disabled until Phase 3. |

## Current Contract

The shared trace contract is:

- `scripts/training/jury_review.py`
- `scripts/training/trace_record.py`
- `scripts/training/jury_pipeline.py`
- `scripts/training/make_lab_truth_heldout_registry_iter6.py`

Generate the Codex registry / extracts with:

```bash
python3 scripts/training/make_lab_truth_heldout_registry_iter6.py
```

Claude's existing held-out guard can consume either the generated registry JSON
or the generated `_held_out.jsonl` extract:

```bash
python3 scripts/training/jury_pipeline.py \
  --traces <trace-dir> \
  --held-out ~/.aegispt-tools/training/aegispt_lab_truth_heldout_registry_iter6.json \
  --out <factory-out>
```

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

Current status update: task #2 now supplies canonical lab truth for the current
generated lab specs and standalone benchmark suite. Task #3 is still the main
remaining no-finding lever because richer route/auth/input coverage must come
from runner state, not from static metadata.
