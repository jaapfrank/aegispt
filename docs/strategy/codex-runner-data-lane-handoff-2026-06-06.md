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
| 2 | `lab_truth` tagging: `known_clean` / `known_vulnerable` / `live_no_oracle` | DONE for current generated lab specs and local benchmark suites, and wired into the read-only exporter. `scripts/training/make_lab_truth_heldout_registry_iter6.py` emits the registry; `trace_record.py --lab-truth auto --lab-truth-registry ...` resolves known IDs and falls back to `live_no_oracle` on no match. | Later slice: automatic post-run trace persistence can pass canonical lab IDs through the governed artifact path in task #1. |
| 3 | No-finding artifact from runner state: coverage, untested boundaries, blockers | DONE for the read-only exporter path. `from_runner_tasks(...)` derives tool-level coverage and can now merge existing `coverage_truth` surfaces, stop conditions, and blocker IDs. The `--run-id` exporter builds `coverage_truth` by default and offers `--no-coverage-truth` for a minimal trace. | Later slice: persist/export `run_trace.jsonl` automatically after run completion through the governed artifact path in task #1. |
| 4 | Held-out registry of scenario IDs for Claude's `load_held_out()` / pipeline guard | DONE for current eval/lab assets. The registry has exact IDs for `deep_chain_eval`, LLMSVS adversarial eval, iter6 multi-turn eval/test, and standalone lab-suite benchmark challenges. `jury_factory.load_held_out(...)` can now read the registry JSON directly as well as JSONL files. | Later slice: keep adding new eval/test scenario IDs to the registry whenever new held-out families are introduced. |
| 5 | Reviewer rubric/prompts for structured verdicts by perspective | DONE as Phase-3 prep only. `scripts/training/make_reviewer_rubrics_iter6.py` emits prompt/schema rows for Codex code/logic, Claude reasoning/safety, DeepSeek alternative routes, Grok counterexamples, and a local schema/evidence guard. Every row has `execution_enabled=false`, `provider_binding=null`, and `runtime_execution=false`. | Later slice: wire real reviewer adapters only after capability is confirmed and real trajectories exist. |

## Current Contract

The shared trace contract is:

- `scripts/training/jury_review.py`
- `scripts/training/trace_record.py`
- `scripts/training/jury_pipeline.py`
- `scripts/training/make_lab_truth_heldout_registry_iter6.py`
- `scripts/training/make_reviewer_rubrics_iter6.py`

Generate the Codex registry / extracts with:

```bash
python3 scripts/training/make_lab_truth_heldout_registry_iter6.py
```

Use the registry during read-only runner trace export with:

```bash
python3 scripts/training/trace_record.py \
  --run-id <run-id> \
  --out run_trace.jsonl \
  --lab-truth auto \
  --lab-truth-registry ~/.aegispt-tools/training/aegispt_lab_truth_heldout_registry_iter6.json \
  --scenario-id <scenario-or-lab-target-id>
```

Generate the gated reviewer rubric prep family with:

```bash
python3 scripts/training/make_reviewer_rubrics_iter6.py
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
generated lab specs and standalone benchmark suite. Task #3 now consumes the
existing runner/report `coverage_truth` artifact for the read-only exporter
path; the remaining integration work is task #1's governed post-run artifact
persistence. Task #5 is also complete as prep-only rubric data; provider
adapter execution remains intentionally disabled until Phase 3.
