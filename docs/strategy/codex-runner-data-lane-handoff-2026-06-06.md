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
| 1 | Runner-side trace recorder for `assessment_loop` / stored `tool_executions` into `run_trace.jsonl` using `jury_review.TRACE_FIELDS` | DONE for exporter plus governed persistence. `from_runner_tasks(...)` and the read-only `--run-id` exporter convert persisted Task/ToolExecution records into the frozen trace schema; `api/app/services/run_trace_artifacts.py` can now persist `run-trace.jsonl` for terminal runs only when run config opts in. The artifact attaches to the latest existing `ToolExecution`, is duplicate-guarded by artifact kind, and the orchestration hook is best-effort/log-only. | Keep future live/lab run configs carrying canonical `scenario_id` / `target_id` / `lab_target_id` so `lab_truth=auto` can resolve precisely. |
| 2 | `lab_truth` tagging: `known_clean` / `known_vulnerable` / `live_no_oracle` | DONE for current generated lab specs and local benchmark suites, and wired into the exporter and opt-in artifact path. `scripts/training/make_lab_truth_heldout_registry_iter6.py` emits the registry; `trace_record.py --lab-truth auto --lab-truth-registry ...` and the artifact hook resolve known IDs and fall back to `live_no_oracle` on no match. | Keep adding canonical lab/spec IDs when new live targets are introduced. |
| 3 | No-finding artifact from runner state: coverage, untested boundaries, blockers | DONE for exporter and opt-in artifact path. `from_runner_tasks(...)` derives tool-level coverage and can merge existing `coverage_truth` surfaces, stop conditions, and blocker IDs. The artifact hook calls `build_coverage_truth(...)` and remains conservative if coverage extraction fails. | Add richer coverage extractors only as existing runner evidence schemas grow. |
| 4 | Held-out registry of scenario IDs for Claude's `load_held_out()` / pipeline guard | DONE for current eval/lab assets. The registry has exact IDs for `deep_chain_eval`, LLMSVS adversarial eval, iter6 multi-turn eval/test, iter7 chain-type eval/test, iter8 multi-service eval/test, and standalone lab-suite benchmark challenges. `jury_factory.load_held_out(...)` can now read the registry JSON directly as well as JSONL files. | Keep adding new eval/test scenario IDs to the registry whenever new held-out families are introduced. |
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

Generate the iter8 multi-service chain-type family or committed artifact pack
with:

```bash
python3 scripts/training/make_multiservice_chaintype_diversity_iter8.py
python3 scripts/training/build_iter8_training_artifact_pack.py
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

That command now includes `scripts/tests/test_jury_system.py`, including an
end-to-end guard that verifies `jury_pipeline.run(... --held-out registry.json)`
skips held-out scenarios before dataset emission.

## Important No-Finding Rule

No-finding is not clean truth by default.

- `known_clean` plus sufficient coverage may become positive SFT.
- `known_vulnerable` plus no finding is a missed finding and can become DPO /
  contrastive data.
- `live_no_oracle` plus no finding remains inconclusive / `do_not_reward`.

Codex tasks #2 and #3 are therefore high leverage: without lab truth and real
coverage evidence, the coverage arbiter must stay conservative.

Current status update: tasks #1-#4 are now done for the current data-lane scope:
read-only export, opt-in post-run trace artifact persistence, lab-truth lookup,
coverage/no-finding evidence, and held-out protection for iter6/iter7/iter8 are
wired. Task #5 is complete as prep-only rubric data; provider adapter execution
remains intentionally disabled until Phase 3.
