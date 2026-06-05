# AegisPT Data-Lane Iter-5 Claude Handoff

This handoff summarizes the Codex data-lane work so Claude can continue without rediscovering artifact state.

## Promotion State

- promotion_ready: `false`
- required_failures: `sft_eval_score_present, deep_chain_eval_gate, llmsvs_adversarial_gate`

## Safety Boundaries

- No runtime assessment behavior was changed by this data lane.
- No capability pack registry, approval flow, deployment flow, NEXT_TASK.md, or TASK_QUEUE.md was changed.
- Live-lab specs are data-only contracts; they do not materialize or bind runtime targets.
- Duplicate exclusions are non-destructive and only apply to derived mixes.
- Multi-turn chain rows are lab/simulator/read-only training data and do not bind live runner targets.
- Smoke LLMSVS scores prove the scorer path only; they are not model-promotion evidence.

## Training Order

1. Use the curated SFT mix for the next SFT run: aegispt_curated_sft_mix_iter5.jsonl.
2. Keep DPO data separate: aegispt_payload_dpo_iter4_* remains prompt/chosen/rejected data.
3. Keep the multi-turn chain family separate from the active iter5 SFT run unless a follow-up adapter/RL curriculum explicitly selects it.
4. Use LLMSVS adversarial data as an eval gate, not ordinary SFT data.
5. Generate real adapter predictions for aegispt_llmsvs_prediction_requests_iter5.jsonl.
6. Score predictions with score_llmsvs_adversarial_eval_iter5.py.
7. Run the SFT eval harness to produce eval_<label>.json.
8. Run deep_chain_eval.py to produce deep_<label>.json.
9. Rebuild adapter readiness with non-smoke LLMSVS scores and deep-chain scores before promotion.

## Claude Next Actions

- `train_sft_candidate` (ready): Use ~/.aegispt-tools/training/aegispt_curated_sft_mix_iter5.jsonl as the SFT training file.
- `run_sft_eval_harness` (blocked_until_candidate_adapter_exists): python3 scripts/training/eval_harness.py --per-family 50 --out ~/.aegispt-tools/training/eval_scores.json
- `generate_llmsvs_predictions` (blocked_until_candidate_adapter_exists): Run the candidate adapter against ~/.aegispt-tools/training/aegispt_llmsvs_prediction_requests_iter5.jsonl.
- `score_llmsvs_predictions` (ready_after_predictions): python3 scripts/training/score_llmsvs_adversarial_eval_iter5.py --predictions <model_predictions.jsonl> --fail-on-gate
- `run_deep_chain_eval` (blocked_until_candidate_adapter_is_served): AEGISPT_DEEP_OUT=~/.aegispt-tools/training/deep_<label>.json python3 scripts/training/deep_chain_eval.py
- `rebuild_promotion_readiness` (ready_after_scores): python3 scripts/training/make_adapter_promotion_readiness_iter5.py --sft-eval-scores <eval_label.json> --llmsvs-scores <non_smoke_scores.json> --deep-chain-scores <deep_label.json>
- `use_multiturn_chain_family_for_frontier` (ready_after_iter5_gate): Use ~/.aegispt-tools/training/aegispt_multiturn_agentic_chain_iter6_train.jsonl as the multi-turn follow-through curriculum/rollout seed after the supervised iter5 gate.

## Artifact Summary

- `full_coverage_sft`: present - `/home/administrator/.aegispt-tools/training/aegispt_full_coverage_dora_loraplus_unsloth_manifest.json`
- `open_corpus_iter3`: present - `/home/administrator/.aegispt-tools/training/aegispt_open_corpus_iter3_manifest.json`
- `payload_capability_iter4`: present - `/home/administrator/.aegispt-tools/training/aegispt_payload_capability_iter4_manifest.json`
- `payload_negative_iter4`: present - `/home/administrator/.aegispt-tools/training/aegispt_payload_negative_contrastive_iter4_manifest.json`
- `payload_dpo_iter4`: present - `/home/administrator/.aegispt-tools/training/aegispt_payload_dpo_iter4_manifest.json`
- `payload_domain_extension_iter4`: present - `/home/administrator/.aegispt-tools/training/aegispt_payload_domain_extension_iter4_manifest.json`
- `live_lab_specs_iter5`: present - `/home/administrator/.aegispt-tools/training/aegispt_live_lab_target_specs_iter5_manifest.json`
- `llmsvs_eval_iter5`: present - `/home/administrator/.aegispt-tools/training/aegispt_llmsvs_adversarial_eval_iter5_manifest.json`
- `near_duplicate_flags_iter5`: present - `/home/administrator/.aegispt-tools/training/aegispt_near_duplicate_flags_iter5_manifest.json`
- `duplicate_triage_iter5`: present - `/home/administrator/.aegispt-tools/training/aegispt_duplicate_triage_iter5_manifest.json`
- `training_exclusions_iter5`: present - `/home/administrator/.aegispt-tools/training/aegispt_training_exclusions_iter5_manifest.json`
- `curated_sft_mix_iter5`: present - `/home/administrator/.aegispt-tools/training/aegispt_curated_sft_mix_iter5_manifest.json`
- `multiturn_agentic_chain_iter6`: present - `/home/administrator/.aegispt-tools/training/aegispt_multiturn_agentic_chain_iter6_manifest.json`
- `llmsvs_request_pack_iter5`: present - `/home/administrator/.aegispt-tools/training/aegispt_llmsvs_prediction_requests_iter5_manifest.json`
- `adapter_readiness_iter5`: present - `/home/administrator/.aegispt-tools/training/aegispt_adapter_promotion_readiness_iter5.json`
