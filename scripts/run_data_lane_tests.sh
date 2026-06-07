#!/usr/bin/env bash
set -euo pipefail

python3 -m pytest -q \
  scripts/tests/test_full_pentest_dataset.py \
  scripts/tests/test_open_corpus_iter3_dataset.py \
  scripts/tests/test_payload_capability_iter4_dataset.py \
  scripts/tests/test_payload_negative_dpo_domain_datasets.py \
  scripts/tests/test_data_lane_lab_llmsvs_dedup.py \
  scripts/tests/test_duplicate_triage_llmsvs_score.py \
  scripts/tests/test_training_exclusions_curated_mix.py \
  scripts/tests/test_llmsvs_requests_readiness.py \
  scripts/tests/test_claude_data_lane_handoff.py \
  scripts/tests/test_multiturn_agentic_chain_dataset.py \
  scripts/tests/test_multiturn_chaintype_diversity_dataset.py \
  scripts/tests/test_multiservice_chaintype_diversity_iter8.py \
  scripts/tests/test_iter7_training_artifact_pack.py \
  scripts/tests/test_iter8_training_artifact_pack.py \
  scripts/tests/test_iter9_combined_sft_mix.py \
  scripts/tests/test_v4pro_demonstrated_ingest_iter8.py \
  scripts/tests/test_v4pro_teacher_generator_iter9.py \
  scripts/tests/test_v4pro_teacher_topup_iter10.py \
  scripts/tests/test_teacher_demonstration_gen.py \
  scripts/tests/test_multichain_rl_envs_iter9.py \
  scripts/tests/test_headless_oob_chain_envs_iter10.py \
  scripts/tests/test_blind_oob_command_envs_iter10.py \
  scripts/tests/test_multichain_heldout_eval_envs_iter10.py \
  scripts/tests/test_xben_gap_matrix_iter10.py \
  scripts/tests/test_xben_triage_backlog_iter10.py \
  scripts/tests/test_jury_system.py \
  scripts/tests/test_jury_review.py \
  scripts/tests/test_trace_record.py \
  scripts/tests/test_lab_truth_heldout_registry.py \
  scripts/tests/test_reviewer_rubrics.py
