# Transfer matrix (aegispt_transfer_matrix_iter11)

- runs: 1
- scenarios: 24
- expected scenarios: 24
- results: 24
- complete runs: 1
- policy: eval/reporting only; no training rows generated

## Ledger ingestion

Summary check:

`python3 scripts/validation/build_evidence_ledger.py --transfer-matrix codex/results/training/transfer-matrix-20260611/aegispt_transfer_matrix_iter11.json --summary-json`

Materialize canonical ledger with this transfer matrix:

`python3 scripts/validation/build_evidence_ledger.py --transfer-matrix codex/results/training/transfer-matrix-20260611/aegispt_transfer_matrix_iter11.json --write`

## Run x Class

- `iter11_oracle` / `auth_logic_session_forgery`: solve_rate=1.0; recover_rate=1.0; revealed_rate=1.0; avg_reward=26.5; attempts=2
- `iter11_oracle` / `blind_command_result_recovery`: solve_rate=1.0; recover_rate=1.0; revealed_rate=1.0; avg_reward=26.5; attempts=2
- `iter11_oracle` / `graphql_worker_queue_pivot`: solve_rate=1.0; recover_rate=1.0; revealed_rate=1.0; avg_reward=26.5; attempts=2
- `iter11_oracle` / `headless_xss_callback_recovery`: solve_rate=1.0; recover_rate=1.0; revealed_rate=1.0; avg_reward=26.5; attempts=2
- `iter11_oracle` / `idor_object_swap_token_reuse`: solve_rate=1.0; recover_rate=1.0; revealed_rate=1.0; avg_reward=26.5; attempts=2
- `iter11_oracle` / `info_disclosure_credential_reuse_lateral`: solve_rate=1.0; recover_rate=1.0; revealed_rate=1.0; avg_reward=26.5; attempts=2
- `iter11_oracle` / `jwt_key_confusion_authz`: solve_rate=1.0; recover_rate=1.0; revealed_rate=1.0; avg_reward=26.5; attempts=2
- `iter11_oracle` / `nosql_filter_bypass_chain`: solve_rate=1.0; recover_rate=1.0; revealed_rate=1.0; avg_reward=26.5; attempts=2
- `iter11_oracle` / `ssrf_internal_endpoint_recovery`: solve_rate=1.0; recover_rate=1.0; revealed_rate=1.0; avg_reward=26.5; attempts=2
- `iter11_oracle` / `ssti_template_context_pivot`: solve_rate=1.0; recover_rate=1.0; revealed_rate=1.0; avg_reward=26.5; attempts=2
- `iter11_oracle` / `upload_metadata_pivot`: solve_rate=1.0; recover_rate=1.0; revealed_rate=1.0; avg_reward=26.5; attempts=2
- `iter11_oracle` / `xxe_document_parser_pivot`: solve_rate=1.0; recover_rate=1.0; revealed_rate=1.0; avg_reward=26.5; attempts=2
