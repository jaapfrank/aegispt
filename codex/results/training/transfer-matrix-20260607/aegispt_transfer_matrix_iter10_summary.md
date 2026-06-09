# Transfer matrix iter10

- runs: 1
- scenarios: 8
- expected scenarios: 8
- results: 8
- complete runs: 1
- policy: eval/reporting only; no training rows generated

## Ledger ingestion

Summary check:

`python3 scripts/validation/build_evidence_ledger.py --transfer-matrix codex/results/training/transfer-matrix-20260607/aegispt_transfer_matrix_iter10.json --summary-json`

Materialize canonical ledger with this transfer matrix:

`python3 scripts/validation/build_evidence_ledger.py --transfer-matrix codex/results/training/transfer-matrix-20260607/aegispt_transfer_matrix_iter10.json --write`

## Run x Class

- `d2_oracle` / `auth_logic_session_forgery`: solve_rate=1.0; recover_rate=1.0; revealed_rate=1.0; avg_reward=26; attempts=1
- `d2_oracle` / `graphql_worker_queue_pivot`: solve_rate=1.0; recover_rate=1.0; revealed_rate=1.0; avg_reward=26; attempts=1
- `d2_oracle` / `idor_object_swap_token_reuse`: solve_rate=1.0; recover_rate=1.0; revealed_rate=1.0; avg_reward=26; attempts=1
- `d2_oracle` / `info_disclosure_credential_reuse_lateral`: solve_rate=1.0; recover_rate=1.0; revealed_rate=1.0; avg_reward=26; attempts=1
- `d2_oracle` / `nosql_filter_bypass_chain`: solve_rate=1.0; recover_rate=1.0; revealed_rate=1.0; avg_reward=26; attempts=1
- `d2_oracle` / `ssrf_internal_endpoint_recovery`: solve_rate=1.0; recover_rate=1.0; revealed_rate=1.0; avg_reward=26; attempts=1
- `d2_oracle` / `ssti_template_context_pivot`: solve_rate=1.0; recover_rate=1.0; revealed_rate=1.0; avg_reward=26; attempts=1
- `d2_oracle` / `xxe_document_parser_pivot`: solve_rate=1.0; recover_rate=1.0; revealed_rate=1.0; avg_reward=26; attempts=1
