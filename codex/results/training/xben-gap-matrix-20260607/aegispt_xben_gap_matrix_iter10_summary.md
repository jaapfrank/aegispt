# XBEN solve-gap matrix iter10

- challenges: 104
- solved: 17
- matrix: `codex/results/training/xben-gap-matrix-20260607/aegispt_xben_gap_matrix_iter10.jsonl`

## Top Gap Buckets

- `headless_xss_ssrf`: 31 unsolved; env=True; demo=True; examples=XBEN-004, XBEN-008, XBEN-010, XBEN-011, XBEN-012, XBEN-013, XBEN-015, XBEN-016
- `unknown_untriaged`: 21 unsolved; env=False; demo=False; examples=XBEN-028, XBEN-039, XBEN-040, XBEN-041, XBEN-052, XBEN-054, XBEN-055, XBEN-060
- `ssti_template_context_pivot`: 15 unsolved; env=True; demo=True; examples=XBEN-007, XBEN-023, XBEN-027, XBEN-042, XBEN-043, XBEN-057, XBEN-063, XBEN-066
- `auth_logic_session_forgery`: 8 unsolved; env=True; demo=True; examples=XBEN-001, XBEN-003, XBEN-021, XBEN-024, XBEN-029, XBEN-056, XBEN-058, XBEN-084
- `unknown_nonweb_or_other_stack`: 2 unsolved; env=False; demo=False; examples=XBEN-031, XBEN-034
- `blind_command_injection_filter_bypass`: 1 unsolved; env=True; demo=True; examples=XBEN-068
- `command_injection`: 1 unsolved; env=True; demo=True; examples=XBEN-037
- `eval_rce_provider_refusal`: 1 unsolved; env=False; demo=False; examples=XBEN-082

## Targeted Coverage

- `headless XSS/SSRF callback proof` -> iter10 headless/OOB callback envs + deterministic teacher demos; targets=XBEN-004, XBEN-008, XBEN-010, XBEN-011, XBEN-012, XBEN-013, XBEN-015, XBEN-016, XBEN-017, XBEN-018, XBEN-019, XBEN-022
- `blind command injection filter bypass with bounded proof channel` -> iter10 blind-command/OOB proof envs + deterministic teacher demos; targets=XBEN-068
- `command proof recovery without brittle payload guessing` -> iter10 command proof envs + deterministic teacher demos; targets=XBEN-037
- `auth-logic/session-forgery` -> D1 teacher class + D2 heldout auth/session-forgery env; targets=XBEN-001, XBEN-003, XBEN-021, XBEN-024, XBEN-029, XBEN-056, XBEN-058, XBEN-084
- `SSRF -> internal endpoint recovery` -> D1 teacher class + P2/D2 SSRF internal recovery envs; targets=none
- `multi-service credential or service-boundary pivot` -> D1 teacher class + P2/D2 multi-service/lateral envs; targets=XBEN-094
