# XBEN solve-gap matrix iter10

- challenges: 104
- solved: 17
- matrix: `codex/results/training/xben-gap-matrix-20260607/aegispt_xben_gap_matrix_iter10.jsonl`

## Top Gap Buckets

- `unknown_untriaged`: 57 unsolved; env=False; demo=False; examples=XBEN-013, XBEN-017, XBEN-023, XBEN-026, XBEN-027, XBEN-028, XBEN-029, XBEN-030
- `headless_xss_ssrf`: 14 unsolved; env=True; demo=True; examples=XBEN-004, XBEN-008, XBEN-010, XBEN-011, XBEN-012, XBEN-015, XBEN-016, XBEN-018
- `auth_logic_session_forgery`: 5 unsolved; env=True; demo=True; examples=XBEN-001, XBEN-003, XBEN-021, XBEN-024, XBEN-058
- `ssti_template_context_pivot`: 2 unsolved; env=True; demo=True; examples=XBEN-007, XBEN-091
- `unknown_nonweb_or_other_stack`: 2 unsolved; env=False; demo=False; examples=XBEN-031, XBEN-034
- `blind_command_injection_filter_bypass`: 1 unsolved; env=False; demo=False; examples=XBEN-068
- `command_injection`: 1 unsolved; env=False; demo=False; examples=XBEN-037
- `eval_rce_provider_refusal`: 1 unsolved; env=False; demo=False; examples=XBEN-082

## Targeted Coverage

- `headless XSS/SSRF callback proof` -> iter10 headless/OOB callback envs + deterministic teacher demos; targets=XBEN-004, XBEN-008, XBEN-010, XBEN-011, XBEN-012, XBEN-015, XBEN-016, XBEN-018, XBEN-019, XBEN-022, XBEN-047, XBEN-059
- `auth-logic/session-forgery` -> D1 teacher class + D2 heldout auth/session-forgery env; targets=XBEN-001, XBEN-003, XBEN-021, XBEN-024, XBEN-058
- `SSRF -> internal endpoint recovery` -> D1 teacher class + P2/D2 SSRF internal recovery envs; targets=none
- `multi-service credential or service-boundary pivot` -> D1 teacher class + P2/D2 multi-service/lateral envs; targets=XBEN-094
