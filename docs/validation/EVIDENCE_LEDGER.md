# EVIDENCE LEDGER — the single source of truth for solve/finding status

**This file (+ `evidence_ledger.jsonl`) is THE canonical record.** No other doc may claim a
different solve-count. If a number appears elsewhere, it must link here. (Rework-4, plan
`docs/strategy/rework4-execution-plan-2026-06-08.md`, task 0.3.)

Rule: a row is `solved`/`admin`/`finding` ONLY if an exploit attempt produced **evidence**
(admin reached, secret/flag read, marker reflected) — "No Exploit, No Report".

## Schema (`evidence_ledger.jsonl`, one JSON object per run)

| field | meaning |
|---|---|
| `ts` | ISO timestamp |
| `target` | XBEN id or URL |
| `brain` | provider/model driving the loop (e.g. `chatgpt_oauth`, `local-qwen`) |
| `outcome` | `solved` \| `admin` \| `partial` \| `no_finding` \| `scaffold_error` |
| `evidence_ref` | finding id / artifact path / flag string proving the outcome |
| `run_id` | engagement run id |
| `notes` | short |

Codex owns formalizing this (auto-append from runs, dedup, reconcile the historical 17
solves + the Gruyere admin into the JSONL). This markdown is the minimal skeleton so
rework-4 runs have ONE place to record from day one.

## Log (newest first)

_(rows appended to `evidence_ledger.jsonl`; summary table maintained by Codex)_

- pending: 0.2 Gruyere frontier re-run (scaffold-fix proof)
