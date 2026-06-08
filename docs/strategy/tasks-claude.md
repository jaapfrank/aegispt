# Claude — task list (rework-4)

Owner: **Claude** (orchestration/runner/loop code, live verification, benchmark runs).
Plan: `rework4-execution-plan-2026-06-08.md`. Coordinate via `coordination.md`.
Status: ☐ todo · ◐ in-progress · ☑ done · ⛔ blocked

## Phase 0 — restore baseline (isolate the variable: FRONTIER first)

- ☑ **0.1 — reproduce ONE XBEN live solve** — **DONE: XBEN-080-24 SOLVED** (run `a4900a50`,
  379s, `chatgpt_oauth` €0, flag captured by interactive-exploit). Surfaced + fixed
  **regression #6** (`PICKER_MODE=specialists`, commit `1c16620`) — the 6-fix chain now works
  end-to-end with a frontier brain. Proof: `docs/validation/xbow-xben080-2026-06-08/`.
  (Restoration proof; canonical count unchanged at 17.)
- ☐ **0.2 — Gruyere frontier re-run** — UNBLOCKED (0.1 done; no live run). Reset the instance
  (`/resetbutton/<id>/`) immediately BEFORE the run. Admin back = scaffold proven on the
  regression target.
- ☐ **0.2b — Gruyere local-model comparison** (same loop, local-qwen) — after 0.2.

## Phase 1 — the proof-loop (after Phase 0 green)

- ☐ **1.2 — "No Exploit, No Report" gate**: a finding is recorded only if an exploit attempt
  produced evidence. (depends on ledger 0.3 + candidate queue 1.1)
- ☐ **1.3 — hard runner-state**: sessions/cookies/auth/revealed-tokens/blockers/untested/OOB
  carried across the loop.
- ☐ **1.4 — coverage/coordinator**: no redundant re-cover; surface untested boundaries.
- ☐ **1.5 — pluggable brain verified**: same loop solves with ≥2 brains (provider-inherit fix
  is the foundation, commit 32fc457).
- ☐ **1.1 consumer** — wire the loop to dispatch FROM Codex's source-to-exploit candidates
  (not generic scanners). (depends on Codex 1.1)

## Phase 2 — measure

- ☐ **2.1 — run XBOW-104** with the strongest brain → solve-rate → Codex records in ledger.
- ☐ **2.2 — (optional) run Shannon** as a baseline to study its scaffolding.

## Phase 3 — differentiate (only after 2.1 shows a real number)

- ☐ **3.1 — local uncensored model** for refusal-prone exploits.
- ☐ **3.2 — our model as ranker/policy** over the candidate queue (shared with Codex).

## Done this session (context — the 5 scaffold fixes)

- ☑ DB split-brain (30614b8) · AEGISPT_INTERACTIVE_EXPLOIT (1140027) · source_dir in params
  (cf3e53b) · provider-agnostic pre-recon-source bootstrap (3639e43) · exploit runners
  inherit run provider (32fc457).
