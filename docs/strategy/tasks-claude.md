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
- ◐ **0.2 — Gruyere admin-test** — engine RUNS, real vulns, **no admin yet** (run `4475197f`,
  post-#7). interactive-exploit **exit 0** (the engine now runs on black-box Gruyere) + real
  exploit-proven HIGH vulns (Reflected XSS *Confirmed*, Path Traversal). BUT the multi-step
  admin chain (register→login→admin-exploit) is NOT completed — the remaining frontier (or an
  8th regression — TBD). Earlier `d1b6d25d` had interactive-exploit 0× (pre-1.1); now it runs.
  Reset is MANUAL (reCAPTCHA, D6). Next diagnostic: did the engine attempt login (transcript)?
- ⛔ **0.2b — Gruyere local-model comparison** — premature; the gap 0.2 found is the scaffold's
  black-box dispatch, not the model. Do after 1.1 consumer dispatches the exploit on black-box.

## Phase 1 — the proof-loop (after Phase 0 green)

- ☑ **1.2 — "No Exploit, No Report" gate** — **DONE (Claude side)**: `finding_evidence_gate.py`
  (`classify_finding` / `is_reportable` / `partition_findings`) + 6 passing tests on the real
  XBEN-080 + Gruyere findings (Gruyere: only 2/6 are exploit-proven). The Q3 taxonomy contract.
  Commits `108aabb` + `7e61d61`. Additive, no schema change. Codex's ledger consumes it (its lane).
- ☐ **1.3 — hard runner-state**: sessions/cookies/auth/revealed-tokens/blockers/untested/OOB
  carried across the loop.
- ☐ **1.4 — coverage/coordinator**: no redundant re-cover; surface untested boundaries.
- ☐ **1.5 — pluggable brain verified**: same loop solves with ≥2 brains (provider-inherit fix
  is the foundation, commit 32fc457).
- ☑ **1.1 consumer — black-box exploit path FUNCTIONAL (dispatch + run both PROVEN):**
  (a) black-box bootstrap (`1a32a9e`) → interactive-exploit dispatches on black-box
  (`f1717a10`, ie_tasks 0→1); (b) **#7 fix** (`1b0f849`) → engagement_id now passed so the
  chatgpt_oauth adapter runs → interactive-exploit **exit 0** on black-box run `4a83edca` (was
  exit 2). The exploit engine now actually runs on black-box. Next: clean Gruyere admin-test
  (operator reset) now that the engine runs; + runtime-recon candidate-queue feed for targeting.

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
