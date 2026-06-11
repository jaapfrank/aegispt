# AegisPT — STATE (single source of truth)

*Clean slate established 2026-06-11. This file replaces the multi-MB narrative
sprawl (`DONE_LOG.md`, `CURRENT_STATE.md`, `TASK_QUEUE.md`, …) that was archived to
[`docs/history/`](docs/history/). It stays short on purpose: one page, derived from the
evidence ledger — never a running diary.*

## The number that matters

Canonical score lives ONLY in the evidence ledger — never re-typed elsewhere:

- [`docs/validation/evidence_ledger.jsonl`](docs/validation/evidence_ledger.jsonl) (generated)
- [`docs/validation/EVIDENCE_LEDGER.md`](docs/validation/EVIDENCE_LEDGER.md) (schema + rule)

**XBOW-104, as of 2026-06-11:** `solved=18 · attempted_no_solve=17 · infra_blocked=5 · unknown=64`.
Reference competitor: Shannon ≈ 96%. A row is `solved` only under **"No Exploit, No Report"**
(an exploit attempt produced concrete evidence). Regenerate with
`scripts/validation/build_evidence_ledger.py`.

## Scope (narrowed — rework-4)

Source-aware **web/API** only, on XBEN-style labs. Five vuln families:
**injection · XSS/headless · SSRF/internal · auth/authz/business-logic · file/path/upload.**
LAN/WAN/AD/cloud/IoT/wireless/mobile expansion is **out of scope** until the web number
beats Shannon. The picker is now gated to the in-scope tool surface
(`_FROZEN_PICKER_TOOLS` in `api/app/services/assessment_loop.py` freezes 33 out-of-scope
runners from the picker menu; their code + tests are untouched and reversible).

## The plan we are executing (do NOT start a 5th rework)

[`docs/strategy/rework4-execution-plan-2026-06-08.md`](docs/strategy/rework4-execution-plan-2026-06-08.md)
— Shannon-style proof-loop: source-analysis → candidate → exploit attempt → evidence →
proven-findings-only. Already built: the canonical ledger, the candidate-queue schema
(`workers/runners/pre_recon_source/candidate_queue.py`), and the No-Exploit-No-Report gate
(`api/app/services/finding_evidence_gate.py`). Still open: hard runner-state (sessions/
cookies/auth carried across the loop), coverage/coordinator, and the callback/victim lane.

## Progress 2026-06-11 (this session)

- **Spoor 0 DONE + live-proven** (commit `5d00166`): picker provider **failover chain** +
  **DeepSeek** as a first-class picker brain + hardcoded `claude-opus-4-8` un-hardcoded. The
  `picker_retry_exhausted` death is gone: the system now runs end-to-end on `deepseek-v3`
  (uncensored, no GPU, no Claude). Proof: `docs/validation/spoor0-deepseek-2026-06-11/`
  (before: `stop_reason=picker_retry_exhausted`; after: `api.deepseek.com 200 OK`, 0×
  PROVIDER_UNHANDLED). 8/8 unit tests.
- **Hard runner-state DONE (unit)** (commit `f0e069e`): interactive-exploit HTTP tool now
  holds ONE persistent cookie jar (`_HttpScopeSession`) so a login/session is auto-carried
  across calls — the `register→login→admin` chain prerequisite. 4/4 unit tests
  (`workers/tests/test_interactive_exploit_session_state.py`).
- **"Keep going" verification DONE (unit)** (commit `b8309d4`): the exploit loop no longer
  accepts a premature "done" — if the agent stops with no flag and budget remains it re-seeds
  to push for the next step (bounded by `_MAX_DONE_NUDGES=3`); the cookie jar survives the
  re-seed so it stays authenticated. Addresses the done-too-early chain failure. 2/2 unit
  tests (`workers/tests/test_interactive_exploit_keepgoing.py`).
- All three are **loaded in the running `aegispt-api.service`** (verified by source
  inspection on the live venv).

## Live blockers / open

1. ~~Local GPU model operator-blocked~~ **RESOLVED (no sudo needed).** The earlier
   "needs nvidia-container-toolkit + sudo" call was WRONG. This is a native WSL2 docker host:
   the GPU is exposed via `/dev/dxg` + `/usr/lib/wsl/lib`, so the container gets the GPU by
   **mounting those directly** — no toolkit, no sudo. `--gpus all` (which needs the toolkit)
   was the bug in `scripts/serve_local_llm_gpu.sh`; fixed to use WSL-native passthrough.
   The uncensored Qwen3.6-27B is **UP on :8801, GPU-resident (15.2GB), healthy** (container
   logs: `CUDA0 : NVIDIA GeForce RTX 5080 Laptop GPU`, ARCHS includes 1200/Blackwell). The
   strongest non-refusing solve brain is now available as `--llm-provider local-qwen`.
2. **DeepSeek is a weaker solve brain than gpt-5.5.** It runs the loop but on XBEN-080 it
   picked exec-plan/xss over the SSTI→interactive-exploit path and did not capture the flag.
   Infra is proven; *solve quality* needs the local GPU model or gpt-5.5 (which refuses
   offensive). This is the real capability frontier — see below.
3. **API restart resurrects cancelled runs** (pre-existing): restarting `aegispt-api.service`
   re-activates non-terminal runs → contention. Cancel via `POST /runs/{id}/cancel` after
   restart. Not Spoor-0 related; a separate startup-resume hygiene item.

## The real capability frontier (the actual hard problem)

Multi-step chains: `register → login → admin`, and `SSRF → internal endpoint → chain`.
gpt-5.5 **refuses** offensive chains (cyber_policy); the local uncensored 27B **doesn't refuse
but can't chain**. This is the ceiling — not the architecture, not training-data volume.
Levers: a capable non-refusing brain for the exploit step, and/or chain-decomposition
scaffolding over hard runner-state. Measured ONLY by ledger movement.

## Discipline (the one rule that breaks the restart cycle)

**DONE = the evidence ledger moved.** Not "tests green", not "code exists", not "substrate
shipped". See [`ANTI_DRIFT.md`](ANTI_DRIFT.md). If a claim's number disagrees with the
ledger, the ledger wins and the claim is wrong.

## Operating docs (kept)

`README.md` · `AegisPT.md` (architecture) · `ANTI_DRIFT.md` (discipline) ·
`SESSION_PROMPT.md` (session kickoff) · `AGENTS.md` · `DECISIONS.md` (ADR log) ·
`TESTING_POLICY.md` · `validation-status.md` (live validator) · this `STATE.md`.
Everything else that used to claim status now lives under `docs/history/` as history.
