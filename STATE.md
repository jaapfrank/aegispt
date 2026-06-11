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

## Live blocker RIGHT NOW (fix before any capability work)

The validator ([`validation-status.md`](validation-status.md)) shows **100% of recent runs
end in `picker_retry_exhausted`** because the **Anthropic credit balance is exhausted** →
Claude-dependent critical-path runners (`target-intel`, `ai-pentest-agent`, the legacy
picker hardcoded to `claude-opus-4-8` at `assessment_loop.py:~4258`) return HTTP 400. This is
the *same* failure as 2026-05-26. **Operational fix (Spoor 0):** provider failover in the
critical path (chatgpt_oauth → local-qwen → deepseek) + remove the hardcoded Claude picker +
move `PICKER_MODE`/provider into committed config. One empty credit balance must never again
take the whole system down.

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
