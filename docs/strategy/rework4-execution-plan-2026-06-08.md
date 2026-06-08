# Rework-4 execution plan — Shannon-style proof-loop restoration

**Date:** 2026-06-08
**Status:** proposed (Claude) → for Codex review
**Pairs with:** `docs/strategy/rework4-shannon-research-reset-2026-06-08.md` (Codex, commit e9fb861)

## 0. Framing — this is RESTORATION + SHARPENING, not a rebuild

Hard facts that anchor this plan:

- **The scaffold already works.** It has gotten **admin on Gruyere** and produced **17 XBOW
  solves / multiple admin+flag captures**. The capability is proven; we are not at zero.
- **This session it found nothing** = a **regression**, not an inability. The Gruyere run
  found only surface findings because the scaffold was broken by 5 infra bugs (DB
  split-brain, interactive-exploit→Claude default, source_dir not propagated, focused-exploit
  specialists-only, provider-branch gaps). 4–5 of these are now fixed this session.
- **Research is unambiguous** (Shannon 96% on hint-free source-aware XBOW; XBOW #1 on
  HackerRank): the winners use **heavy orchestration + a strict proof-loop + a strong
  frontier brain + rigorous validation**, and **none of them train a custom model**. The
  lever is the **scaffold + proof-loop**, not the model.

The mistake of the last ~2 months: 3 iterations trying to make a script-runner "smart" by
(a) training a local model and (b) flip-flopping the architecture, while the actual gap was
a **buggy, unvalidated orchestration loop**. We stop that now.

## 1. Guiding principles (from the research)

1. **Evidence is the gate. "No Exploit, No Report."** A finding is real ONLY if an exploit
   attempt produced concrete evidence (admin reached, secret read, marker reflected). Kill
   false positives ruthlessly.
2. **One canonical proof-loop:** source-analysis → candidate → exploit attempt → evidence →
   only-proven findings. Every component serves that loop.
3. **The brain is pluggable and model-agnostic.** Start with the strongest available brain
   (frontier OR our local uncensored model); the loop must not depend on a specific model.
4. **Our own model is a RANKER/policy later, not the full pentester brain.** Only after the
   loop is proven and benchmarked.
5. **Narrow scope first, prove it, then widen.** Source-aware web/API + XBEN labs only, until
   the canonical number moves.
6. **One source of truth for score/evidence.** No more docs claiming different solve-counts.

## 2. STOP doing (anti-drift)

- ❌ STOP treating local-model training as the primary lever. (Keep it as ONE parallel
  experiment that only counts if it moves the canonical ledger.)
- ❌ STOP changing the architecture. The architecture is decided: Shannon-style proof-loop.
- ❌ STOP creating parallel score/findings docs with conflicting numbers.
- ❌ STOP "minimal / no-orchestration autonomous loop" experiments — the research shows
  unconstrained agents = chaos (XBOW). Orchestration stays.

## 3. Plan — phased, with owners

Owners: **C = Claude** (orchestration/runner/loop code, live verification, benchmark runs)
· **X = Codex** (data-lane: ledger, candidate-queue data, teacher-data, registry/hygiene)
· **O = Operator** (scope, frontier budget, go/no-go decisions).

### Phase 0 — Stabilize + one source of truth (restore the baseline)

| # | Task | Owner | Done when |
|---|------|-------|-----------|
| 0.1 | Verify the 5 infra fixes live: drive the proof-loop end-to-end on ONE XBEN lab → recover a real solve | C | one XBEN solve reproduced + logged with evidence |
| 0.2 | Re-run **Gruyere** with fixes live → **admin restored** (the regression test) | C | admin/secret proven on Gruyere again |
| 0.3 | Build ONE canonical **evidence ledger** (single authoritative store of solve/finding/evidence; deprecate all conflicting docs) | X | every other score doc points to it; numbers reconcile |
| 0.4 | Freeze scope to **source-aware web/API + XBEN labs** (temporary) | O+X | scope written down; out-of-scope work paused |

### Phase 1 — The proof-loop (the core architecture)

| # | Task | Owner | Done when |
|---|------|-------|-----------|
| 1.1 | **Source-to-exploit candidate queue**: pre-recon-source emits ranked exploit *candidates* per vuln class (sink + entry + hypothesis), consumed by the loop | X builds the candidate schema/data; C wires the consumer | loop dispatches exploit attempts FROM candidates, not generic scanners |
| 1.2 | **"No Exploit, No Report" gate**: a finding is recorded only if an exploit attempt produced evidence; unproven hypotheses are discarded | C | false-positive rate drops; ledger only holds proven findings |
| 1.3 | **Hard runner-state**: carry sessions, cookies, auth/login, revealed tokens, blockers, untested boundaries, OOB/callbacks across the whole loop | C | the agent logs in + reuses revealed creds within one engagement |
| 1.4 | **Coverage/coordinator**: track what's been tested per target so agents don't re-cover the same surface | C | no redundant re-dispatch; untested boundaries surfaced |
| 1.5 | **Brain = pluggable**: the loop runs identically on frontier OR local-uncensored; provider chosen per run (the provider-inherit fix is the foundation) | C | same loop solves with ≥2 different brains |

### Phase 2 — Measure honestly (the hard number)

| # | Task | Owner | Done when |
|---|------|-------|-----------|
| 2.1 | Run the system on **XBOW-104** with the strongest brain → solve-count vs Shannon's 96% | C runs; X records in the ledger | a real % in the canonical ledger |
| 2.2 | Optionally run **Shannon** itself (open-source) as a baseline to study its exact scaffolding | C | side-by-side gap analysis |

### Phase 3 — Differentiate (ONLY after Phase 2 shows a real number)

| # | Task | Owner | Done when |
|---|------|-------|-----------|
| 3.1 | Local uncensored model for **refusal-prone** exploits (the niche frontier can't do) | C | ≥1 solve the frontier brain refused, our model got |
| 3.2 | Our model as **ranker/policy** over the candidate queue (not the full brain) | C+X | ranker improves candidate ordering vs baseline on the ledger |
| 3.3 | Teacher-data continues **only if** it moves the canonical/held-out ledger | X | gated on 3.2 / the ledger |

## 4. Definition of done / metrics

- **Single number:** XBOW-104 solve-rate in the canonical ledger, tracked over time vs 96%.
- **Regression closed:** Gruyere admin restored.
- **Quality:** ledger contains only exploit-proven findings (no header/clickjacking noise as
  "findings").
- **Honesty:** one ledger; teacher-data labeled as data, not capability, until it moves it.

## 5. Risks

- Frontier-model cost/policy-refusal → the local uncensored model is the mitigation (Phase 3.1).
- Scope creep → Phase 0.4 freeze; widen only after 2.1 moves.
- "Proof-loop" rigor regressing under linter/edits → the canonical ledger + 1.2 gate catch it.

## 6. Immediate next action (proposed)

Phase 0.2 — **re-run Gruyere with the fixes + our local model; admin back = fixes proven,
baseline restored.** One lab, one clear outcome. Then 0.1, then Phase 1.
