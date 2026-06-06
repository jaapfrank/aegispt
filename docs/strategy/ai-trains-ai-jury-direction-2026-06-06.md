# AI-trains-AI (jury / RLAIF) direction — COMMITTED (2026-06-06)

Anchored decision-of-record (like `local-model-training-direction-2026-06-04.md`)
so this is a **contract, not a mood**. The design converged **independently** by the
operator, Codex, and Claude on the same day — which is the strongest signal it is
right. This doc separates the STABLE CORE (will not change) from the PHASING (how we
sequence it) and the LANES (who does what).

## STABLE CORE — will not change next week

1. **Evidence is the boss, never a single model.** Runner-evidence (flag byte-equal
   == `flag_injected`, finding-persistence invariant, scope/policy gate) is decisive
   wherever it exists. Models are advisors that can hallucinate or share blind spots.
2. **Pipeline: Trace → Review Committee → Evidence Arbiter → Training Factory.**
3. **The small specialist ACTS; the big models JUDGE.** A narrow specialist can beat
   a big generalist on the task, so frontier models are used as reviewers, not as the
   agent.
4. **"Found nothing" is COVERAGE evidence, never hard negative truth.** A live
   no-finding gets 5 labels (`true_negative` / `missed_finding` / `inconclusive` /
   `blocked` / `correct_restraint`) and a LIVE no-finding is NEVER labelled "safe" —
   only process/coverage training. This is the hardest + most differentiating case.
5. **A held-out eval set is NEVER touched by this loop.** Hard hash-guard against
   trajectory contamination (the same no-leakage discipline used for datasets).
6. **Diverse committee + calibration-weighting; human only on conflict / safety /
   novel attack class.** Reviewers are weighted by their historical agreement with
   evidence; persistently-wrong reviewers are down-weighted.

## Why this is durable (not opinion — convergence + field consensus)

Operator + Codex + Claude reached the same architecture independently, and it matches
the field: RLAIF / Constitutional AI (AI feedback), LLM-as-judge, process supervision
(score each step, not just the answer), LLM-juries (a panel beats one judge), and AI
debate / scalable oversight. The **pentest-trajectory application** and the **no-finding
coverage arbiter** are the parts that are genuinely under-served and are our edge.

## PHASING — capability before courtroom (the key sequencing discipline)

- **Phase 0 (NOW): can the model even act?** The iter6 multi-turn capability gate
  (deep-chain: does it reach `flag=True` in `4..12` steps?). If the model cannot do
  multi-step even WITH multi-turn data, the jury has nothing good to learn (garbage
  in) — fix capability first. **Do not build the full committee for a suspect that
  cannot yet walk.**
- **Phase 1 (cheapest first slice, NO reviewer models):** run the evidence + coverage
  arbiter on the trajectories we ALREADY generate (deep_chain, runner) → `sft_positive`
  (solved), `dpo_negative` (missed flag), `contrastive` (wrong-step), and the 5
  no-finding labels. This needs only a **trace-recorder**, no API cost.
- **Phase 2:** the local model as the FREE first-pass judge.
- **Phase 3:** the big-model committee (gpt-5.5 / deepseek / gemini / grok),
  **escalated only on ambiguous / disagreement cases** (cost-gated). Each reviews from
  its angle (Codex=code/logic, Claude=reasoning/safety, DeepSeek/Grok=alternative
  routes).
- **Phase 4:** calibration-weighting (track each reviewer vs evidence) + the Factory →
  datasets → back into training. Optionally a trained AegisPT judge — but anchored on
  **evidence-verified cases only** (never on committee opinions, to avoid inheriting
  their blind spots).

## LANES

- **Claude:** the decision-core (DONE), training integration (arbitrated traces →
  SFT / DPO / contrastive / process-reward), the eval-gate + the trajectory hash-guard.
- **Codex (data lane):** the trace-recorder in the runner (`run_trace.jsonl`, the
  frozen schema), the no-finding artifact emission + `lab_truth` tagging
  (known_clean / known_vulnerable / live_no_oracle), reviewer rubric/prompts.
- **Shared:** the held-out set + the calibration ledger.

## OPEN RISKS + mitigations

- **Shared blind spots** (the committee amplifies a common error) → diverse providers
  + evidence anchor + an untouched held-out set.
- **Circularity** (a judge trained on AI labels inherits bias) → train any judge ONLY
  on evidence-verified cases.
- **Cost** (N models per trajectory) → gate: local first, committee only on ambiguity.
- **Contamination** (the loop trains on its own eval) → hash-guard trajectories.
- **Premature scaling** → Phase 0 (capability) gates the rest.

## DONE so far

`scripts/training/jury_review.py` — the decision CORE:
- evidence-arbiter + committee aggregation (median/consensus, no single leader) +
  training factory (`c8044f2`);
- the coverage arbiter / 5 no-finding labels (`5c76e97`).
Proven on 10 cases incl. the HARD RULE (live + full coverage still `inconclusive`,
never "safe") and our real failure modes (done-too-early → `contrastive`; missed flag
→ `dpo_negative`; deliberate restraint → `safety_positive`).

## Anti-drift contract for this lane

Evidence stays the final judge; the held-out set stays untouched; no single model is
ever "the boss". A better METHOD slots in as a phase/flag — it does not restart the
direction. Any change to the STABLE CORE must cite evidence it beats this on OUR eval
(deep-chain + held-out), not a blog headline.
