# Continual-Harness Roadmap (H-roadmap)

Last updated: 2026-05-24
Status: **PLANNED — not active.** Activation gated by the M-roadmap reaching a measurable solve baseline (target ≥ 50% on the AI-attempted XBOW subset). See [beat-shannon-pro-roadmap-2026-05-23.md](beat-shannon-pro-roadmap-2026-05-23.md) for the current capability work.

## Why this exists separately from the M-roadmap

The M-roadmap (M1–M9) adds **capabilities**: another runner, another agent, another data source. Useful, but capability-only. Continual Harness adds **self-improvement**: the system observes its own failures, classifies them, and proposes harness changes that — after evidence — get promoted.

Reference: Princeton "Continual Harness — Online Adaptation for Self-Improving Foundation Agents" (arXiv 2605.09998, MIT GitHub `sethkarten/continual-harness`).

Core thesis: **the harness around the model is the bottleneck, not the model.** The M-roadmap can lift solve rate by giving better capabilities; the H-roadmap lifts solve rate by making the system rewrite its own harness when it stalls.

**Critical safety differentiator from the paper:** Pokémon Continual Harness allows live self-modification — worst-case the agent walks into a wall. AegisPT cannot allow that — a wrong harness mutation can touch scope, legal boundaries, or false-positive rates. So every H-item below is constrained:

- Trajectory & failure data: collect freely.
- Skill / prompt / tool-policy changes: **proposal only** during a run. Promotion via offline replay + benchmark evidence + operator gate.
- No new permissions ever granted by the AI to itself.

## Activation gate

H-roadmap work begins **after** the M-roadmap delivers:

- ≥ 50% solve rate on the AI-attempted XBOW subset (10+ challenges), with at least 5 of those wins on non-IDOR vuln classes (XSS, SQLi, SSRF, RCE).
- M2 verdict gate live and filtering at least one false-positive per smoke.
- M5 cross-run recall surfacing actionable hints in at least 30% of advances (measured via picker prompt log inspection).
- M7 two-phase separation (analysis specialist → exploit specialist) shipped or explicitly declined with measurement.

If the M-roadmap stalls (we cannot get past ~30% even after M2/M5/M7), H1+H2 may be promoted ahead of schedule — the data-collection layers are zero-risk and feed any future direction.

## H-items

### H1 — TrajectoryStore

Capture every AI-advance as a structured trajectory record (richer than current `loop_state.iterations`). One record per advance: context snapshot, picker decision, runner outcome, validator verdict, derived reward. Append-only, queryable cross-run.

- **Hypothesis**: most failure-classification + skill-discovery work below needs per-step granularity we currently don't persist. Today's `loop_state.iterations` is decision-level; we need observation→action→outcome triples.
- **Move**: new table `trajectory_steps` (run_id, advance_idx, context_hash, picker_decision_json, runner_outcome_json, verdict, reward, created_at). Hook write in `advance_assessment_loop` right before return.
- **Risk**: zero — data collection only, no behavior change.
- **Acceptance**: any smoke writes one row per advance; query "show me all picks against an XSS endpoint that returned reflected=true" works.

### H2 — FailureClassifier

When a CEA script exits without emitting a finding (or with non-zero exit), classify *why*. Distinct from current `recent_failures` which is a freeform stdout excerpt.

- **Hypothesis**: failures cluster into ~8 reasons (wrong endpoint, no auth, bad plan, timeout, hallucinated path, missing source, missing tool, dependency down). If we name them we can route the next pick differently.
- **Move**: rule-based first pass on stdout/stderr/exit code, LLM-assisted only when rules can't decide. Persisted into `trajectory_steps.failure_class`.
- **Risk**: low — classification is advisory, not gating.
- **Acceptance**: 90% of CEA failures in a smoke get a class other than `unknown`.

### H3 — Versioned SkillLibrary

Skills are reusable mini-strategies with input/output contracts (NOT runners — those are tools). Examples: `login_with_disclosed_credentials`, `discover_form_and_replay_post`, `test_idor_pair`, `extract_flag_from_response`, `source_to_sink_trace`, `verify_replay_marker`.

- **Hypothesis**: the picker currently chooses tools; humans chain them mentally. Naming the chains makes them reusable + critique-able + benchmark-able.
- **Move**: directory `api/app/services/skills/` with one Python file per skill. Each skill = pure function `(context: dict) -> StepResult`. Versioned via filename suffix `_v1.py` etc. Skills get registered via decorator and exposed to picker as a structured option alongside runners.
- **Risk**: medium — adds new dispatch path. Mitigation: skills run inside the existing exec-plan substrate, no new permissions.
- **Acceptance**: ≥ 3 skills shipped. Picker prompt includes skill catalog. Trajectory store records skill invocations with input/output contract.

### H4 — HarnessRefiner (proposal-only)

The AI may propose harness changes when it stalls. Proposals are versioned, not live. Operator (or future PromotionGate) reviews + promotes.

- **Hypothesis**: most "this prompt is wrong" / "this runner lacks parameter X" observations today disappear into log noise. Capturing them creates an improvement backlog.
- **Move**: new table `harness_proposals` (run_id, proposal_kind, target_artifact, current_value_excerpt, proposed_change, rationale, evidence_refs). Picker prompt gains an output field `harness_proposal` (optional). Proposals get a status field (pending, accepted, rejected, superseded).
- **Risk**: zero during proposal collection. Risk shifts to H6 PromotionGate when proposals start landing.
- **Acceptance**: ≥ 5 proposals collected over a 10-challenge smoke. Operator review surface (CLI is fine for v1) renders them.

### H5 — ProcessRewardJudge

Per-step reward derived from outcome categories. Not just "flag found / not found" — also `recon_yielded_endpoints+`, `hypothesis_with_evidence_root+`, `tool_without_basis-`, `exploit_verified++`, `false_positive_report--`, `timeout_no_new_info-`.

- **Hypothesis**: training-free reward signal can be used to (a) sort skills by historical effectiveness, (b) seed RL-fine-tuning later, (c) flag suspicious advances for operator review.
- **Move**: rule-based reward computed at trajectory-write time. Stored in `trajectory_steps.reward`. Aggregated per-skill and per-tool into `skill_effectiveness` view.
- **Risk**: low — reward is observational. Becomes gating only when wired into picker prompt (H3 + H5 combined: "skills with reward >X are preferred").
- **Acceptance**: per-skill reward histogram is queryable. Picker prompt surfaces top-3 high-reward skills for the current phase.

### H6 — PromotionGate

No harness mutation goes live without: (a) replay against ≥ 3 prior trajectories shows non-regression, (b) benchmark smoke on a held-out XBEN subset shows non-regression, (c) operator approval.

- **Hypothesis**: without this gate, "AI rewrites its own prompt" becomes the bug pattern that ruins every production run.
- **Move**: extend existing `capability_packs` lifecycle to accept `harness_change` artifacts. Reuse approval state machine. Existing `capability_pack_validation_results` becomes the evidence carrier.
- **Risk**: medium — touching governance code. Mitigation: pattern is well-tested for capability packs; harness changes are a new artifact_type, not a new lifecycle.
- **Acceptance**: ≥ 1 harness change proposed by H4, validated by replay, promoted via the gate, observed in a subsequent smoke.

### H7 — Dynamic sub-agent spawning (deferred)

Allow the orchestrator to spawn a sub-agent for a finding/target on the fly, within fixed allowed types, with output that must carry schema + evidence.

- **Hypothesis**: certain vuln classes (XSS-callback, blind SQLi, RCE-confirm) need specialist execution agents that don't fit the picker's catalog model.
- **Move**: defer until H1–H6 are live. Sub-agent spawning sits on top of the SkillLibrary + PromotionGate primitives. Premature without those.
- **Status**: pending. Don't start.

## Order

H1 → H2 → H3 → H4 → H5 → H6 → H7. Each gates the next. H1+H2 are zero-risk and could be promoted ahead of schedule if the M-roadmap stalls (data-collection that any future direction needs).

## Decision rules

1. **No H-item begins** until the M-roadmap activation gate above is met.
2. **Every H-item gets a measurement BEFORE we move on.** Same rule as the M-roadmap.
3. **No live harness self-modification** is allowed until H6 PromotionGate is shipped and tested.
4. **Operator stays in the loop** for any promotion of a harness change throughout H1–H7.
