# Handoff → Codex data-lane: multi-turn chain-TYPE diversity (2026-06-06)

## Empirical finding that drives this (from the expert-iteration round 1)

The combined SFT model (curated + iter6 multi-turn) now **authenticates** on the
held-out deep-chain (`logged_in=true`, steps=4) — a real multi-step gain. But across
**16 temperature rollouts it NEVER discovered the IDOR pivot** (`any_idor=false`,
`any_flag=false`). It logs in, then goes straight to `/admin/config`→403 and stops.

**Why:** the iter6 multi-turn family is one chain TYPE — `web_auth_followthrough`
(login → proof). The model generalises the chain types it was SHOWN; it learned
auth-followthrough but has no notion of `notes → IDOR → steal token → reuse token`.
Pure self-sampling cannot discover a chain type the model never saw → cold-start.

## The data task (Codex lane)

The multi-turn agentic family needs **chain-TYPE diversity**, not more of the same:
- `idor_object_swap → token/secret leak → privileged reuse`
- `ssrf → internal-only endpoint (remote_addr-gated) → admin action`
- `low-priv login → privilege escalation → admin resource`
- `info-disclosure → credential reuse → lateral step`

Each as multi-turn chains (the iter6 schema: system + alternating user/assistant,
`next_action.args`, `done` only at goal). Generate them the way iter6 was generated —
ideally **teacher-demonstrated** (a frontier model solving diverse, NON-held-out
scenarios → emergent trajectories), NOT hand-scripted recipes
([[feedback_no_prescriptive_recipes]]). Keep them OUT of the held-out registry (the
deep-chain IDOR scenario is held-out — training on it would contaminate the eval).

## Contract / interface (already built, Claude side)

- Schema: `jury_review.TRACE_FIELDS` + the iter6 `{messages:[...]}` SFT format.
- The pipeline `trace → jury (evidence/coverage arbiter) → factory → sft/dpo/process-
  reward`, held-out-guarded, is ready (Phase 1, tested).
- `jury_rollout.py` (expert iteration) becomes useful ONCE the model has the chain-
  type repertoire — then temperature sampling finds better variants to reinforce.

## Claude side (in parallel)

- Add a cloud-teacher path so a frontier model can DEMONSTRATE chains (teacher, not
  just judge) — proving the teacher-demonstration concept + feeding SFT data.
- SFT on the richer family + jury process-reward/DPO refinement once it lands.

Sequence: richer chain-type data (teacher) → model learns the pivots → jury/RL
refines → the deep-chain (and the live XBEN auth class) gets solved.

## Codex data-lane status

Codex added `scripts/training/make_multiturn_chaintype_diversity_iter7.py` as
the additive family for this handoff. It covers the four requested non-held-out
chain types:

- `idor_object_swap_token_reuse_chain`
- `ssrf_internal_endpoint_admin_action_chain`
- `lowpriv_privilege_escalation_admin_resource_chain`
- `info_disclosure_credential_reuse_lateral_chain`

The generator emits the iter6 chat SFT shape with system + alternating
user/assistant turns, `next_action.args`, carried `last_observation_ref` state,
and `done=true` only on the final evidenced goal. The scenarios are synthetic
authorized labs, marked `global_held_out_registry=excluded`, and the regression
checks reject the held-out deep-chain markers/routes (`shop.lab`, `/notes/`,
`/admin/config`, `X-Admin-Token`, `ADM-7741-KQ`,
`flag{deep-eval-5b7c2}`).

This is a deterministic scaffold for the cold-start chain-type lever. Claude's
cloud-teacher path can later add model-demonstrated variants on top of this
family without contaminating the held-out deep-chain eval.

## Codex artifact-pack status

Codex later committed the generated iter7 scaffold as a compressed artifact pack
under `codex/results/training/iter7-chaintype-diversity-20260606/`:

- iter7 train/eval/test JSONL gzip files
- LLMSVS adversarial eval JSONL gzip
- expanded lab-truth/held-out registry JSON and gzip JSONL extracts
- artifact-pack manifest with sha256s and row-count stats

The held-out registry now includes iter7 eval/test split IDs. The iter7 train
split remains training data; the eval/test split is protected from factory
feedback loops.

Codex did not generate true V4-Pro-demonstrated rows in this shell because no
V4/OpenAI-compatible endpoint or API key is available. That remains the next
strongest lever once Claude's V4-Pro teacher path exports real non-held-out
trajectory rows.

## Codex iter8 multi-service follow-up

Codex added `scripts/training/make_multiservice_chaintype_diversity_iter8.py`
as the next scaffold layer for harder, longer chain-type diversity. It extends
iter7 from single-surface pivots into multi-service state handoffs:

- `ssrf_recovery_ticket_admin_session_chain`
- `graphql_idor_worker_queue_chain`
- `oauth_callback_misbind_api_lateral_chain`
- `nosql_role_confusion_admin_chain`

The default iter8 pack has 2400 train rows, 300 eval rows, and 300 test rows.
Every row has 6 assistant turns, observed state reuse, lab-only safety metadata,
and final `done=true` only after the marker is evidenced. The generator rejects
the deep-chain held-out route/marker strings, including `/notes/`,
`/admin/config`, `/reset_password`, `X-Admin-Token`, and
`flag{deep-eval-5b7c2}`.

Codex also committed `scripts/training/build_iter8_training_artifact_pack.py`
and the generated gzip artifact pack under
`codex/results/training/iter8-multiservice-diversity-20260607/`. The canonical
lab-truth/held-out registry now includes iter8 eval/test scenario IDs, so those
splits are protected from Claude's jury/factory feedback loop.
