# Rework 4 Research Reset: Shannon Comparison and AegisPT Plan

Date: 2026-06-08

## Executive conclusion

AegisPT should stop treating small-model training as the central lever until the
runner has a narrower, Shannon-like proof loop.

The current failure mode is not mainly "the model is too small". The failure
mode is architectural drift: many lanes generate useful artifacts, but no single
canonical execution loop forces:

source/runtime signal -> candidate queue -> stateful exploit attempt ->
evidence verdict -> report or blocked/no-finding label.

Shannon is currently ahead because it is narrower and more disciplined. It is a
white-box web/API pentester that uses source analysis to guide dynamic testing,
runs specialized vulnerability/exploit pipelines, keeps workspace state, and
only reports vulnerabilities that are proven by working exploitation evidence.
AegisPT has more ambition and more components, but less enforcement at the
critical point where a discovered target must become an attempted, evidenced
action.

The next move should be a reset, not a fifth broad rework:

1. Freeze new broad feature work and broad model-training claims.
2. Create one canonical score/evidence ledger.
3. Narrow the product target to source-aware web/API XBEN-style solving.
4. Build a source-to-exploit candidate queue with mandatory per-candidate
   state.
5. Use training only as a subordinate policy/ranking model after runner
   evidence exists.

## Sources reviewed

Primary system comparison:

- KeygraphHQ Shannon repository, snapshot inspected at commit
  `0a1a2eb1c11a05891bcae248bfacd92ee77af1a7` from 2026-06-05:
  https://github.com/KeygraphHQ/shannon
- Shannon coverage roadmap:
  https://github.com/KeygraphHQ/shannon/blob/main/docs/coverage-roadmap.md
- Shannon configuration/authentication docs:
  https://github.com/KeygraphHQ/shannon/blob/main/docs/configuration.md
- Keygraph open-source Shannon page:
  https://keygraph.io/open-source

Research and adjacent agent systems:

- PentestGPT:
  https://arxiv.org/abs/2308.06782
- EnIGMA:
  https://arxiv.org/abs/2409.16165
- HackSynth:
  https://arxiv.org/abs/2412.01778
- Towards Automated Penetration Testing:
  https://arxiv.org/abs/2410.17141
- ReAct:
  https://arxiv.org/abs/2210.03629
- Reflexion:
  https://arxiv.org/abs/2303.11366
- SWE-agent:
  https://arxiv.org/abs/2405.15793
- Tree of Thoughts:
  https://arxiv.org/abs/2305.10601
- CHECKMATE:
  https://arxiv.org/abs/2512.11143

## What the research says

The strongest consistent signal is that end-to-end pentesting is a long-horizon
agent problem, not a pure text-generation problem.

PentestGPT identified context loss and broken task decomposition as central
problems in LLM-assisted pentesting, and mitigated them by splitting the work
into interacting modules. EnIGMA showed that interactive tools and real
observations materially improve vulnerability-solving behavior, while also
warning about models hallucinating observations when the environment loop is
weak. HackSynth uses an iterative planner/summarizer/executor style loop over
command feedback rather than relying on one-shot reasoning. ReAct, Reflexion,
Tree of Thoughts, SWE-agent, and CHECKMATE all point in the same direction:
better action interfaces, state, observations, planning, reflection, and
verification often matter more than simply swapping model weights.

Implication for AegisPT:

- Training traces can improve policy behavior.
- Training cannot compensate for missing runner affordances.
- If the environment does not expose candidate state, blocked reasons, auth
  state, callback evidence, and untested boundaries, the model can only guess.
- If scores are not generated from a canonical evidence ledger, rework looks
  like progress while live capability remains flat.

## What Shannon does well

Shannon Lite is deliberately scoped:

- Source-available web applications and APIs.
- Current Lite coverage: Broken Authentication, Broken Authorization,
  Injection, XSS, and SSRF.
- Source-guided dynamic testing.
- Specialized vulnerability analysis and exploitation agents.
- Authenticated scan configuration with login flows, credentials, rules, focus
  areas, and rate/concurrency control.
- Ephemeral Docker worker/workspace and resumability.
- Reports include validated findings, while unproven hypotheses are discarded.
- The README explicitly warns that smaller/alternative/proxied non-Claude
  models may be incomplete or unstable.

This is the core difference:

Shannon is not trying to make one small model become a complete pentester first.
It builds a disciplined execution product around a strong general model, then
lets the product enforce evidence.

## AegisPT diagnosis

AegisPT already has valuable pieces:

- broad runner and service code under `workers/runners/` and `api/app/services/`
- source triage and XBEN gap-matrix tooling
- interactive exploit and trace/jury work
- recovery-arc envs and teacher data
- held-out registries and contamination guards
- UI/reporting work
- D1/E2 V4-Pro demonstrated data generation, now reflected in the combined SFT
  mix as `v4pro_demonstrated_iter9=118` and `selected_total=16917`

But the pieces are not yet arranged into one hard execution loop.

Current observed score truth is also inconsistent:

- `codex/results/training/xben-gap-matrix-20260607/` reports
  `challenge_count=104`, `solved_count=17`, `attempted_no_solve=18`,
  `infra_blocked_or_crashed=5`, and `unknown_untriaged=64`.
- `codex/results/training/xben-triage-backlog-20260607/` reports
  `item_count=87`, all in `covered_needs_rollout_eval`, with
  `source_triage_required_count=0`.
- Older strategy/backlog docs discuss larger solved deltas and headless solve
  progress that are not reflected in the current canonical gap artifact.
- `NEXT_TASK.md` still keeps T-CHAIN1 active and not live-proven.

This means the repo has at least two kinds of truth:

- generated validation artifacts
- narrative planning docs

The generated artifacts must win. Narrative docs should be demoted to history
unless regenerated from the artifact ledger.

## Root cause of rework

The system keeps changing direction because it lacks a single acceptance
function.

Examples:

- "More data" becomes a task even when the runner has not proven it can consume
  that behavior.
- "More model training" becomes a task even when the candidate action space is
  not constrained or evidence-linked.
- "More coverage" becomes a task without a canonical solved/blocked/no-oracle
  ledger.
- "No finding" cannot be trusted unless the runner records what was actually
  covered and what boundaries remained untested.
- UI and reporting can improve perceived product quality while solve-rate stays
  unchanged.

The hard metric is not rows trained, number of envs, number of lanes, or number
of reports. The hard metric is live evidence-backed solves over a held-out,
source-aware, reproducible benchmark.

## Strategic decision

For the next work cycle, AegisPT should become a Shannon-style source-aware
web/API proof engine before it tries to be a universal Web/LAN/WAN/IoT/AD/Cloud
pentesting platform.

This is not abandoning the larger mission. It is choosing the smallest surface
where the architecture can become true.

Non-goals during the reset:

- no new LAN/WAN/IoT/AD/Cloud scope
- no promotion based only on shallow eval, synthetic traces, or SFT loss
- no new "agent brain" rewrite
- no UI/reporting work counted as solve-rate progress
- no generated training data entering eval or held-out sets
- no runtime self-modification or bypass of existing safety/approval hooks

## Plan

### Phase 0: one score ledger

Duration: 1 day.

Build or designate one canonical scorecard generated only from validation
artifacts. It must include:

- scenario id
- source hash or scenario hash
- status: solved, attempted_no_solve, infra_blocked, unknown, known_clean,
  known_vulnerable, live_no_oracle
- evidence path
- runner transcript path
- no-finding coverage fields
- last model/runner version
- whether the scenario is held-out, train, RL-env, or demo-only

Acceptance:

- `CURRENT_STATE.md` links to exactly one live score artifact.
- narrative docs that disagree are marked historical.
- promotion readiness reads the ledger instead of hand-maintained summaries.

### Phase 1: narrow target

Duration: 1 day.

Declare the next capability target:

- source-aware web/API only
- XBEN-style local/lab targets only
- five vulnerability families only:
  - injection
  - XSS/headless/browser-mediated
  - SSRF/internal-resource
  - auth/authz/business logic
  - file/path/upload

Acceptance:

- all active runner/data tasks must map to one of these families
- broad platform tasks stay in backlog

### Phase 2: source-to-exploit candidate queue

Duration: 3-5 days.

Add a Shannon-like queue between source/recon and exploit:

- `candidate_id`
- route/method/parameter
- source file and line reference where safe to store
- sink/evidence class
- auth requirement
- required runtime observation
- candidate state:
  - untested
  - tested_no_signal
  - blocked_needs_auth
  - blocked_needs_callback
  - blocked_needs_state
  - exploited
  - false_positive
- evidence refs
- next allowed actions

Exploit execution should consume this queue instead of free-form choosing the
next thing to try.

Acceptance:

- every discovered endpoint/sink is either tested, blocked with reason, or
  explicitly out of scope
- no report can claim a finding without candidate evidence
- no "done" verdict is possible while high-priority candidates are untested
  unless an approved budget/scope cutoff is recorded

### Phase 3: stateful exploit sessions

Duration: 3-5 days.

The runner must persist:

- browser/session state
- cookies/tokens
- source-discovered local credentials and seeded test credentials
- visited routes
- attempted forms/API calls
- boundary coverage
- blockers
- callback evidence

Acceptance:

- T-CHAIN1 / XBEN-024 is either live-solved with evidence or marked not done
  with the exact blocker
- auth/session-forgery and credential-reuse attempts reuse actual runner state,
  not prompt memory

### Phase 4: callback/victim lane for headless and SSRF

Duration: 3-5 days.

Build the missing affordance for classes that require another actor or an
outbound observation:

- local callback server
- victim-trigger action
- callback capture
- replay/follow-up action when callback evidence yields a bounded token,
  route, or credential

Acceptance:

- at least 3 headless/XSS/SSRF XBEN scenarios move from
  `attempted_no_solve` or `unknown` to live `solved`
- no callback evidence means no positive finding

### Phase 5: train only the policy layer

Duration: after Phases 0-4 start producing traces.

Use the small model for bounded choices:

- rank next candidate
- choose among allowed runner actions
- predict blocker category
- summarize evidence
- abstain when coverage is insufficient

Do not use it as the full pentester brain yet.

Training outputs:

- successful traces -> SFT
- good/bad decisions -> DPO
- premature done -> contrastive examples
- per-step evidence labels -> process reward model

Acceptance:

- model promotion requires improvement on the canonical held-out ledger
- SFT rows alone do not count as progress

### Phase 6: workspace/checkpoint behavior

Duration: parallel with Phases 2-4.

Adopt the workspace behavior that makes Shannon practical:

- resumable runs
- per-candidate checkpoints
- stable transcript format
- final report generated only from evidence ledger

Acceptance:

- interrupted run can resume without losing tested/blocked/exploited candidate
  states

## Immediate next tasks

Recommended order:

1. Canonical score ledger and drift cleanup.
2. Source-to-exploit candidate queue.
3. Stateful runner session persistence wired to the queue.
4. Callback/victim lane for headless/SSRF.
5. Only then: retrain/evaluate the small model as a policy model.

The current V4-Pro teacher corpus can remain useful, but it should be treated as
teacher material for the policy layer, not as proof that the platform has gained
capability.

## Success criteria

Within the reset window, success means:

- one canonical score artifact replaces contradictory narrative claims
- at least one previously active blocker, especially T-CHAIN1/XBEN-024, is
  closed as live solved or honestly not done
- at least 5 new XBEN live solves come from the queue/session/callback
  architecture, not from synthetic-only training claims
- every no-finding result contains coverage, untested boundaries, and blockers
- model training resumes only after those traces exist

## Bottom line

Shannon is better right now because it has a tighter product loop:

source-aware plan -> dynamic test -> exploitation proof -> validated report.

AegisPT should not try to beat that with a broader model-first system. It should
first copy the discipline: narrow scope, candidate queues, stateful execution,
callback evidence, canonical score ledger, and proof-only reporting. After that,
our custom model can become valuable as an internal policy/ranking layer instead
of being asked to carry the whole pentest.
