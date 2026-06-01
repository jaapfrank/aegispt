# AegisPT execution roadmap — A→Z (2026-06-01)

Authoritative, living roadmap. Purpose: (1) evaluate codex's strategy, (2) record
MY own plan grounded in today's empirical data, (3) prevent drift — every session
updates the Tracker (§6) so we always know what is done and what is left.

Read with: `ANTI_DRIFT.md` (DONE = user-value metric movement, never code-structural),
`CURRENT_STATE.md`, `docs/research/ai-pentest-competitive-deep-dive-2026-05-27.md`.

---

## 1. North star (operator-confirmed 2026-06-01)

The maximal vision IS the goal, not a thing to avoid:

> Better than everyone on every benchmark type · full replacement of human
> pentesters · black-box superintelligence.

Codex's "do not promise" list is **near-term go-to-market caution** (don't
oversell to customers yet), **not the ceiling**. Consequence for architecture:
every phase must be a **credible step toward the north star**, never a design that
caps us at "proof-first enterprise tool." Two non-negotiables this forces:

- **Black-box discovery is a first-class track**, not an afterthought. Today
  100% of our solves are **source-assisted (white-box)** — we hand-derive recon
  facts from source. "Black-box superintelligence" means the agent must
  eventually **discover** those facts through interaction. Source-assisted is a
  near-term score crutch; the roadmap must build the path off it.
- **No capability ceiling baked into the engine.** The execution layer must be
  able to express anything a human pentester can do (concurrency, timing,
  protocol breadth, identity chaining), so capability is bounded by the planner's
  reasoning, not by the runtime's vocabulary.

Near-term external claims stay honest; internal ambition stays maximal.

---

## 2. Evaluation of codex's analysis

### Adopt (codex is right)
- **Execution discipline + proof-first is the frontier**, not "a smarter prompt
  or another provider." Today's data confirms: recon improved, tooling improved
  (TCP), model upgrades gave limited lift — the residue is execution/proof.
- **Stop-doing list** (no new providers without a failure-class A/B, no niche
  runners in the core flow, no vanity benchmark runs, no "one more prompt will
  make it smart"). Matches our own scar tissue (skill-pack A/B did not move SOLVE).
- **Cross-layer enterprise wedge** (web + external + internal) and the
  proof-first / self-hosted product framing.

### Refine or reject (grounded in TODAY's data — where I differ)
1. **"The free-text loop can't do multi-step → build a typed runtime to fix
   multi-step."** Partly FALSE. Today the free-text tool-use loop solved **9/10
   stateful LAN chains of 5–7 steps** (auth→read, write→read, fetch-token→replay)
   with deepseek-chat. Multi-step is NOT the wall. The 1 failure (mqtt) was a
   **recon gap** (missing `action=dump` fact), fixed by adding a fact — not by an
   engine. And the hardest HTTP residual (billing-webhook 3-hop) failed **both**
   deepseek AND Claude → that is a **model-reasoning** limit a typed runtime does
   NOT remove (something still has to author the correct program).
   → The typed runtime's real, justified value is **(a) deterministic replay /
   proof and (b) patterns the free loop genuinely cannot express: concurrency,
   timing, parallelism, long waits**. Scope it as a **proof + hard-pattern layer**,
   introduced incrementally beside the working loop — **not a brain rewrite**.
2. **"Simplify the brain first" (big orchestration refactor).** RISKY and it
   violates the anti-drift contract (large code-structural work with no committed
   user-value metric). It would also destabilize a system that currently scores
   (9/10 LAN, 8/run HTTP). → Replace with **targeted reliability hardening of
   OBSERVED bugs** (finding-promotion gap, double-dispatch race, run-hang),
   measured by user-value (run-completion %, findings-persistence %). Refactor
   only the seams those bugs live in.
3. **Codex underweights the #1 credibility gap.** Every solve we cite is on our
   OWN lab (`aegispt_lab_suite`) AND source-assisted. The market lat
   (Shannon 96.15%, PentestGPT 86.5%) is the **public XBOW/XBEN** benchmark, where
   our official baseline is still ~0/25 with 1–2 ad-hoc XBEN solves. → A
   **reproducible public-benchmark number is Track A**, because without it every
   architecture claim is "belofte."
4. **Codex's enterprise-trust "ceiling" is too low for the north star.** Good as a
   funding/credibility milestone, wrong as the end-state. Black-box discovery
   (point 1 of §1) must be funded in parallel, not deferred forever.

**Net:** I adopt codex's diagnosis and stop-list, but **re-order by ROI-per-risk
and re-scope the typed runtime**: public truth + reliability + proof-capture
first; typed steps only where the free loop provably can't reach; black-box as a
standing north-star track.

---

## 3. The plan A→Z (priority order; tracks may overlap but only ONE is "active")

Each track has a **user-value acceptance metric** (never code-structural) and a
drift guard.

### Track A — Public-benchmark truth (the score meter)
- **Why:** all current evidence is self-lab + white-box; we cannot claim progress
  vs Shannon/XBOW/PentestGPT without a reproducible public number.
- **Work:** stand up a reproducible XBEN scorelane (fixed N challenges, current
  improved system, local-provider baseline, Gemini/Claude only as labelled
  accelerator); ledger per run (solved/attempted/exec_plan/verified/time-to-proof);
  `docs/validation/` baseline with flag byte-equality + commit SHA + replay.
- **Acceptance (user-value):** reproducible **≥2/5 XBEN** with replay artifacts;
  the official 0/25 baseline is replaced by a real number.
- **Drift guard:** NOT a vanity full-suite sweep — fixed small set, every run
  closes a named failure-class.

### Track B — Proof-first reliability (observed bugs only)
- **Why:** a solve that doesn't persist as a finding is invisible to operator +
  report — directly undermines the proof-first wedge. Observed today: **3/9 LAN
  solves were grader-verified but NOT promoted to findings**; double-dispatch
  race; run-hang risk.
- **Work:** fix finding-promotion so every grader-verified solve persists with
  transcript + verifier + scope provenance; kill the double-dispatch race;
  surface one auditable execution profile per run.
- **Acceptance (user-value):** **findings-persistence = 100%** of grader-verified
  solves on a run; **run-completion ≥95%** without manual rescue.
- **Drift guard:** fix only the seams the observed bugs live in; no speculative
  "simplify everything."

### Track C — Capture-replay verifier (typed program as OUTPUT, not input)
- **Why:** the market's hardest demand is replayable, verifier-backed exploit
  chains. We have grader-match but not a self-contained replay program. This is
  where "typed attack program" earns its keep WITHOUT rewriting the brain: the
  free loop DISCOVERS; the runtime RECORDS the winning chain as a deterministic
  typed program + verifier and can re-run it.
- **Work:** define an attack-program schema (steps: http_request, tcp_request,
  extract, set_var, assert, branch, wait); auto-capture each grader-verified solve
  into one; verifier hook per critical milestone; replay command.
- **Acceptance (user-value):** **every critical finding replays deterministically**
  from its recorded program on a clean target reset.
- **Drift guard:** capture/replay first; authoring attacks AS typed programs is
  Track D, gated separately.

### Track D — Hard-pattern execution (concurrency / timing / parallel)
- **Why:** the only patterns the free loop provably can't express (e.g.
  coupon-race needs concurrency; no current tool).
- **Work:** add typed steps for parallel/wait/race ON TOP of the Track-C schema;
  planner authors these only for the matching failure-class.
- **Acceptance (user-value):** solve a **concurrency/timing-class** challenge the
  free loop cannot (A/B vs free loop on that class).
- **Drift guard:** failure-class-gated; do not generalise to "all attacks are
  typed" until the A/B justifies it.

### Track E — Cross-layer breadth (the wedge; build on today's win)
- **Why:** our differentiation vs web-only Shannon/XBOW. Today: 9/10 internal LAN
  almost free.
- **Work:** extend internal (identity/credential vault + reuse, more protocols —
  SMB/LDAP/Kerberos/SSH pragmatically, lateral/path chaining) and external
  (target normalization, WAF/CDN/admin-plane flows, narrow retest).
- **Acceptance (user-value):** chained internal findings (credential reuse →
  lateral → secret) on a target beyond the current toy lab.
- **Drift guard:** every protocol added must produce a grader-verified solve, not
  just a banner.

### Track F — Black-box discovery (north-star track; long-horizon, standing)
- **Why:** "black-box superintelligence" requires discovering, not being handed,
  the recon facts. De-risks the white-box crutch.
- **Work:** for a subset we currently solve source-assisted, measure black-box
  (no source_dir); invest in discovery loops (interaction-derived grammar/gates)
  to close the gap.
- **Acceptance (user-value):** solve a named subset **black-box** that today only
  solves source-assisted; track the white-box→black-box delta as a standing KPI.
- **Drift guard:** measured as a delta, not a vibe; runs in parallel at low
  weight, never blocks A–E.

### Track G — Productize for trust (funding milestone, not ceiling)
- **Why:** real enterprise pilots; revenue to fund the north-star.
- **Work:** self-hosted/customer data plane, run isolation/secrets/cost controls,
  engineer + manager reports, retest/diff, pilot workflow.
- **Acceptance (user-value):** 3 design partners extracting real value;
  low false-positive rate on criticals; every critical has transcript + verifier +
  scope provenance.

---

## 4. Stop-doing (enforced)

- No new LLM providers unless a failure-class A/B justifies it.
- No niche runners bolted into the core flow.
- No vanity benchmark sweeps without a pre-named failure-class to close.
- No "one more prompt / one more model" as a substitute for execution work.
- No large refactor of `assessment_loop.py` / `tasks.py` without a committed
  user-value metric attached (anti-drift).

---

## 5. Product wedge (near-term honest, north-star aimed)

> Proof-first autonomous pentesting across web, external, and internal — with
> validated, replayable exploit chains and a self-hosted data plane.

…as the **credibility on-ramp** to the north-star (§1): the same engine, scaled in
reasoning + black-box discovery, is the path to "better than everyone, everywhere."

---

## 6. Progress tracker (update every session — drift firewall)

Status: ☐ not started · ◐ in progress · ☑ done (with user-value evidence)

| Track | Status | User-value acceptance | Evidence / artifact |
|---|---|---|---|
| A — public-benchmark truth | ☐ | reproducible ≥2/5 XBEN + replay | — |
| B — proof-first reliability | ☑ | findings-persistence 100%; double-dispatch 0 | DONE 2026-06-01: M2-gate `DETERMINISTIC_PROOF` exemption (bounded: flag-literal+provenance) + synchronous dedup memo + canary. Proven 2 runs: 5b8aa552 9/9 + 95847b80 7/7 = 100% persistence, 0 double-dispatch; old-run canary 66.7% (3 violations) confirms detection. Severity-label refinement descoped (verdict-agnostic for scoring). |
| C — capture-replay verifier | ☐ | every critical replays deterministically | — |
| D — hard-pattern execution | ☐ | solve a concurrency-class challenge free loop can't | coupon-race is the target case |
| E — cross-layer breadth | ◐ | chained internal findings beyond toy lab | LAN **10/10** in prod (run 7e589aea 9/10 + 74017f96 mqtt after recon fix) — foundation laid |
| F — black-box discovery | ☐ | solve named subset black-box that today needs source | white-box is current crutch |
| G — productize for trust | ☐ | 3 design partners; criticals fully evidenced | — |

### Done so far (foundation, pre-roadmap)
- Provider-agnostic interactive loop + adapter layer (Anthropic/Gemini/DeepSeek/Grok/ChatGPT-OAuth).
- Focused-assessment source-assisted recon (state-flow, value-flow, helper-chain, membership gates).
- Bounded `tcp_request` cross-layer tool; LAN 9/10 + HTTP 8/run grader-verified in production.
- Lab suite (50 challenges) + grader + run_lab_suite production driver.

### Active now → Track B (reliability), then Track A (public truth)
Rationale: a reliable score meter must exist before any track's numbers mean
anything; B makes solves persist + runs complete, A gives the public number. C–G
follow. F runs at low weight throughout.

**Open decision (RESOLVED by 3-way consensus below):** after B → A. (E deferred.)

---

## 7. Three-way consensus (codex + operator + Claude) — 2026-06-01

Codex's synthesis converged on this roadmap's structure (B→A→C→D→E→F→G, north-star
maximal, no big rewrite first, metric-gated refactor). Agreed. Four
evidence-based refinements from today's data sharpen it:

### R1 — "Replay" is overloaded; split Track C so A is not blocked on it
Codex puts "replay" in **A's** acceptance but the replay MACHINERY in **C** —
a contradiction. Resolution: two senses of replay.
- **C1 (capture, runs WITH A):** record each winning chain as a structured
  artifact + re-run the scorelane at RUN level (we already do this via
  run_lab_suite). Cheap; directly hardens A's "reproducible".
- **C2 (deterministic LLM-free replay, after A):** re-run the captured program
  with NO model in the loop, flag-byte-equal, on a clean target reset.
So the sequence is **B → (A + C1) → C2 → D → E → F(standing) → G**.

### R2 — Define the CANONICAL score source (Track B precondition)
Today 3/9 grader-verified LAN solves did NOT persist as findings. Our current
scorecards are read from **grader + execution stdout**, not the findings table —
i.e. two numbers that currently disagree by up to 33%. Track B must make them
identical and declare ONE canonical source. **Decision: canonical score =
grader-verified flag; a solve is only "counted" once it ALSO persists as a
finding with transcript + scope provenance.** B's job is to make those equal.

### R3 — Black-box is NOT safely deferrable; it may GATE A (empirical)
`assessment_loop.py:2136` gates the ENTIRE focused-assessment path on
`source_dir_for_run and source_gate_token_count > 0`. **100% of our recent gains
(state/value/helper-flow, LAN tcp objectives) are white-box-only**; a black-box
run skips them and falls back to the legacy generic path. Shannon is white-box;
the XBOW lat and the north-star are black-box. So Track A must report a
**black-box column AND a source-aware column from day 1** on the SAME subset, to
size the white-box→black-box cliff before we commit downstream order.
**New decision rule:** if A's black-box number is <50% of its source-aware
number, **promote F ahead of E** (the north-star needs the discovery loop more
than more breadth).

### R4 — Tightened acceptance metrics (the operator's ask)

| Track | Tightened acceptance |
|---|---|
| B | 100% of grader-verified solves persist as findings WITH transcript + scope provenance, enforced by an **automated in-run invariant + regression canary** (not manual); **0 double-dispatched tasks** (observed 3 today); run-completion ≥95% = terminal status without manual restart over ≥10 runs |
| A | reproducible across **≥2 independent runs** (not one lucky run); **flag byte-equality** (not substring); **local/cheap provider baseline** (Claude/Gemini only as labelled accelerator, else the score is a spend artifact); separate **black-box vs source-aware** columns |
| C1 | every grader-verified solve auto-captured as a replay artifact; scorelane re-runs reproduce the same solve set |
| C2 | replay reproduces flag-byte-equal on a clean reset with **no LLM in the loop** |
| D | **controlled A/B**: same challenge, free-loop (0 solves over N) vs typed (≥1) — proves runtime, not variance; coupon-race is the named case |
| E | chained finding (cred reuse → lateral → secret) on a target **beyond the toy lab** |
| F | named subset shifts white-box-only → black-box solve; **white-box−black-box delta is a standing KPI** |
| G | 3 design partners; criticals all have transcript + verifier + scope provenance; operators don't rescue runs |

### Decision rules (when we MAY pull a big refactor forward)
Only if a METRIC forces it: (1) B stays under acceptance after 2 targeted fixes;
(2) A doesn't move after 2 failure-class closures; (3) free-text loop fails
SYSTEMATICALLY on recon-complete chains; (4) replay capture proves impossible
without structural extraction; (5) black-box stays flat despite targeted
discovery investment. **Metrics first, refactor-right second.**

### What all three agree on
Maximal ambition · free-text loop is better than first thought · reliability +
score-truth take priority NOW · typed runtime comes later and smaller (capture
first, then concurrency) · no broad central-loop rewrite now · black-box is a
standing track, not an afterthought.
