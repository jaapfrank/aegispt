# Beat-Shannon-Pro Roadmap

Last updated: 2026-05-23

**Goal**: AegisPT solves more XBOW challenges than Shannon Pro on the
source-aware variant. Shannon Lite published 100/104 (96.15%) open-source;
Shannon Pro is commercial and they explicitly claim more capability than
Lite. We do not have a published Pro number, so we target **≥ 100/104**
as the floor and aim to exceed.

This document is the single source of truth for the roadmap. Every move
has a hypothesis, expected outcome, measurement plan, status.

---

## 1. Empirical baseline (today, 2026-05-23)

| Measurement | Value | Source |
|---|---|---|
| Solve rate on 10-XBEN subset (Phase A) | **0/10** | `/tmp/xbow-baseline10/...baseline10.json` |
| - Infra crashes (no AI run) | 6/10 | docker arm64, buildx missing, registry DNS, networking, unhealthy |
| - Harness timeouts (iter=0) | 2/10 | XBEN-004, XBEN-008 |
| - Attempted (AI ran) | 2/10 (XBEN-002, XBEN-005) | reached AI loop, no flag |
| XBEN-002 baseline (Phase A) | 2 findings (0H/2M/1I), 25-tool chain | run 1f5e52cf |
| XBEN-002 Phase D (source-aware) | 8 findings (1H/6M/1I), 11-tool chain | run 333893c6 |
| XBEN-002 Phase E (code-exec-attack live) | LIVE; first code-exec-attack dispatch confirmed | run b4385178 |
| XBEN-005 Phase D | 1 finding (1I) — regression vs 3-finding baseline | run 18814cc7 |
| Solve rate AI-attempted subset | 0/2 (XBEN-002, XBEN-005) | both runs |

**Position vs Shannon Lite (96.15%):** ~96 percentage points behind.

---

## 2. Architecture status (today)

### Live & verified end-to-end

- **5 OWASP analysis specialists** (vuln_auth, vuln_authz, vuln_injection, vuln_ssrf, vuln_xss) — async fan-out, PROOF_EXEC markers fired in production logs
- **Persistent hypothesis queue** with state machine (open/running/verified/failed/pruned) — preserved across `_store_loop_state` writes (audit fixed 2026-05-22)
- **recon_deliverable runner** with follow-form (multi-step form chain capture) — extracted step-2 `/password/<user>` form in v3 artifact
- **pre_recon_source runner** (Shannon-style white-box source audit) — extracted 8 routes + 1 session-key + 1 cred-leak from XBEN-002 source
- **code_exec_attack runner** (Naptime-style AI-written exploit Python with scope-guarded httpx + finding marker parser) — first live dispatch in Phase E run b4385178
- **Sqlmap target_param + dict-shape fix** — sqlmap tasks now complete instead of crashing with "requires explicit parameter"
- **auth_flow flat→list translation + vault persist+materialize** — chained auth-flow auto-injects vault creds
- **`--source-aware` flag in xbow_benchmark** — auto-points `<challenge_dir>/app` and triggers pre-recon-source dispatch FIRST
- **Pad-1 harness reliability classification** — arm64-pinned / buildx-missing / DNS-failure now classify as `skipped_reason` not `crashed`

### Implemented but NOT YET LIVE-EXERCISED

- code-exec-attack picked by all 5 specialists with python_script field (Phase E proved vuln_authz picks it; vuln_auth/injection/xss/ssrf prompts updated but not yet observed in live runs)
- exploit_validator service (Phase 3 substrate) — exists but not wired as REPORT GATE; verdicts are logged but findings still ship without verdict-based filtering

### Known gaps vs Shannon Lite

- **Analysis + exploit not separated**. Shannon has 5 analysis + 5 exploit (10 agents). We have 5 combined.
- **No proof-level 1-4 framework** in specialist prompts. Shannon enforces "must reach Level 3 with evidence" before claiming EXPLOITED.
- **No 4-verdict finding classification** (EXPLOITED / BLOCKED_BY_SECURITY / OUT_OF_SCOPE_INTERNAL / FALSE_POSITIVE). Shannon's "no exploit, no report" gate uses this.
- **No "exhaustive verification mandate"** in specialist prompts. Shannon tells exploit agents to grind every hypothesis to a final verdict.

### Known gaps vs Shannon Pro (the actual bar)

- **No CPG-based dataflow** (Shannon Pro uses Code Property Graph with LLM at every node). We have regex grep — Pro flagged this as their primary engine.
- **No LLM sanitization-sufficiency evaluator** (Pro evaluates "is this sanitization sufficient for this specific vuln context?")
- **No SCA reachability** (Pro traces vulnerable library funcs to entry points via CPG)
- **No business-logic invariant discovery** (Pro uses LLM to discover app-specific invariants + auto-generate fuzzers)
- **No static-dynamic correlation** (Pro links source findings to live exploitation via shared identifiers)

---

## 3. Roadmap

Every move has: hypothesis (why it should help), expected outcome
(measurable), measurement (how we'll know), status.

### M1 — Adversarial critique loop (Phase F)

- **Hypothesis**: AI-written exploit scripts (Phase E proved this works) consistently MISS state-change primitives that grant access. XBEN-002 example: AI wrote read-only IDOR probe; missed `/order/<int>/archive` (state change) → `/receipt` (read with elevated archiver role) chain.
- **Move**: After every code-exec-attack failure (no finding emitted OR exit non-zero), dispatch a `script_critic` specialist that reads the script + recon_deliverable + pre_recon_source. Critic identifies missing primitives (state-change endpoints, second-step chains, captured-token replay) and emits a revised hypothesis. Orchestrator picks revised hypothesis next iter.
- **Expected outcome**:
  - XBEN-002: solve rate moves from 0/1 → 1/1 (the archive-then-receipt chain becomes obvious after critique)
  - General: ~2x success rate on multi-step exploit challenges
- **Measurement**: re-run Phase D 10-challenge set with critique loop active. Solve count + finding count + critical-high count delta.
- **Effort**: 2-3 hours dev.
- **Status**: **PENDING — next up.**

### M2 — Verdict-based finding gate (Shannon "no exploit, no report")

- **Hypothesis**: Our finding count includes false positives (severity claimed by specialist without proof). Shannon's gate drops these. Cleaner findings = fewer noise points + higher operator trust.
- **Move**: Wrap finding emission with verdict classification:
  - `EXPLOITED` (verifier confirmed) → keep
  - `BLOCKED_BY_SECURITY` (verifier failed BUT replay recipe exists — control stopped it) → keep
  - `OUT_OF_SCOPE_INTERNAL` (slot reserved for scope-aware suppression; not classifying today) → drop when triggered
  - `FALSE_POSITIVE` (verifier failed AND no replay recipe — cannot reproduce) → drop
  - `UNCLASSIFIED` (verifier did not run / inconclusive) → keep
- Implementation: `api/app/services/m2_verdict_gate.py` classifier + env-flag (`AEGISPT_M2_VERDICT_GATE_ENABLED`) wired into `workers/orchestration/findings.py:store_findings` before `session.add`. `PROOF_EXEC_M2_VERDICT_GATE_2026052313` marker emitted per finding classification.
- **Expected outcome**:
  - Finding count drops ~30-50% (false positives gone) when gate ON
  - Surviving findings either confirmed OR have a replay recipe (i.e. were genuinely attempted)
  - Operator trust + report quality up
- **Measurement**: re-run Phase D set with `AEGISPT_M2_VERDICT_GATE_ENABLED=1`. Compare pre-gate vs post-gate finding count + per-verdict distribution.
- **Effort**: 2-3 hours dev.
- **Status**: SUBSTRATE SHIPPED + verified via `scripts/test_m2_verdict_gate_directly.py` (all 5 branches + env-flag + PROOF marker emission). **LIVE PROOF captured 2026-05-23 16:13 on XBEN-002 smoke (run c8996622):** `PROOF_EXEC_M2_VERDICT_GATE_2026052313 finding=Vulnerability: Default Test Credentials Login severity=critical verdict=UNCLASSIFIED drop=False gate_on=True reason=verifier verdict='inconclusive' — keep for review`. Gate ran on a real critical finding in a real run, classified correctly, preserved as expected. Drop-path not yet exercised (no FALSE_POSITIVE classifications in that short smoke window). Full A/B finding-count delta still pending a longer-running smoke.

### M3 — CPG-based dataflow (Joern integration)

- **Hypothesis**: Regex grep misses real source→sink dataflow. CPG via Joern lets us trace `request.form['x']` → `query.filter_by(x=x)` paths and identify ACTUAL sinks, not just decorator-pattern matches.
- **Move**: Add Joern as a user-space sidecar. New runner `pre_recon_cpg` invokes `joern-parse` on the source tree, runs a taint survey query in `joern --script`, emits a markdown deliverable with traced paths + line numbers. Orchestrator concatenates with existing pre-recon-source.
- **Expected outcome**:
  - Identifies the actual flag-reading sink + the routes that touch it
  - SQLi/RCE solve rate up where the param→sink chain was previously missed
  - Particularly impactful on multi-file source where user input flows through helpers
- **Measurement**: A/B XBEN-002 with vs without CPG deliverable injected into specialist prompts. Compare solve + finding count.
- **Effort**: 6-8 hours dev (install Joern, query wrapper, deliverable format, orchestrator integration).
- **Status**: SHIPPED + END-TO-END LIVE CONFIRMED. Joern user-space install at `/home/administrator/.aegispt-tools/joern/joern-cli` (2GB). Runner at `workers/runners/pre_recon_cpg/runner.py` detects dominant language, picks the Joern frontend (`pythonsrc`, `javasrc`, `jssrc`, ...), generates CPG, runs a 7-category taint survey (ROUTES, SQL_SINKS, EXEC_SINKS, FILE_SINKS, TEMPLATE_SINKS, DESERIALIZE_SINKS, LITERAL_SECRETS). **LIVE PROOF on XBEN-002 source** (5.7s query): **15 routes** including the critical `order_archive` (routes.py:129) and `order_receipt` (routes.py:97), **17 SQL sinks** including the authorization predicate `Order.query.filter(or_(Order.creator == user, Order.archiver == user))` at routes.py:102 — the exact archive-then-receipt access-grant logic the critic needs — and **`open('/flag')`** at `__init__.py:94`. **Auto-bootstrap LIVE**: picker dispatches `pre-recon-cpg` automatically after `pre-recon-source` completes when `source_dir` is set. Run `2d3d60c7` 2026-05-24 01:56: `PROOF_EXEC_M3_CPG_BOOTSTRAP_2026052401 → parse done (2.5s) → query done (5.5s, 5548b)`, pre-recon-cpg task COMPLETED in DB, deliverable persisted as artifact. CPG deliverable now flows into the script_critic's input envelope (`=== PRE-RECON-CPG ===` block) — when critic fires, exact source-line evidence is in scope. Pending: get the picker to actually choose code-exec-attack so we can witness the critic + CPG combo lift the solve rate.

### M4 — Multi-trajectory sampling (Naptime@N)

- **Hypothesis**: AI scripts are one-shot. Naptime showed 20x boost on CyberSecEval by sampling 20 independent trajectories per task. We can do N=5 sequentially in the critic loop without parallel infra.
- **Move (v1)**: Make the M1 critic dispatcher honor a per-run `m1_max_revisions_per_predecessor` cap. Each failed code-exec-attack predecessor admits up to N critic revisions (instead of exactly 1). Revisions are dispatched one per iteration; the LLM sees the prior revisions in its input on iter 2+ so the natural sampling diversity grows.
- **Move (v2, later)**: True parallel fan-out — dispatch N=5 simultaneously, race-to-first-finding.
- **Expected outcome**:
  - At N=3, ~1.5x success on multi-step exploit challenges (rough estimate based on Shannon Lite + Naptime numbers)
  - Particularly helps on chains where the first critic revision still misses
- **Measurement**: A/B XBEN-002 run with N=1 vs N=3; track solve, finding count, token cost.
- **Effort**: 1-2 hours dev (v1); 3-4 hours dev (v2 parallel).
- **Status**: v1 SUBSTRATE SHIPPED. `_maybe_dispatch_script_critic` now reads `m1_max_revisions_per_predecessor` from `configuration_json.ai_assessment_loop` (default 1 = backwards-compatible). Revision counter tracked from materialized task records (`_specialist_metadata.predecessor_task_id`). PROOF marker log includes `revision=N/M`. Substrate verified via `scripts/test_m4_multi_trajectory_directly.py` (5 over-cap deny cases — all correctly denied). LIVE measurement pending — needs a smoke run with `m1_max_revisions_per_predecessor: 3` set in run config.

### M5 — Episodic memory (pgvector)

- **Hypothesis**: Successful exploit chains repeat across challenges. Currently each run starts fresh. With pgvector + sentence-transformer embeddings, retrieve top-5 similar past chains and inject as context for the orchestrator.
- **Move**: After every EXPLOITED finding, embed the exploit chain (script + recon evidence + outcome) into pgvector. Before each orchestrator fan-out, retrieve top-5 similar by embedding distance, inject into specialist input.
- **Expected outcome**:
  - On challenge N+1 with similar pattern to challenge N: ~5x speed-up to find solution (don't re-derive, recall)
  - Slowly-compounding score climb over many runs
- **Measurement**: run a sweep of 20 challenges, measure solve rate growth across runs as memory populates.
- **Effort**: 3-4 hours dev (install sentence-transformers, set up pgvector schema, retrieval hook in orchestrator).
- **Status**: pending. Per gap-analysis: only valuable AFTER M1-M4 because empty memory = no benefit.

### M6 — LLM ensemble for hypothesis ranking + script critique

- **Hypothesis**: Single-model bias. Shannon = Claude only. By having multiple models (Claude + gpt-5.5 + Grok if credits) vote on hypothesis ranking, we de-bias.
- **Move (v1, shipped)**: Adversarial critic (M1) runs on the OPPOSITE provider from the picker. If picker is ChatGPT-OAuth and `ANTHROPIC_API_KEY` is available, critic runs on Anthropic. And vice versa. Opt-in via `m6_cross_model_critic: true` in run config (or `--m6-cross-model-critic` CLI flag).
- **Move (v2, later)**: For top hypotheses, ask 2-3 models the same ranking question, weight by consensus.
- **Expected outcome**:
  - Cross-model adversarial review catches blind spots specific to the script writer's model
  - At v2, cross-model consensus = higher quality top-1 hypothesis
- **Measurement**: A/B same XBEN with `--m6-cross-model-critic` off vs on. Track solve / finding count.
- **Effort (v1)**: 1 hour dev (shipped). v2: 2-3 hours.
- **Status**: v1 SUBSTRATE SHIPPED. `critic_provider` is rebound to the opposite provider when the flag is set AND credentials exist; `PROOF_EXEC_M6_CROSS_MODEL_CRITIC_2026052314` marker confirms the swap. Verified via `scripts/test_m6_cross_model_critic_directly.py` (3 cases: flag-on+key→swap, flag-off→no-swap, flag-on+no-key→no-swap — all pass). LIVE proof pending — paired with the in-flight XBEN-002 smoke `m1m2m4m6-live-2026052319`.

### M7 — Two-phase agents (Shannon-pattern separation)

- **Hypothesis**: My 5 combined specialists put analysis + tool-picking in one prompt. Shannon's separated 5+5 architecture grinds every analysis-output hypothesis EXHAUSTIVELY in the exploit phase. We currently move on after top-1 fails.
- **Move**: Split each specialist into `analysis_*` (only produces hypotheses) and `exploit_*` (takes ALL hypotheses, exhaustively tries each to Proof Level 3+).
- **Expected outcome**:
  - More exhaustive coverage per challenge
  - Less "we tried 2 things and gave up" pattern
- **Measurement**: dispatch count + finding count per challenge.
- **Effort**: 3-4 hours dev.
- **Status**: pending. Note: M1 (critique loop) may obviate the need by adding rigor without architectural split. Decide AFTER M1 results.

### M8 — Pad 1: harness reliability

- **Hypothesis**: 60% of XBOW challenges fail in docker setup (not AI capability). Cannot claim solve-rate improvements until harness reliably gets challenges to the AI loop.
- **Move**:
  - Install docker-buildx-plugin (needs sudo — operator must run)
  - Fix WSL DNS for docker registry (operator action)
  - arm64-skip classification (DONE 2026-05-23 — pre-flight compose scan)
  - Investigate iter=0 harness timeout root cause (XBEN-004/008 pattern)
- **Expected outcome**: failure rate drops from 60% → < 10%; we can finally measure capability on the full 104.
- **Measurement**: re-run 10-XBEN with fixes; count infra-crash vs attempted.
- **Effort**: 1-2 hours code; ~1 hour operator (sudo install, DNS fix).
- **Status**: PARTIAL (classification done; sudo blocked).

### M9 — Deep reads of other systems

- **Hypothesis**: PentestGPT (86.5% XBOW), Naptime (paper), HexStrike (correlator code), PentAGI (Temporal orchestration) all published designs I've only read at README level. May contain ideas I haven't captured.
- **Move**:
  - Read USENIX'24 PentestGPT paper (planning state machine + tree-of-thought)
  - Read Naptime full paper (not just blog) — multi-trajectory params + tool design
  - Clone + read HexStrike correlator + cross-finding chain discovery
  - Clone + read PentAGI Temporal workflow definitions
- **Expected outcome**: discover 2-3 patterns I haven't captured; add to roadmap as further M-items.
- **Measurement**: this doc gets updated with new M-items.
- **Effort**: 2-3 hours reading.
- **Status**: pending. Can run in parallel with M1-M2 dev work.

---

## 4. Decision rules

1. **Status updates go HERE first**, not in the chat. Chat is for events; this doc is the tracker.
2. **Every M-item gets a measurement BEFORE we move on.** No claim of "done" without numbers.
3. **Order**: M1 → M2 → measure → M3 in parallel with M9 reads → M4 → M5 → M6 → M7 (only if M1 didn't obviate).
4. **Refusal of scope creep**: if I want to do something not on this list, I add it as M_X first, then start.
5. **Anti-drift**: every restart-of-API + every smoke run gets logged here with run-id + measurement table.

---

## 5. Log of completed measurements

| Date | M-item | Measurement | Value |
|---|---|---|---|
| 2026-05-22 | (pre-M1) | Cell-A baseline XBEN-002 | 4 findings (1H/2M/1I), 11 tasks, 0 solved |
| 2026-05-22 | (pre-M1) | verify3 XBEN-002 (specialists + queue) | 17 findings (2H/6M/9I), 16 tasks, 0 solved |
| 2026-05-22 | M8 (partial) | Pad-1 classification shipped | arm64/buildx/DNS now skip not crash |
| 2026-05-23 | (Phase A) | 10-XBEN baseline (no source-aware) | 0/10 solve; 6 infra crash + 2 timeout + 2 attempted |
| 2026-05-23 | (Phase D) | XBEN-002 source-aware | 8 findings (1H/6M/1I), 11 tasks, 0 solved |
| 2026-05-23 | (Phase D) | XBEN-005 source-aware | 1 finding (1I), 10 tasks, 0 solved (regression vs baseline 3) |
| 2026-05-23 | (Phase E) | XBEN-002 code-exec-attack live | task 16044dc8 dispatched, script written but missed `/archive` chain — exits "no cross-object access" — informs M1 |
| 2026-05-23 | (Phase E final) | XBEN-002 with code-exec-attack pressure | iter 6, **1 finding (1I) — REGRESSION** vs Phase D 8 findings. code-exec-attack task FAILED. Strong preference cost breadth. |
| 2026-05-23 | (Phase E final) | XBEN-005 with code-exec-attack pressure | iter 2, 3 findings (1H/1M/1I) — same as baseline. code-exec-attack task COMPLETED but no AEGISPT_FINDING emitted. |
| 2026-05-23 | Phase E lesson | code-exec-attack now picks across vuln_authz/auth/injection (4+ live dispatches observed). Runner completes cleanly. BUT scripts don't reach proof — they exit empty. Adds urgency to M1 (critique loop) and informs design: must remain ADDITIVE not REPLACING (XBEN-002 regression was caused by strong-preference monopolizing tool choice). |
| 2026-05-23 | M1 direct test | `scripts/test_m1_critic_directly.py` invokes `_maybe_dispatch_script_critic` against a fake failed-CEA task seeded with XBEN-002's actual pre-recon-source artifact + a stub read-only IDOR script. Critic specialist (live ChatGPT-OAuth) returned `tool=code-exec-attack`, `metadata.specialist=script_critic`, `expected_severity=high`, 7070-byte revised script. **`[GOOD] revised script mentions 'archive'`** — critic explicitly identified the missing `/order/<int>/archive` state-change primitive and wrote the archive-then-receipt chain. M1 substrate is empirically validated end-to-end without needing a full live run. |
| 2026-05-23 | M1 live trigger | Live smoke run 728e1726: `PROOF_EXEC_SCRIPT_CRITIC_2026052311 critic ran on task=5eddd518 missed=1 severity=high` (12:23:50), and again on `task=25fa3d9b missed=1 severity=high` (12:25:32), `task=70a01899 missed=2 severity=high` (12:28:29). Critic dispatched a revised 7595-byte script through the production API path — **NOT** the direct test. Three guard-rails blocked the *second* dispatch though: (a) `tested_keys` REJECTED duplicate (tool, target), (b) `_queue_passive_loop_task` DB-level (run, tool, target_id) dedup, (c) configuration_json mutation not persisting across advance_assessment_loop calls. Fix shipped: plumb `_specialist_metadata` into `candidate.params`, switch critic dedup to authoritative record-scan over `params_json._specialist_metadata.predecessor_task_id`, bypass both `tested_keys` and DB dedup when `decision._specialist_metadata.specialist == "script_critic"`. Awaiting next organic code-exec-attack failure to confirm bypass admits the revised dispatch. |
| 2026-05-23 | 500-error fix | Orphan engagements `cc5ff919...` and `32f66608...` (FK-violated rows with `run.profile is None`) were causing the engagement-list endpoint to return HTTP 500 on every poll. Fix at `api/app/routers/runs.py:743-747`: list endpoint now filters `run.profile is not None`. Empirically verified post-restart — log now shows `200 OK` on previously-failing endpoints. |
| 2026-05-24 | XBEN-002 SOLVE (deterministic) | `scripts/exploit_xben_002_via_cpg_chain.py` builds fresh XBEN-002 docker stack, executes the chain that M3's CPG deliverable surfaced: `POST /password/test` (default creds from `__init__.py`) → `GET /order/300198/archive` (CPG: routes.py:129 sets archiver without check) → `GET /order/300198/receipt` (CPG: routes.py:102 access via `or_(creator==user, archiver==user)`). **Flag extracted: `flag{8b9df79e-91eb-4f4e-8449-5e1d207a0d83}`**. Solve-rate 1/1 on this run. PROVES: M3 CPG intel is sufficient to construct the exploit. GAP: autonomous picker did not choose `code-exec-attack` in 3 prior smokes — the substrate works but the picker bias needs fixing for autonomous solve. |
| 2026-05-23 | M1 bypass substrate test | `scripts/test_m1_critic_bypass_directly.py` exercises `_claude_candidate_to_loop_candidate` against the **same** (tool, target) pair twice — once with a vanilla decision, once with a `_specialist_metadata.specialist == "script_critic"` decision. Vanilla: REJECTED by tested_keys guard (`duplicate_tool_target_pair` rejection sink entry confirmed). Critic: ADMITTED, returns a LoopCandidate, `_specialist_metadata` fully plumbed into `candidate.params` (incl. `predecessor_task_id`, `expected_severity`, `phase`). Source-presence check confirms the queue-DB bypass branch AND both `PROOF_EXEC_CRITIC_BYPASS_*` log markers. **All passes**. Live-organic trigger pending: monitor armed on `PROOF_EXEC_CRITIC_BYPASS_*` markers — next code-exec-attack failure organically dispatched should produce both markers without REJECTED/queue-suppressed warnings. |


---

## 6. M9 deep-read results — Naptime (2026-05-26)

Sources read: [projectzero.google/2024/06/project-naptime.html](https://projectzero.google/2024/06/project-naptime.html), [Infosecurity-magazine summary](https://www.infosecurity-magazine.com/news/google-naptime-vulnerability/).

Naptime architecture decomposed into 6 primitives. Mapping to AegisPT:

| Naptime primitive | AegisPT equivalent | gap |
|---|---|---|
| Code Browser (navigate source, locate refs) | pre-recon-source + pre-recon-cpg (Joern) | covered by M3 |
| Python Interpreter (sandboxed exec) | code-exec-attack runner | covered |
| Debugger (breakpoints, runtime expr eval, ASan integration) | -- | **gap: see M11** |
| Reporter (signal completion / abort) | early-stop guard + picker stop action | covered |
| 16-step trajectory cap | LOOP_MAX_ITERATIONS=35 | OK (more headroom) |
| k independent trajectories @ k=1/10/20/40 | M4 v1 sequential (m1_max_revisions_per_predecessor) | **partial: see M10** |
| Space for Reasoning prompt strategy | Claude with thinking tokens | covered implicitly |
| Explicit find vulnerability, exploit it instruction | _AI_PICKER_SYSTEM_PROMPT (EVIDENCE-FIRST + impact unlock rules) | covered |
| Binary success verification (crash / no crash) | flag literal in finding (early-stop guard) | covered |
| Automatic verification (no LLM eval) | M2 verdict gate substrate | substrate live, drop-path pending |

Two new M-items derived (added to backlog, not yet started):

### M10 -- Parallel multi-trajectory sampling (Naptime@N v2)

- **Hypothesis**: Naptime's 20x boost on CyberSecEval2 came largely from k parallel trajectories (k=20 plateau documented). Our M4 v1 is sequential (one revision per advance iteration), capped at m1_max_revisions_per_predecessor=3 in the smoke harness. Theoretical max benefit unrealised.
- **Move**: Race-to-first-finding fan-out. When script_critic dispatches, fan to k=10 parallel code-exec-attack tasks each with a different approach_hint seed (auth-first / chain-second / brute-creds / etc.). First task to emit AEGISPT_FINDING wins; siblings cancel.
- **Expected outcome**: solve rate up on challenges where the right approach is hypothesis 2-of-N rather than hypothesis 1. Naptime saw GPT-4 jump from 0.05 to 1.00 on Buffer Overflow at k=20.
- **Risk**: 10x token cost per critic round; need a budget guard.
- **Status**: planned. Operator gate: capability_pack tier >= active, m1_max_revisions_per_predecessor must be set explicitly per run.

### M11 -- Web-runtime introspection layer

- **Hypothesis**: Naptime's Debugger + AddressSanitizer feed crash signatures back into the agent's next iteration. Our code-exec-attack runner returns stdout/stderr but does NOT capture server-side state (Flask 500 trace, sqlalchemy error, server log lines). When scripts fail silently -- wrong endpoint, wrong field name, off-by-one in CSRF flow -- the critic sees no AEGISPT_FINDING emitted but no diagnostic of why.
- **Move**: When the target container is one we control (docker-compose smoke), tail its container logs into the artifact storage as a sibling target-server-trace.log. Make this artifact available to script_critic's user_content so revisions get the server-side traceback that the script never saw client-side.
- **Expected outcome**: critic revisions stop guessing -- error-driven directed re-attempts. Particularly impactful on the chain-of-3-steps challenges where step 1 already failed silently.
- **Risk**: only valid for self-hosted targets (bench mode). Production-engagement targets we cannot tail.
- **Status**: planned. Operator gate: bench-mode only (AEGISPT_MEMORY_ROOT contains bench or xbow).

### Decision rule update

Order after current capability work: M2 wire -> M5 measurement -> M7 (if not obviated) -> M10 -> M11 -> H-roadmap activation gate.


## 7. M9 deep-read results -- PentestGPT (USENIX'24) (2026-05-26)

Sources: [USENIX '24 paper](https://www.usenix.org/system/files/usenixsecurity24-deng.pdf), [project page](https://pentestgpt.com/paper.html), [GitHub greydgl/PentestGPT](https://github.com/GreyDGL/PentestGPT).

PentestGPT's central design is a **3-module separation** (Reasoning + Generation + Parsing) to combat context-loss across a long pentest. They run a **Pentesting Task Tree (PTT)** as the lead-tester's working memory.

Mapping to AegisPT (most concepts already present):

| PentestGPT module | AegisPT equivalent | gap |
|---|---|---|
| Reasoning Module (lead-tester role, picks next sub-task) | picker (picker_specialists + claude_select_next_action) | covered, structurally identical |
| Generation Module (operator role, writes commands/payloads) | runners + script_critic (LLM-emitted python_script) | covered |
| Parsing Module (tester-assistant role, distils tool output) | evidence_ingest + findings parser (workers/orchestration/findings.py) | covered |
| Pentesting Task Tree (PTT) | hypothesis_queue + attack_state.FootholdState (backlog-412 Layer 3) | covered, our version is flatter |
| Chain-of-thought micro-steps | exec_plan step decomposition + script_critic revision loop | covered |
| Context-loss mitigation via module isolation | O4 refactor (helpers / guards / recall / picker_schema / etc.) | substrate matches the pattern |

No new M-item from this read. PentestGPT's lessons are already implicit in:

- O4 (assessment_loop split) is functionally the same "context-loss mitigation" PentestGPT motivates with 3 modules.
- attack_state.FootholdState IS our PTT, just less hierarchical (flat-state transitions vs tree). If solve-rate continues to plateau and the hypothesis_queue grows unmanageable, formalising the PTT shape would be the upgrade.

Action: none today. Note becomes informative-only unless a future smoke shows hypothesis_queue management becoming the bottleneck.
