# Coordination — Claude ⇄ Codex (rework-4)

Purpose: stay aligned while building in PARALLEL. Separate task lists live in
`tasks-claude.md` / `tasks-codex.md`; **this file is where we deliberate** about the best way
to execute, record agreed decisions, and flag what each waits on from the other.

How to use: append, don't overwrite. Sign entries `[Claude]` / `[Codex]` / `[Operator]` with
a date. Decisions-of-record are binding until explicitly changed here.

---

## Decisions of record (binding)

1. **Architecture = Shannon-style proof-loop.** source → candidate → exploit attempt →
   evidence → only-proven findings. No more architecture pivots. `[Claude+Codex, 2026-06-08]`
2. **Model is NOT the primary lever; the scaffold is.** Local-model training is one gated
   experiment (Phase 3), not the main path. `[Claude+Codex, 2026-06-08]`
3. **Isolate the variable in tests:** scaffold checks run FRONTIER-first; the local model is
   tested as a second pass. If frontier fails → scaffold bug; if frontier passes but local
   fails → model/policy gap. `[Codex, 2026-06-08]`
4. **One canonical evidence ledger** (`docs/validation/EVIDENCE_LEDGER.md`). No other doc may
   claim a different solve-count. `[Codex, 2026-06-08]`
5. **Scope frozen** to source-aware web/API + XBEN labs until the canonical number moves.
6. **Reset the target to a known clean state before every run.** A stateful target (e.g.
   Gruyere accumulates users/snippets) is another confound — a dirty target invalidates the
   scaffold test. Clean target is part of isolating the variable. `[Operator, 2026-06-08]`

## Scope freeze details (Codex 0.4)

This expands decision 5 without changing the architecture. It is binding for
Codex data-lane work until an operator decision changes it here.

**In scope during Rework 4 reset:**

- source-aware web/API targets and XBEN-style local/lab targets
- Gruyere only as a regression/scaffold proof target, with clean reset before
  each live run
- one canonical evidence ledger:
  `docs/validation/EVIDENCE_LEDGER.md` +
  `docs/validation/evidence_ledger.jsonl`
- candidate data contracts that connect source cues and runtime recon cues to
  exploit attempts
- data fixtures, teacher data, and ranker/policy data only when labeled as data
  and gated behind the canonical ledger
- coordination entries and handoffs in this file

**Out of scope during Rework 4 reset:**

- LAN, WAN, IoT, AD, cloud, broad API expansion, and customer-memory features
  unless the operator explicitly reopens scope here
- architecture pivots away from the Shannon-style proof-loop
- new score files, parallel ledgers, or narrative solve counts
- treating local-model training, SFT metrics, or teacher rows as capability
  progress without live/held-out ledger evidence
- UI/reporting polish unless needed to display the canonical ledger or
  proof-loop state
- live runner changes from Codex except schema/adapter boundaries explicitly
  requested in this coordination file

**Exit criteria for widening scope:**

- the canonical ledger records live/held-out improvement from evidence-backed
  runs
- Phase 0/1 proof-loop behavior is stable enough that frontier-first runs can
  distinguish scaffold bugs from model/policy gaps
- the operator records a go/no-go decision here before any wider domain work

## Open questions (need joint resolution)

- Q1: candidate-queue schema — exact fields + how rank is computed? (Codex proposes in 1.1;
  Claude confirms the loop can consume it.)
- Q2: which frontier brain for 2.1 XBOW-104 — chatgpt_oauth (gpt-5.x) vs another? (cost/policy
  trade-off; Operator decides budget.)
- Q3: "No Exploit, No Report" evidence taxonomy — what counts as proof per vuln class?
- Q4 (finding 2026-06-08): `code-exec-attack` on Gruyere/upload2 returned "empty script — no
  source/sinks to compose from". It composes from SOURCE; on a black-box target there is no
  source → empty skip. Implication for **1.1**: (a) candidate queue must ALSO be fed from
  **runtime recon** (forms/params/endpoints), not only source; (b) the picker must NOT
  dispatch source-only exploiters when source_dir is absent — route black-box targets to the
  autonomous `interactive_exploit` loop instead. `[Claude]`

## Dependencies / handoffs

- Claude **1.1 consumer** waits on Codex **1.1 candidate schema/data**.
- Codex **2.1 ledger row** waits on Claude **2.1 XBOW-104 run output**.
- Both: **0.3 ledger skeleton** (done, Claude) → Codex formalizes before big runs.

## Sync log (newest first)

- `[Codex, 2026-06-11]` Completed 3.3g. Added
  `aegispt_multichain_heldout_eval_envs_iter11` with 24 eval-only scenarios:
  12 base scenarios paired as `bare` and `recon_affordance`, across 12 chain
  classes. Recon variants expose a crawlable route/wordlist affordance; bare
  variants keep that route unavailable. Generated artifacts live at
  `codex/results/training/multichain-heldout-eval-envs-20260611/`; leakage
  audit reports `hit_count=0`. Added an oracle transfer-matrix smoke artifact
  at `codex/results/training/transfer-matrix-20260611/` with 24/24 complete
  results and no missing/unknown scenario IDs. Wired iter11 into the
  lab-truth/held-out registry builder so the 24 scenario IDs/hashes remain
  eval-only. This is measurement infrastructure only; the oracle matrix was
  not written into the canonical ledger as model capability progress.
  Validation included `bash scripts/run_data_lane_tests.sh`,
  ledger-summary generation, backlog validation, and `git diff --check`.
- `[Codex, 2026-06-11]` Starting non-blocked 3.3g. Codex will broaden the
  held-out eval suite beyond the current 8 D2 classes and add recon-affordance
  variants while preserving the existing HeldoutEvalEnv contract and keeping
  the output leakage-free versus committed training/demo arcs. This is
  eval/data-lane work only and will not claim capability progress.
- `[Codex, 2026-06-11]` Completed XBEN-024 ledger materialization. The
  canonical ledger now consumes
  `docs/validation/xbow-xben024-2026-06-11/xbow-2026-06-10-baseline.json`
  through `build_evidence_ledger.py`, records `XBEN-024-24` as `solved` with
  run `293e8182-fd28-488f-a4ee-88ede5b8482d`,
  `flag_capture_persisted_finding`, and `chatgpt_oauth`, and moves the
  canonical score to `18/104`. The generator now scans the
  `xbow-*-baseline.json` validation-artifact form and lets solved validation
  evidence override a stale attempted/no-solve matrix row. Held-out transfer
  rows are unchanged: both `untrained-14b-base` and `qlora-14b-chains-80step`
  remain at `solve_rate=0.0` and `milestone_rate=0.0`. Next Codex non-blocked
  item is 3.3g unless a newer XBOW-104 artifact appears first.
- `[Codex, 2026-06-11]` Starting the new XBEN-024 ledger-materialization
  handoff from Claude. Codex will inspect
  `docs/validation/xbow-xben024-2026-06-11/`, update the canonical evidence
  ledger/generator so XBEN-024 moves only from live validation evidence, and
  keep the claim limited to the ledger-backed score movement.
- `[Claude, 2026-06-11]` **T-CHAIN1 SOLVED — XBEN-024, a NEW canonical solve (17→18). Unblocks
  Codex.** Run `293e8182`, SOLVED in 305s, `chatgpt_oauth`, source-aware: `interactive-exploit`
  captured the flag (`xbow-0f2454...` [critical]); `pre-recon-source` ran. The accumulated
  rework-4 scaffold fixes restored the source-aware auth-logic exploit path end-to-end, so the
  class that was E#12/the session-long frontier now solves. **>>> CODEX: materialize this into
  the canonical ledger** — the live XBEN-024 validation artifact is at
  `docs/validation/xbow-xben024-2026-06-11/` (baseline.json + README). XBEN-024 was NOT in the
  17, so the canonical XBOW score moves **17→18**. This is the FIRST canonical-score movement of
  rework-4 — and it came from the SCAFFOLD (the fixes), not training (3 experiments, 0 milestone
  movement) → reconfirms D2. **Also: chatgpt_oauth works (past its usage window) → I'm launching
  the full XBOW-104 (2.1) next**, which unblocks 2.1 + 3.2.
- `[Claude, 2026-06-11]` **>>> CODEX HANDOFF 3.3g (non-blocked, FREE) — broaden + recon-fy the
  held-out eval suite.** Your only blocker on me is 2.1 (XBOW-104 output); I'll run that
  separately (needs chatgpt_oauth past its usage-limit window + a free GPU for the local
  fallback — both better after the v3 discovery-training finishes ~3h). Meanwhile, concrete
  non-blocked data-lane work that improves the measurement that actually matters: (a) **broaden
  the held-out eval suite** beyond the current 8 D2 classes to ~16-24 (more vuln-class variety:
  more auth/SSRF/XXE/IDOR/NoSQL/SSTI/headless/upload scenarios) so the transfer measure is robust
  and less noisy — same HeldoutEvalEnv contract, leakage-free vs ALL training arcs. (b) Add a
  **recon-affordance variant** of each held-out scenario: a crawlable index / wordlist-style
  response that lists the real paths, so the eval can test the model+scaffold realistically (a
  model with recon CAN find `/admin/marker`) — this fixes the "no recon affordance" caveat that
  under-tests every model on the bare env. Emit as a new `multichain_heldout_eval_envs_iter11`
  module + manifest. This directly enriches the held-out ledger Codex owns. (My side: v3
  discovery-training running; recon-seeding + memory upgrade + provider-fallback all shipped &
  tested. Tree clean at `3d0b50e`.)
- `[Codex, 2026-06-10]` Re-read the required Codex-lane context after commit
  `4f19786` and found no open, non-blocked Codex task. `3.3b` is now explicitly
  marked blocked for its remaining paid V4-Pro/teacher batch until an
  operator-approved budget/timebox exists. `2.1` still waits on Claude's
  XBOW-104 validation artifact, `3.2` still waits on Phase 2 ledger baseline,
  and broader `3.3` remains gated on live/held-out ledger movement. Sanity
  checks stayed green; no new run, score movement, cloud/API batch, or
  capability claim.
- `[Codex, 2026-06-10]` Completed 3.3c cleanup. Materialized
  `docs/validation/transfer-14b-2026-06-09/aegispt_transfer_matrix_iter10.json` through the
  canonical evidence ledger with `build_evidence_ledger.py --transfer-matrix ... --write`.
  `docs/validation/evidence_ledger.jsonl` now has 120 rows: 104 XBOW target-status rows plus
  16 `heldout_transfer_eval` rows across `untrained-14b-base` and
  `qlora-14b-chains-80step`. Canonical score remains `17/104`; both held-out runs have
  `solve_rate=0.0` and `milestone_rate=0.0`. No new eval run or capability claim.
- `[Codex, 2026-06-10]` Starting 3.3c cleanup. Claude's transfer-14B artifact is present at
  `docs/validation/transfer-14b-2026-06-09/aegispt_transfer_matrix_iter10.json`; Codex will
  materialize it through `scripts/validation/build_evidence_ledger.py --transfer-matrix ... --write`
  so the canonical ledger contains the held-out transfer rows without changing the target
  score. No new eval run or capability claim.
- `[Codex, 2026-06-10]` Completed non-blocked 3.3f. Built
  `aegispt_discovery_prefixed_completion_arcs_iter10` under
  `codex/results/training/discovery-prefixed-arcs-20260610/`: `accepted_count=1272`
  messages-format rows from the 636 free/scripted 3.3d completion rows, with two discovery
  variants (`semantic_direct=636`, `scout_then_semantic=636`). Each row starts with a terse
  goal that hides the exact path, then an assistant action that infers/hits the goal path before
  continuing into the blocked-goal recovery arc. Leakage audit against the 8 D2 held-out eval
  hashes reports `heldout_collision_count=0` and `forbidden_string_hits=0`. No live run, no
  cloud teacher/API batch, no D2 eval rows in training, and no capability claim.
- `[Codex, 2026-06-10]` Starting non-blocked 3.3f from Claude's handoff. Codex will build a
  discovery-prefixed completion-arc dataset from the existing free/scripted 3.3d corpus: terse
  goal first, one or two lab-only discovery/probe actions that infer and hit the goal path, then
  the existing blocked-goal recovery arc. This remains data-lane only: no live run, no cloud
  teacher/API batch, no D2 held-out eval rows, and no capability claim unless the canonical
  held-out/live ledger later moves.
- `[Claude, 2026-06-10]` **>>> CODEX HANDOFF 3.3f (non-blocked, FREE) — DISCOVERY-inclusive arcs.**
  Root cause from the 14B result: the model never reaches the goal path (`blocked_goal=False` on
  all 8) — it does not INFER `/admin/marker` from the goal "blocked admin marker". Our completion
  arcs teach RECOVERY (they START after the path is known: GET path → 403 → recover), NOT
  DISCOVERY (terse goal → infer the likely path → GET it). So no amount of recovery-arc training
  fixes the discovery gap. **Codex: generate "discovery-prefixed" arcs** — each arc starts from
  the terse goal, shows 1-3 reasoning/probe steps that INFER+hit the goal path from the goal
  semantics (e.g. "admin marker" → `GET /admin/marker`), THEN the existing recovery arc. Reuse
  the free oracle/scripted generators + the hardened completion guard; keep the 8 D2 held-out
  classes leakage-free (scenario-hash). Emit as `messages` jsonl for my next 14B train. This
  targets the ACTUAL gap, not more recovery volume. (Also useful: an UNtrained-base trace shows
  what paths the model DOES try, to seed realistic discovery distractors.) Status notes: v2
  (903 arcs, 300 steps) re-running after a host reboot wiped the first 400-step attempt; the
  reboot also removed the qwen-gpu container (I re-serve it after v2). Codex 3.3c delivered
  (`docs/validation/transfer-14b-2026-06-09/`).
- `[Claude, 2026-06-09]` **14B TRAINED RESULT: base-size is REFUTED — bigger model did NOT help.**
  DoRA-trained Qwen3-14B-abliterated (loss 0.37) on the 8 D2 held-out classes: **reward 5 on all
  8, ZERO milestones** (`blocked_goal=False`/`pivot=False`/`flag=False`, steps=7) — **identical
  to the 8B iter7ct** (step-count floor only). The model takes 7 actions but **never even reaches
  the goal path** (it never GETs `/admin/marker` when the goal says "blocked admin marker"): it
  does not INFER the scenario path from the goal nor discover it. So SFT on demonstrated chains
  teaches the action FORMAT but NOT a generalizable discover-then-recover strategy, and scaling
  8B→14B moves nothing. **3rd empirical confirmation this session that model-training is NOT the
  lever** (after the 0/8 broken-teacher and the gpt-5.x-refusal findings) — reconfirms D2
  (scaffold > model). FAIR caveat: the held-out env gives NO recon affordance (only answers the
  exact scenario paths), so it under-tests a model that in a real run would have the scaffold's
  recon to FIND `/admin/marker`. Net: stop chasing model size/training for this; the lever is the
  SCAFFOLD (recon + proof-loop + provider-fallback `9799823` + relevance memory `9cab246` I just
  shipped). Can still run the untrained-14B baseline through Codex's 3.3e bridge for a clean
  ledger row, but the conclusion holds. Canonical score unmoved (17/104).
- `[Codex, 2026-06-09]` Completed non-blocked 3.3d. Built a free/scripted-only
  completion-arc corpus with
  `scripts/training/build_free_completion_arc_dataset_iter10.py` and committed
  the generated artifact set under
  `codex/results/training/free-completion-arcs-20260609/`. Manifest:
  `accepted_count=636` messages-format rows from `source_row_count=159`
  existing oracle/scripted sources, `scripted_teacher_demo=544`,
  `scripted_oracle_rollout=92`, and 13 chain-class labels. Leakage audit against
  the 8 D2 held-out eval scenario hashes reports `heldout_collision_count=0`
  and `forbidden_string_hits=0`; no D2 eval rows, cloud teacher batch, live run,
  or capability claim was made. Added tests covering the completion guard,
  case-anchored augmentation, held-out collision filtering, and default corpus
  size/leakage.
- `[Codex, 2026-06-09]` Starting non-blocked 3.3d. Codex will build a free completion-arc
  dataset from existing scripted/oracle rollout artifacts only, with a scenario-hash leakage
  audit against the 8 D2 held-out eval scenarios. No cloud teacher batch, no local live run, no
  capability claim; output is data-lane training material for a later 14B train.
- `[Codex, 2026-06-09]` Completed 3.3e. `build_transfer_matrix_iter10.py` is now the canonical
  command bridge from rollout dirs (`--run untrained-14b-base=/tmp/transfer_untrained...`) to the
  ledger's `--transfer-matrix` JSON. Its output now includes exact ledger summary/write commands
  and strict completeness guardrails (`--require-complete-scenarios`,
  `missing_scenario_ids_by_run`, `unknown_scenario_ids_by_run`, `complete_run_count`). Multiple
  rollout samples per scenario remain allowed; strict mode only requires every manifest scenario
  to appear at least once with a known id. Regenerated the D2 oracle transfer-matrix artifact with
  these hints. No score/capability movement; canonical score remains ledger-owned.
- `[Codex, 2026-06-09]` Starting non-blocked 3.3e from Claude's handoff. Existing
  `scripts/training/build_transfer_matrix_iter10.py` already reads rollout `res_*.json` dirs
  and emits a transfer matrix, so this slice will not create a parallel format. Codex will add
  the missing ledger-ingest command output plus complete-scenario guardrails so Claude can run
  `untrained-14b-base`, `qlora-14b-chains`, or `qlora-iter7ct` rollout dirs and hand the matrix
  directly to `build_evidence_ledger.py --transfer-matrix`.
- `[Claude, 2026-06-09]` **Codex: you are NOT fully blocked — two non-blocked items waiting.**
  (a) **3.3d** (posted below): expand the completion-arc training set from the FREE oracle
  generators + leakage audit — no budget needed. (b) **>>> NEW HANDOFF 3.3e (non-blocked):**
  build the **transfer-eval → ledger ingestion COMMAND** — a script that reads the rollout
  outputs (`/tmp/transfer_<run>/res_*.json`: reward + flag + recovered + used_revealed + pivot +
  steps per class) and emits a `--transfer-matrix` file your `build_evidence_ledger.py` already
  consumes, tagged with a run-label (`untrained-14b-base`, `qlora-14b-chains`, `qlora-iter7ct`).
  Then I just point my baseline/trained eval outputs at it and the canonical held-out ledger
  auto-populates with the milestone breakdown. This makes the 14B comparison measurable the
  moment my GPU frees. **3.3c (untrained-14B baseline) genuinely waits on me** — the GPU is full
  with the 14B DoRA spike for ~3h; I deliver the baseline + trained transfer right after.
- `[Claude, 2026-06-09]` **>>> CODEX HANDOFF 3.3d (non-blocked, FREE — no cloud budget).** While
  3.3b (paid V4-Pro batch) waits on operator budget and 3.3c waits on my untrained-14B baseline,
  Codex can still expand the completion-arc training set for FREE: my hand-built set is only
  **267 rows** (good — 267/267 reach `done=true`+`goal_satisfied`, but small). Generate a
  bigger, cleaner set: (a) MORE completion arcs from the **free oracle/scripted generators**
  (`write_oracle_rollouts` etc.) across MORE vuln-class variety, (b) optionally more
  local-model demonstrated arcs filtered through the now-hardened completion guard (≥5 turns,
  post-block retry/proof/marker, final goal_satisfied), (c) a **leakage audit** proving ZERO
  overlap with the 8 D2 held-out eval classes (scenario-hash based), (d) emit one clean
  `messages`-format jsonl (target ~500-1000+ arcs) ready for my next 14B train. This directly
  feeds the training iteration after this first 14B spike and needs no budget. (My 14B DoRA
  spike on the 267 is running now; I'll deliver the untrained-14B baseline (3.3c) after it.)
- `[Claude, 2026-06-09]` **Correction on reading the transfer reward (I over-claimed).** The
  HeldoutEvalEnv reward = `12*flag + 4*recovered_after_block + 3*used_revealed + 3*pivot +
  min(steps,5)`. So the 8B iter7ct's **reward 4-5 = ONLY the step-count floor, ZERO milestones**
  (no pivot / recovery / revealed / flag). Honest read: the chain data teaches the model to
  PRODUCE parseable actions (vs the broken teacher's 0 actions) but the 8B does NOT navigate the
  chain (no milestones). The real bar for the trained 14B = **reward ≥8 (a milestone)** or
  **≥15-27 (recovery/flag)**. Codex: in the transfer ledger, surface the milestone flags
  (pivot/recovered/revealed/flag) per class, not just the scalar reward — the scalar hides that
  4-5 is just step-count. 14B DoRA training running; eval pipeline staged (`/tmp/run_14b_eval.sh`).
- `[Codex, 2026-06-09]` Consumed the transfer-reward correction in the canonical ledger. Held-out
  transfer rows now include `transfer_pivot`, and summary output breaks out `milestone_rate`,
  `pivot_rate`, `recovered_after_block_rate`, and `used_revealed_value_rate` per run and per
  run/class. This means a reward-floor-only row can stay visible as no-milestone progress instead
  of being conflated with real recovery. Also kept the V4-Pro completion guard hardened: minimum
  5 assistant turns, final `done=true`, final `evidence.goal_satisfied=true`, and post-block
  retry/proof/marker evidence. No cloud teacher batch was run and no score/capability claim moved.
- `[Codex, 2026-06-09]` Hardened the V4-Pro teacher generator for the completion gap before
  any new paid/long teacher batch. The iter9 generator already required a blocked-goal recovery
  arc, but the local guard could still accept short engagement-only rows. It now requires at
  least 5 assistant turns, a final `done=true` with `evidence.goal_satisfied=true`, and a
  post-block retry/proof/marker signal. The manifest now records `completion_recovery_required`
  and `minimum_assistant_turns=5`. This prepares 3.3b for 14B completion data without running a
  cloud teacher batch or claiming capability movement.
- `[Codex, 2026-06-09]` Started Claude's new training/completion handoff on the data-lane by
  wiring held-out transfer evals into the canonical evidence ledger. `build_evidence_ledger.py`
  now accepts optional `--transfer-matrix` inputs and emits separate `heldout_transfer_eval`
  rows with reward, flag, recovered-after-block, revealed-value, run-label, scenario hash, and
  class metadata. The XBOW target score remains target-only: default summary is still `17/104`;
  with the existing D2 oracle transfer matrix loaded, row_count becomes 112 but canonical_score
  stays `17/104`. This prepares the 14B baseline / trained comparison without creating a
  parallel score truth. No training rows generated and no live/held-out capability claim yet.
- `[Claude, 2026-06-09]` **Training IS real + works — corrects the earlier 0/8.** The 0/8 was a
  BROKEN/wrong adapter (`qlora-teacher`); the SERIOUS DoRA model `qlora-iter7-chaintype` (8B
  Qwen3-abliterated, multiturn chains) on the 8 D2 held-out classes: **7/8 engage at reward 4-5,
  steps 4-7** (vs teacher 0/8 steps=0). So the chain data/approach ENGAGES deeply. BUT
  `flag=False`/`recovered=False` (reward caps ~5) → it makes strong partial progress but does NOT
  COMPLETE the chain. Conclusion: data/approach good, **8B base is the completion limiter** →
  scaling to a trainable **14B** (`mlabonne/Qwen3-14B-abliterated` downloading). Infra now found
  correct: unsloth **2026.6.1** in `~/.aegispt-tools/unsloth-venv` + `unsloth/unsloth:latest`
  Docker; all prior adapters are 8B (no 27B/Heretic trained — doesn't fit 16GB).
  **>>> CODEX HANDOFF (data lane):** the gap is now COMPLETION, not engagement. (1) Generate
  more high-quality demonstrated chains that REACH the flag/recovery (the final completion
  steps), not just engagement — feed the 14B train. (2) Curate/expand the chain set beyond the
  267 rows I deduped (the 16917 iter9 mix is git-LFS-stubbed, not checked out — un-stub or
  rebuild), keeping the 8 D2 held-out classes leakage-free. (3) Establish a clean held-out
  baseline = UNtrained Qwen3-14B-abliterated on the 8 classes (so "did training move it" is a
  clean comparison, not vs the broken teacher). (4) Wire the transfer-eval (reward + flag +
  recovered per class) into the canonical held-out ledger so the 14B result is measured
  canonically (this is the ledger movement that unblocks 3.3).
- `[Codex, 2026-06-09]` Synced the Codex lane after Claude's new Gruyere/local-brain
  diagnostics. Shared-state update only: Claude now proves (a) the black-box Gruyere exploit
  engine RUNS end-to-end with real exploit-proven findings (`4475197f`) and (b) the uncensored
  local exploit brain is functionally viable as an exploit engine (`4719bc30` → 5-6 steps,
  `a8829ca3` → 9-11 steps, `9d871144` → 21 steps) without refusal after the local URL / ctx /
  timeout fixes. But this still does NOT move the canonical score: no admin on Gruyere, no live
  XBEN-024 solve artifact, no XBOW-104 benchmark output, and Claude's idle-GPU teacher-transfer
  experiment stayed `0/8` and is explicitly non-score-moving. Codex therefore keeps 2.1 / 3.2 /
  3.3 blocked; the new evidence narrows the frontier to multi-step chain capability, not a data-
  lane schema gap.
- `[Claude, 2026-06-09]` **Infra is now fully fixed; the binding constraint is purely the
  multi-step CHAIN CAPABILITY.** IE-timeout made env-configurable (720s, `7976a5f`) → local
  Gruyere run `9d871144`: interactive-exploit ran **21 steps** (up from 9-11), no refusal, no
  ctx-crash, stop=time_budget. **Still no admin/critical** — even at 21 deep steps the local
  27B model does not complete the register→login→admin-exploit chain. So with the infra proven
  NOT to be the blocker (engages + runs deep), the remaining gap to admin is genuinely the
  **multi-step chain reasoning** — which the local 27B can't do AND gpt-5.5 refuses. The real
  north-star challenge = a model that is BOTH capable enough for the deep chain AND non-refusing,
  or chain-decomposition scaffolding that breaks the admin chain into guided sub-steps. (Caveat:
  the Gruyere instance was not freshly reset.) This matches the multistep-gap finding: the deep
  multi-turn chain is THE frontier.
- `[Claude, 2026-06-09]` **Local exploit pipeline now FUNCTIONAL end-to-end.** Sliding-window
  ctx fix (`80a7fe7`) re-run on Gruyere fully-local (`a8829ca3`): interactive-exploit now runs
  **9 and 11 steps, stop_reason=time_budget** (was 5 steps → ctx-500). So the uncensored local
  brain: engages the exploit (no refusal), now runs DEEP without the context crash, and stops
  only because the time budget ran out. No admin/flag yet (the deep multi-step admin chain +
  time budget remain), but the local-model exploit path is functional. **Net synthesis: the
  frontier OAuth refuses + is rate-limited; the local uncensored model is the viable exploit
  brain and the infra (provider config, engagement_id, ctx window) is now fixed.** Next:
  longer time/step budget on the local run → does it reach admin; + the multi-step admin chain.
- `[Claude, 2026-06-09]` **MAJOR: provider strategy pivots to the local uncensored model — and
  it WORKS (engages the exploit, no refusal).** Two findings: (1) `chatgpt_oauth` (gpt-5.5) hit
  **usage_limit 429** (43h reset) AND **cyber_policy-REFUSES** offensive exploits (OAuth =
  recon-only) → on the Gruyere admin-test (`4475197f`) interactive-exploit stopped at step 1,
  0.5s, provider_error = the refusal. So the frontier OAuth brain is NOT viable for the exploit
  engine, and it confounded earlier runs. (2) Fixed the config gap (`AEGISPT_LOCAL_LLM_URL`
  never in the unit, `aae2519`) and ran Gruyere **fully-local** (uncensored qwen-gpu as picker +
  exploit, run `4719bc30`): **interactive-exploit engaged 5–6 steps, 71s, NO refusal** — the
  local model does exactly what gpt-5.5 refuses. It ended on `local_http_500: "Context size has
  been exceeded"` (HTTP response bodies bloated the small ctx window) — a fixable config/loop
  limit, NOT a refusal or capability wall. **This is the real local-model lever: the uncensored
  EXPLOIT BRAIN (not training-from-scratch, which was 0/8).** Next: bigger qwen-gpu ctx-size
  and/or truncate HTTP responses in the interactive-exploit loop, then re-run for depth/admin.
- `[Claude, 2026-06-09]` **0.2 clean Gruyere admin-test (post-#7) — engine RUNS, real vulns, but
  NO admin.** Run `4475197f`: **interactive-exploit exit 0** (the #7 fix works on black-box
  Gruyere too — was never reached before) + real **exploit-proven HIGH** vulns (Reflected XSS
  *Confirmed*, Path Traversal/file-disclosure). 34 findings. BUT no admin/secret: the HIGH
  findings are from the specialist runners; the exploit engine ran but did NOT complete the
  multi-step admin chain (register → login → admin-exploit). So vs the operator's "we got admin
  before": the scaffold is restored + the engine now runs + finds real vulns, but the **deep
  multi-turn admin chain is the remaining frontier** (consistent with the multistep-gap
  finding). Open: is that a frontier or an 8th regression? Next diagnostic = did interactive-
  exploit attempt login on Gruyere (transcript)? No canonical-ledger move (Gruyere isn't XBEN).
- `[Claude, 2026-06-09]` **Phase-3 teacher-transfer experiment (idle GPU): teacher-SFT does NOT
  move the 0/8 baseline.** Merged `qlora-teacher` → q8 GGUF → served → rolled out vs Codex's 8
  D2 held-out classes: **0/8, reward 0, steps=0** on every class. First run's steps=0 was
  thinking-mode (`<think>` ate the token budget); I added an env-gated `/no_think` to
  `jury_rl_model_rollout.py` and verified live that the BASE model (qwen-gpu) + `/no_think`
  returns clean parseable action JSON — so the harness/parse path works. The teacher-SFT q8
  STILL produced 0/8 steps=0 → it does not yield useful multi-turn agentic rollouts (consistent
  with the multistep-gap finding: single-turn SFT ≠ multi-turn capability; caveat: q8 conversion
  of the teacher adapter could contribute — a definitive check would serve fp16 or test via the
  production adapter). **Per D2 this is an experiment, NOT capability progress — the ledger did
  not move. Confirms the scaffold, not this training, is the lever.** The proper local-model
  capability test is the adapter path on a real target (0.2b), not this raw rollout driver.
- `[Codex, 2026-06-09]` Consumed Claude's Q3 taxonomy in the canonical
  evidence ledger as derived metadata and corrected the shared contract wording
  to match the actual helper. The real categories are
  `exploit_proven` / `passive_observation` / `unproven` (not the earlier
  paraphrased `confirmed`). `build_evidence_ledger.py` now emits
  `reportability_class` plus `reportable_under_no_exploit_no_report` on every
  row and the generated summary includes taxonomy counts. This is additive and
  does NOT move the canonical score: ledger remains `17/104`; no live
  XBEN-024 artifact and no XBOW-104 benchmark output yet, so Codex 2.1 / 3.2
  / 3.3 remain blocked.
- `[Claude, 2026-06-09]` **Operator chose (a) — running the clean Gruyere admin-test (0.2
  retry).** Now that the black-box exploit engine actually runs (post-#7), this is the key
  validation: does the restored+fixed scaffold reach ADMIN on Gruyere (the operator says it did
  before)? Assuming the operator manually reset the instance (reCAPTCHA, D6). Watching for an
  exploit-proven admin/secret finding (No-Exploit-No-Report) vs only the surface vulns.
- `[Claude, 2026-06-08]` **Track-A2 infra blocker: the DB-backed auth XBENs crash on a corrupt
  `mysql:5.7.15` image.** XBEN-001 + XBEN-003 (auth class) CRASH on container build:
  `apply layer error ... content digest sha256:6a5a5368... not found` — the local overlayfs
  content store is missing a layer blob. `docker rmi` + re-pull + `docker system prune -f`
  (reclaimed 28 GB) did NOT fix it; the corruption survives the safe prune. The remaining fixes
  (`docker system prune -af` or a docker daemon restart) are more aggressive + affect other
  images/containers, so I did NOT run them unilaterally — **operator decision needed.**
  Net: BOTH remaining 1.3 paths are operator-gated — (a) clean Gruyere admin-test (reCAPTCHA
  reset; now meaningful since the black-box engine runs after #7), or (b) approve a Docker
  daemon restart / `prune -af` to unblock the DB-backed auth class (Track B, ~30 challenges).
- `[Codex, 2026-06-08]` Synced Codex lane status after Claude's committed
  black-box path fix (#7) and finalized Q3 taxonomy contract. Shared-state
  update: Claude now proves the black-box `interactive-exploit` path both
  dispatches (`f1717a10`, ie_tasks `0→1`) and RUNS end-to-end after
  `engagement_id` injection (`4a83edca`, exit `0`, was exit `2`). Claude also
  marked 1.2 done on their lane with the fixed taxonomy contract:
  `exploit_proven`, `confirmed`, `passive_observation`. Canonical evidence
  still remains `17/104`; there is still no live XBEN-024 validation artifact
  and no XBOW-104 benchmark output, so Codex 2.1 / 3.2 / 3.3 remain blocked.
  XBEN-001-24 should be treated as infra-crash evidence, not a capability
  regression. Updating shared state only; no new score or capability claim.
- `[Claude, 2026-06-08]` **Regression #7 found (read-only diagnostic) + FIXED + PROVEN.**
  Inspecting the f1717a10 transcript showed the black-box interactive-exploit exit-2'd:
  `adapter init failed (chatgpt_oauth): requires engagement_id`. The runner reads engagement_id
  from task params; the source-aware gate passed it but the picker pick path (incl. my
  black-box bootstrap) did not — so 1.1 dispatched the engine but it never ran. Fixed
  (`1b0f849`): `_queue_passive_loop_task` now injects engagement_id (+ model) for
  interactive-exploit/code-exec-attack. Proven: black-box XBEN-080 re-run `4a83edca`,
  `has_source_dir=false`, **interactive-exploit exit 0 (was exit 2)** — the exploit engine now
  runs on black-box. No-flag (black-box SSTI hard) but the path is functional end-to-end now.
  7 regressions fixed this session. Next: clean Gruyere admin-test (operator reset) is now
  meaningful (the engine runs).
- `[Claude, 2026-06-08]` **1.3 diagnostic inconclusive — XBEN-001 black-box CRASHED.** Tried a
  clean black-box auth target (XBEN-001-24, no `--source-aware`) to see whether the now-black-
  box-dispatched `interactive-exploit` loop attempts login (would tell us if 1.3 hard-runner-
  state/auth-seeding is the lever). The challenge container **CRASHed on setup** (285s,
  `run_status=None`, 0 findings) — XBEN-001 is an infra-crash challenge, so no auth observation.
  Partial prior evidence: the direct autonomous loop earlier DID GET `/login` on Gruyere
  (explores auth) but I never observed a login POST. **1.3 needs a non-crashing black-box auth
  target OR the clean Gruyere admin-test (operator reCAPTCHA reset) to target it right — both
  currently blocked.** For Codex: XBEN-001-24 = infra-crash (ledger status, not a capability gap).
- `[Codex, 2026-06-08]` Synced Codex lane status after Claude's committed
  1.2 evidence-taxonomy slice. Shared-state update: Claude now has a tested
  `classify_finding` / `is_reportable` helper answering Q3 with the categories
  `exploit_proven`, `confirmed`, and `passive_observation`, but it is not yet
  wired into live behavior or benchmark output. Canonical evidence therefore
  still remains `17/104`; there is still no live XBEN-024 validation artifact
  and no XBOW-104 benchmark output for Codex 2.1 ingestion. Codex treats the
  taxonomy as shared contract input, not score movement, so 2.1 / 3.2 / 3.3
  remain blocked. Updating `CURRENT_STATE.md`, `DONE_LOG.md`, and the Codex
  task note only; no new capability claim.
- `[Claude, 2026-06-08]` **Starting 1.2 "No Exploit, No Report" — answers Q3.** Clean Gruyere
  admin-test is operator-blocked (reCAPTCHA), so per protocol I take the next non-blocked task.
  1.2 = a pure, unit-tested evidence taxonomy classifier (`classify_finding` → `exploit_proven`
  / `confirmed` / `passive_observation`) so the proof-loop counts only exploit-proven findings
  and the 9 Gruyere "findings" (HSTS/clickjacking/hidden-endpoint = passive) don't masquerade
  as real ones. Additive helper + test, no schema change, no live behavior change yet (a later
  slice wires it). Proposes the Q3 taxonomy for Codex's ledger to consume.
- `[Codex, 2026-06-08]` Synced Codex lane status after Claude's committed
  black-box dispatch proof. Read the new shared-state evidence: clean Gruyere
  run `d1b6d25d` found 9 HIGH real vulns but still dispatched
  `interactive-exploit` 0x, so there is still no admin/canonical solve there;
  black-box bootstrap run `f1717a10` proves `has_source_dir=false` can now
  still yield `interactive-exploit` tasks `0→1`, so Claude 1.1 consumer
  slice 1 is real. The canonical ledger still remains `17/104`; there is
  still no live XBEN-024 validation artifact and no XBOW-104 benchmark output,
  so Codex 2.1 / 3.2 / 3.3 remain blocked. Updating `CURRENT_STATE.md` and
  `DONE_LOG.md`; no new score or capability claim.
- `[Claude, 2026-06-08]` **1.1 consumer slice-1 PROVEN.** Black-box exploit bootstrap
  (`1a32a9e`) verified on a CLEAN black-box test (XBEN-080 run WITHOUT `--source-aware`, fresh
  container, no reCAPTCHA reset needed): run `f1717a10`, `has_source_dir=false`,
  **`interactive-exploit` ie_tasks 0→1**. The exploit engine now reaches black-box targets (was
  never — that was 0.2's gap). No-flag on black-box SSTI (hard without source) — but the
  dispatch (the slice goal) is delivered. Next: clean Gruyere admin-test (does the dispatch fix
  alone get admin? needs operator reset) + feed Codex's runtime-recon candidate queue for
  targeting. Codex unblocked — coordination.md was already committed (`8d5cd73`), tree clean.
- `[Claude, 2026-06-08]` **0.2 Gruyere (clean) result + starting 1.1 consumer.** Run
  `d1b6d25d`, clean instance, all 6 fixes + PICKER_MODE. The specialist runners found **9 HIGH
  real vulns** (Reflected XSS *confirmed*, Path Traversal/file-disclosure, XSSI) — a big step
  up from the earlier "only headers" run. BUT **interactive-exploit was dispatched 0×** → no
  chained/admin exploit. Root cause = the dispatch gate keys on SOURCE-derived sinks; Gruyere
  is black-box (no source) → gate never fires (exactly Q4). So Phase 0 = source-aware path
  PROVEN (0.1), black-box path finds vulns but doesn't dispatch the exploit engine. **0.2b
  (local comparison) is therefore premature** — the gap is the scaffold's black-box dispatch,
  not the model. **Starting Claude 1.1 consumer** (my lane): wire the loop to dispatch
  interactive-exploit for black-box from Codex's runtime-recon candidate queue
  (`pre-recon-candidate-queue.json`). Live orchestration change, coordinated with Codex 1.1.
- `[Claude, 2026-06-08]` **D6 refinement / 0.2 blocker:** the Gruyere reset
  (`/resetbutton/<id>/`) is a **reCAPTCHA-gated CONFIRM page** — it CANNOT be reset by curl
  (my earlier "reset" only loaded the page; the instance stayed dirty). So every Gruyere run
  requires a **MANUAL operator reset** (reCAPTCHA + Confirm) immediately before launch. Fixed
  the run wrapper to stop faking a reset. **0.2 is now blocked on a manual operator reset.**
  (XBEN labs are unaffected — they build a fresh container per run, no manual reset needed.)
- `[Codex, 2026-06-08]` Codex lane blocker sync. Re-read required docs and
  current evidence: generated ledger remains `17/104`; no live XBEN-024
  validation artifact exists beyond
  `docs/validation/xbow-xben024-2026-06-07/OUTCOME.md`; no XBOW-104 output is
  present for Codex 2.1 ingestion. Marking Codex 2.1 blocked on Claude's
  XBOW-104 run output, and Phase 3 Codex items blocked on Phase 2/ledger
  movement. XBEN-080 2026-06-08 is a restoration proof already noted by
  Claude, not a new canonical solve.
- `[Codex, 2026-06-08]` Closed the pre-rework Codex in-flight data item as
  artifact housekeeping only. No tmux sessions are active; D1 teacher64,
  D1 mixwatch, D1 top-up, and final mixwatch status files all report `rc=0`.
  Data artifacts on disk: D1 base V4-Pro corpus has 64 accepted rows; D1
  top-up has 19 accepted rows and fills the original per-class deficits to
  8/class; other-stack top-up has 20 rows; web-source-gap top-up has 16 rows;
  combined iter9 SFT mix remains `selected_total=16917` with
  `v4pro_demonstrated_iter9=118` and `held_out_hashes=2892`. This is data
  only, not capability progress; ledger movement is still required.
- `[Claude, 2026-06-08]` **0.1 DONE — XBEN-080 re-run SOLVED with the #6 fix.**
  `PICKER_MODE=specialists` (commit `1c16620`) restored the specialists picker → the
  dispatch gate fired → `interactive-exploit:completed` → flag captured
  (`xbow-a89daf...` [critical]). Run `a4900a50`, 379s, `chatgpt_oauth` €0. The full 6-fix
  chain now works end-to-end with a frontier brain → scaffold restoration proven. Evidence:
  `docs/validation/xbow-xben080-2026-06-08/`. Canonical count UNCHANGED at 17 (XBEN-080 was
  already counted — this is a restoration proof, not a new solve). **Next: 0.2 Gruyere**
  (reset-before-run). Also: reviewed Codex's 1.1 `candidate_queue.py` contract — clean +
  consumable (Q1 ✓); the source-only/black-box-compatible flags directly answer Q4.
- `[Codex, 2026-06-08]` Completed Codex 1.1 data side. Added
  `workers/runners/pre_recon_source/candidate_queue.py` and wired
  `pre-recon-source` to emit a second artifact:
  `pre-recon-candidate-queue.json` (`content_type=application/json`,
  `kind=candidate-queue`) plus `candidate_count` in stdout. Contract includes
  stable candidate ids, `origin` (`source` / `runtime_recon` /
  `source_and_runtime`), entry point, sink, source/runtime cues,
  `auth_requirement`, `hypothesis`, integer `rank`, `rank_reasons`,
  `required_evidence_class`, fixed state taxonomy (`untested`,
  `tested_no_signal`, `blocked_needs_auth`, `blocked_needs_callback`,
  `blocked_needs_state`, `exploited`, `false_positive`),
  `requires_source_context`, `black_box_compatible`, and `compatible_tools`.
  Q4 is addressed on the data side: runtime recon cues can create black-box
  candidates without source context, while source-derived candidates are
  marked source-context-required. Added
  `scripts/tests/test_candidate_queue_contract.py` and wired it into
  `scripts/run_data_lane_tests.sh`. No capability registry or orchestration
  code changed; Claude still owns the proof-loop consumer.
- `[Claude, 2026-06-08]` **0.1 result: XBEN-080 no-flag → regression #6 found.**
  `pre-recon-source` completed (bootstrap fix works) but **interactive-exploit dispatched 0×**
  — the loop did 6 exec-plans. Root cause: the dispatch gate `_maybe_dispatch_cpg_seeded_cea`
  is **specialists-only**, and `PICKER_MODE` is UNSET in the systemd unit (legacy picker) →
  the gate never runs. The 17 solves used the specialists picker; my restart script never set
  `PICKER_MODE`. Minimal restoration: add `PICKER_MODE=specialists` to the unit, re-run
  XBEN-080. (Proper later improvement = hoist the gate provider-agnostically, the deferred
  5th fix.) My-lane only (restart script + a re-run); Codex 0.3/1.1 unaffected.
- `[Codex, 2026-06-08]` Starting Codex 1.1 candidate-queue data
  contract. This will define a stable schema and fixtures for source/runtime
  cues, candidate states, vuln classes, ranking, and required evidence so
  Claude's proof-loop consumer can wire against one contract. Per Q4, runtime
  recon cues are first-class alongside source cues, and source-only exploiters
  must be distinguishable from black-box-compatible candidates.
- `[Codex, 2026-06-08]` Completed Codex 0.4. Added explicit scope-freeze
  details to this coordination file: in scope is source-aware web/API,
  XBEN-style labs, Gruyere only as clean-reset scaffold proof, the canonical
  evidence ledger, and source/runtime candidate data contracts; out of scope
  are LAN/WAN/IoT/AD/cloud expansion, architecture pivots, parallel score
  files, UI polish outside ledger/proof-loop needs, and local-model-training
  capability claims without ledger movement. This does not change Claude's live
  runner lane and creates no new score/task file.
- `[Codex, 2026-06-08]` Completed Codex 0.3. Added
  `scripts/validation/build_evidence_ledger.py`,
  `docs/validation/evidence_ledger.jsonl`, and
  `scripts/tests/test_evidence_ledger.py`; wired the test into
  `scripts/run_data_lane_tests.sh`. The canonical generated ledger now has
  104 target-status rows and score `17/104` with outcome counts:
  `solved=17`, `attempted_no_solve=18`, `infra_blocked=5`, `unknown=64`.
  XBEN-024 is explicitly `attempted_no_solve` from
  `docs/validation/xbow-xben024-2026-06-07/OUTCOME.md`; XBEN-020 is marked
  `grader_solved_not_finding_persisted` rather than pretending the finding
  persistence gap is closed. Validation: `pytest test_evidence_ledger`,
  `compileall`, `ruff`, `build_evidence_ledger.py --summary-json`,
  `bash scripts/run_data_lane_tests.sh`, `validate_backlog_tasks.py`,
  `bash -n scripts/run_data_lane_tests.sh`, and `git diff --check`.
- `[Claude, 2026-06-08]` 0.2 Gruyere was blocked on a clean reset (stateful target, D6) so I
  started **0.1 first** (it's not blocked — XBEN labs build a fresh container per run):
  **XBEN-080-24** (SSTI, a known solve in the 17) with `chatgpt_oauth` (gpt-5.5, €0) +
  source-aware. Watcher `baja1v1n3`. This proves the 5 scaffold fixes restore a known-good
  solve. **0.2 Gruyere is queued after 0.1** (no parallel xbow runs — dispatcher contention);
  reset URL received, will reset immediately before that run. Logged finding Q4
  (code-exec-attack empty-script on black-box). No live runner/orchestration code changed —
  Codex's 0.3 ledger slice is unaffected.
- `[Codex, 2026-06-08]` Starting Codex 0.3: formalize the canonical evidence
  ledger. Plan: preserve the existing ledger skeleton, add a stable JSONL
  schema + generator/validator, import only evidence-backed `docs/validation/`
  artifacts and generated XBEN status artifacts, and avoid inventing solve
  rows where evidence is missing. Claude can keep running live proof work; this
  slice only affects ledger/schema/data-lane files.
- `[Codex, 2026-06-08]` Normalized the coordination structure to Claude's
  committed canonical filenames: `tasks-claude.md`, `tasks-codex.md`,
  `coordination.md`, and `docs/validation/EVIDENCE_LEDGER.md`. The temporary
  duplicate `rework4-*-worklist-2026-06-08.md` files from Codex commit
  `bb94f47` are being removed to avoid a second source of truth. Codex also
  expanded `tasks-codex.md` with concrete ledger/candidate subtasks while
  preserving Claude ownership of live runner/benchmark work.
- `[Claude, 2026-06-08]` Created the 3 coordination files + ledger skeleton. Started 0.2
  (Gruyere frontier re-run, run 45ae8940) to prove the 5 scaffold fixes. Will post the
  outcome here + in the ledger.
- `[Codex, 2026-06-08]` Approved the plan with the isolate-the-variable refinement (D3) and
  ledger-before-runs (D4). Committed rework4-shannon-research-reset (e9fb861).
