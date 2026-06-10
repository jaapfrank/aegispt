# Codex — task list (rework-4)

Owner: **Codex** (data-lane: evidence ledger, candidate-queue data, teacher-data, registry/
hygiene). Plan: `rework4-execution-plan-2026-06-08.md`. Coordinate via `coordination.md`.
Status: ☐ todo · ◐ in-progress · ☑ done · ⛔ blocked
(Claude wrote this as a proposal — Codex owns/edits it.)

## Codex boundaries

- Do not mark T-CHAIN1 done; that remains Claude/score-lane until a live
  XBEN-024 validation artifact exists.
- Do not count teacher-data, SFT rows, or ranker metrics as capability
  progress until the canonical evidence ledger moves.
- Do not create another score-count file. Every score number must come from
  `docs/validation/EVIDENCE_LEDGER.md` and its JSONL/materialized summary.
- Treat Claude's Q3 evidence taxonomy helper as shared contract input only
  until live wiring or benchmark artifacts consume it; taxonomy code alone does
  not move the canonical ledger.
- The fixed Q3 taxonomy categories are now `exploit_proven`,
  `passive_observation`, and `unproven`; Codex may consume those categories in
  ledger/reporting adapters, but they do not count as progress until backed by
  live artifacts.
- Do not edit live runner/orchestration code unless the change is requested in
  `coordination.md` and scoped to a schema/adapter boundary.
- Do not touch capability registry, approval flow, deployment flow, or runtime
  binding flow for this reset.

## Phase 0

- ☑ **0.3 — formalize the canonical evidence ledger.** Skeleton exists at
  `docs/validation/EVIDENCE_LEDGER.md` (+ `evidence_ledger.jsonl`). Make it auto-append from
  runs, dedup, and reconcile the historical **17 XBOW solves + the Gruyere admin** into the
  JSONL so there is ONE number. (THE source of truth; everything else links here.)
  - subtask: define stable JSONL schema + allowed outcomes.
  - subtask: add validation/generation command so narrative docs cannot drift.
  - subtask: map existing `docs/validation/` and XBEN gap-matrix artifacts into
    the ledger without inventing missing evidence.
- ☑ **0.4 — write down the scope freeze** (source-aware web/API + XBEN labs only) with the
  operator.
  - completed in `docs/strategy/coordination.md` under "Scope freeze details
    (Codex 0.4)".

## Phase 1

- ☑ **1.1 — source-to-exploit candidate queue (data side).** Define the candidate schema
  (sink + entry-point + vuln-class + hypothesis + rank) and have pre-recon-source emit ranked
  candidates per vuln class. Claude wires the loop to consume them. This is the Shannon core.
  - subtask: candidate id, route/method/parameter, source/runtime cue,
    vuln-class, auth requirement, hypothesis, rank, required evidence class.
  - subtask: state taxonomy for `untested`, `tested_no_signal`,
    `blocked_needs_auth`, `blocked_needs_callback`, `blocked_needs_state`,
    `exploited`, and `false_positive`.
  - subtask: fixtures for auth/authz, SSRF/internal, XSS/headless, injection,
    and file/path/upload.
  - completed via `pre-recon-candidate-queue.json` emitted by
    `pre-recon-source`, with contract tests in
    `scripts/tests/test_candidate_queue_contract.py`.
  - downstream status: Claude's 1.1 consumer is now proven functionally on
    black-box: dispatch (`f1717a10`, `has_source_dir=false`, `ie_tasks 0→1`)
    plus actual runner execution after #7 (`4a83edca`, `interactive-exploit`
    exit `0`, was exit `2`). Codex 1.1 stays complete; the next Codex-owned
    step is still 2.1 once benchmark evidence exists.
- ☑ **1.2 handoff — ledger consumes Q3 taxonomy as derived metadata.**
  - completed by adding `reportability_class` and
    `reportable_under_no_exploit_no_report` to generated ledger rows, plus
    taxonomy counts in the generated summary.
  - contract matches the real helper in
    `api/app/services/finding_evidence_gate.py`:
    `exploit_proven`, `passive_observation`, `unproven`.
  - this is interpretive metadata only; it does not change the canonical score.

## Phase 2 / 3

- ⛔ **2.1 — record XBOW-104 results** in the ledger (Claude runs; Codex logs the canonical %).
  - blocked: waiting on Claude's XBOW-104 run output / validation artifact.
  - latest Claude 0.2 / 0.2b Gruyere diagnostics are shared-state only:
    local/frontier exploit-brain behavior changed, but there is still no
    benchmark artifact for Codex to ingest.
- ⛔ **3.2 — our model as ranker/policy** over the candidate queue (shared with Claude).
  - blocked: Phase 3 item; needs Phase 2 measurement and ledger baseline first.
- ⛔ **3.3 — teacher-data continues ONLY if it moves the canonical/held-out ledger.** Until
  then, label all teacher-data as data, not capability. (Current: v4pro_demonstrated_iter9=118,
  selected_total=16917 — data, not progress, per Codex's own note.)
  - blocked: requires live/held-out ledger movement before more teacher-data is
    treated as capability-relevant.
  - Claude's 2026-06-09 teacher-transfer / rollout notes (`0/8`, steps `0`)
    remain experiment-only and do not unblock teacher-data promotion.
- ☑ **3.3a — held-out transfer eval rows in the canonical ledger.**
  - completed by adding optional `--transfer-matrix` support to
    `scripts/validation/build_evidence_ledger.py`.
  - transfer rows use `row_type=heldout_transfer_eval` and carry reward,
    flag, pivot, recovered-after-block, used-revealed-value, run-label,
    scenario-hash, scenario-id, and chain-class metadata.
  - after Claude's reward-formula correction, transfer summaries now expose
    `milestone_rate`, `pivot_rate`, `recovered_after_block_rate`, and
    `used_revealed_value_rate` per run and per run/class so reward floor
    (`4-5`) is not mistaken for chain progress.
  - canonical XBOW score remains target-only: transfer rows do not change
    `17/104`.
- ◐ **3.3b — completion-focused demonstrated chains for the 14B train.**
  - next data-generation lever from Claude's 2026-06-09 handoff.
  - needs high-quality rows that reach `flag=True` / `recovered=True`, not
    engagement-only traces.
  - keep D2 held-out scenario hashes leakage-free.
  - completed sub-slice: iter9 V4-Pro teacher generator now rejects
    engagement-only rows by requiring at least 5 assistant turns, a
    post-block retry/proof/marker signal, and final
    `evidence.goal_satisfied=true`.
  - remaining: run a long V4-Pro/teacher batch with operator-approved
    budget/timebox and ingest only rows that pass the strengthened guard.
- ☑ **3.3c — clean untrained Qwen3-14B held-out baseline import.**
  - Codex records the transfer matrix once Claude produces the baseline
    rollout artifact.
  - completed by materializing
    `docs/validation/transfer-14b-2026-06-09/aegispt_transfer_matrix_iter10.json`
    through `scripts/validation/build_evidence_ledger.py --transfer-matrix ... --write`.
  - canonical ledger now has 16 `heldout_transfer_eval` rows for
    `untrained-14b-base` and `qlora-14b-chains-80step`; target score remains
    `17/104` and both held-out runs have `milestone_rate=0.0`.
- ☑ **3.3d — free completion-arc expansion.**
  - from Claude's 2026-06-09 handoff: expand completion arcs from free
    oracle/scripted generators and leakage-audit against the 8 D2 held-out
    classes.
  - target output: one clean messages-format JSONL, roughly 500-1000+
    completion arcs, data-lane only until held-out ledger movement exists.
  - completed with
    `codex/results/training/free-completion-arcs-20260609/aegispt_free_completion_arcs_iter10_train.jsonl`.
  - manifest reports `accepted_count=636`, `source_row_count=159`,
    `scripted_teacher_demo=544`, `scripted_oracle_rollout=92`, and
    `heldout_collision_count=0` against the 8 D2 held-out eval hashes.
  - guard script:
    `scripts/training/build_free_completion_arc_dataset_iter10.py`; tests:
    `scripts/tests/test_free_completion_arc_dataset_iter10.py`.
- ☑ **3.3e — transfer-eval to ledger ingestion command.**
  - completed by hardening `scripts/training/build_transfer_matrix_iter10.py`
    as the command Claude can run over `/tmp/transfer_<run>/res_*.json`
    rollout dirs.
  - output summary now prints the exact
    `python3 scripts/validation/build_evidence_ledger.py --transfer-matrix ...`
    command for summary and materialized ledger use.
  - added complete-scenario guardrails:
    `--require-complete-scenarios`, `missing_scenario_ids_by_run`,
    `unknown_scenario_ids_by_run`, and `complete_run_count`.
  - multiple samples per scenario remain allowed; the guard only requires at
    least one known result per manifest scenario.
- ☑ **3.3f — discovery-prefixed completion arcs.**
  - from Claude's 2026-06-10 handoff: the trained 14B reached action format
    but not the goal path (`blocked_goal=False`), so recovery-only arcs start
    too late.
  - completed with
    `codex/results/training/discovery-prefixed-arcs-20260610/aegispt_discovery_prefixed_completion_arcs_iter10_train.jsonl`.
  - manifest reports `accepted_count=1272`, `source_row_count=636`,
    `semantic_direct=636`, `scout_then_semantic=636`, and
    `heldout_collision_count=0` against the 8 D2 held-out eval hashes.
  - guard script:
    `scripts/training/build_discovery_prefixed_completion_arcs_iter10.py`;
    tests:
    `scripts/tests/test_discovery_prefixed_completion_arcs_iter10.py`.

## Completed pre-rework-4 data artifacts

- ☑ iter9 combined SFT mix rebuild; D1 top-up / final mixwatch.
  - artifact housekeeping only; feeds Phase 3 only and remains gated on
    canonical ledger movement.
  - status files report `rc=0` for D1 teacher64, D1 mixwatch, D1 top-up, and
    final mixwatch.
  - combined iter9 mix:
    `codex/results/training/iter9-combined-sft-mix-20260607/aegispt_iter9_combined_sft_mix_manifest.json`
    reports `selected_total=16917`, `v4pro_demonstrated_iter9=118`, and
    `held_out_hashes=2892`.
