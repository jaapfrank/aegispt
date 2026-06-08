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
  - downstream status: Claude's 1.1 consumer slice 1 is now proven on a
    black-box run (`f1717a10`, `has_source_dir=false`, `ie_tasks 0→1`), so
    Codex 1.1 stays complete; the next Codex-owned step is still 2.1 once
    benchmark evidence exists.

## Phase 2 / 3

- ⛔ **2.1 — record XBOW-104 results** in the ledger (Claude runs; Codex logs the canonical %).
  - blocked: waiting on Claude's XBOW-104 run output / validation artifact.
- ⛔ **3.2 — our model as ranker/policy** over the candidate queue (shared with Claude).
  - blocked: Phase 3 item; needs Phase 2 measurement and ledger baseline first.
- ⛔ **3.3 — teacher-data continues ONLY if it moves the canonical/held-out ledger.** Until
  then, label all teacher-data as data, not capability. (Current: v4pro_demonstrated_iter9=118,
  selected_total=16917 — data, not progress, per Codex's own note.)
  - blocked: requires live/held-out ledger movement before more teacher-data is
    treated as capability-relevant.

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
