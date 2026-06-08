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
- Do not edit live runner/orchestration code unless the change is requested in
  `coordination.md` and scoped to a schema/adapter boundary.
- Do not touch capability registry, approval flow, deployment flow, or runtime
  binding flow for this reset.

## Phase 0

- ☐ **0.3 — formalize the canonical evidence ledger.** Skeleton exists at
  `docs/validation/EVIDENCE_LEDGER.md` (+ `evidence_ledger.jsonl`). Make it auto-append from
  runs, dedup, and reconcile the historical **17 XBOW solves + the Gruyere admin** into the
  JSONL so there is ONE number. (THE source of truth; everything else links here.)
  - subtask: define stable JSONL schema + allowed outcomes.
  - subtask: add validation/generation command so narrative docs cannot drift.
  - subtask: map existing `docs/validation/` and XBEN gap-matrix artifacts into
    the ledger without inventing missing evidence.
- ☐ **0.4 — write down the scope freeze** (source-aware web/API + XBEN labs only) with the
  operator.

## Phase 1

- ☐ **1.1 — source-to-exploit candidate queue (data side).** Define the candidate schema
  (sink + entry-point + vuln-class + hypothesis + rank) and have pre-recon-source emit ranked
  candidates per vuln class. Claude wires the loop to consume them. This is the Shannon core.
  - subtask: candidate id, route/method/parameter, source/runtime cue,
    vuln-class, auth requirement, hypothesis, rank, required evidence class.
  - subtask: state taxonomy for `untested`, `tested_no_signal`,
    `blocked_needs_auth`, `blocked_needs_callback`, `blocked_needs_state`,
    `exploited`, and `false_positive`.
  - subtask: fixtures for auth/authz, SSRF/internal, XSS/headless, injection,
    and file/path/upload.

## Phase 2 / 3

- ☐ **2.1 — record XBOW-104 results** in the ledger (Claude runs; Codex logs the canonical %).
- ☐ **3.2 — our model as ranker/policy** over the candidate queue (shared with Claude).
- ☐ **3.3 — teacher-data continues ONLY if it moves the canonical/held-out ledger.** Until
  then, label all teacher-data as data, not capability. (Current: v4pro_demonstrated_iter9=118,
  selected_total=16917 — data, not progress, per Codex's own note.)

## In flight (Codex, pre-rework-4)

- iter9 combined SFT mix rebuild; D1 top-up / final mixwatch — finish, but these feed Phase 3
  only, gated on the ledger moving.
