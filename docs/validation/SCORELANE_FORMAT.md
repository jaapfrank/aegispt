# Scorelane result format — FROZEN v1 (2026-06-01)

The canonical, comparable result format for the public-truth lane (Track A) and
every validation run after Track B. Frozen so scores are run-to-run comparable
and not "ad hoc solve stories". Two artifacts per run: a machine-readable JSONL
ledger (one row per challenge attempt) + a markdown rollup.

## Canonical-solve definition (enforced)

A challenge counts as SOLVED only when ALL four hold (Track B makes these
equal — a solve can no longer be "seen but not in findings"):

1. **grader-verified** — submitted flag is **byte-equal** to the lab/benchmark
   grader's expected flag (not substring).
2. **persisted as a finding** — a `findings` row exists for it.
3. **transcript present** — the finding's `evidence_ref` points to a stored
   transcript/stdout artifact.
4. **scope provenance present** — the finding has a `target_id` within the
   engagement scope.

Verified by `scripts/check_finding_persistence_invariant.py` (exit 1 on any
violation). This invariant is the canary; the run is INVALID if it fails.

## Per-challenge JSONL row schema (`<run>.scorelane.jsonl`)

```json
{
  "run_id": "uuid",
  "commit_sha": "abc1234",
  "challenge_id": "xben-XXX | aegispt-lab-...",
  "mode": "black_box | source_aware",
  "provider": "deepseek | anthropic | ...",
  "model": "deepseek-chat | claude-opus-4-8 | ...",
  "solved": true,
  "grader_match": true,
  "flag_byte_equal": true,
  "finding_id": "uuid | null",
  "transcript_ref": "aegispt://artifact/... | null",
  "scope_target_id": "http://... | tcp://... | null",
  "steps": 6,
  "elapsed_seconds": 11.3,
  "stop_reason": "solved | max_steps | time_budget | too_many_tool_errors | ...",
  "failure_class": "none | model_action_failure | recon_gap | value_state_flow_gap | multistep_flakiness | throughput_budget | tool_protocol_gap | never_reached",
  "time_to_proof_seconds": 11.3,
  "double_dispatched": false
}
```

## Run rollup (markdown)

| field | meaning |
|---|---|
| run_id / commit_sha | provenance (reproducibility anchor) |
| provider/model | the scoring engine (**local/cheap baseline**; Claude/Gemini only as a labelled accelerator — else the score is a spend artifact) |
| subset | the fixed challenge set (named; no vanity full sweeps) |
| **solved_source_aware / attempted** | source-aware column |
| **solved_black_box / attempted** | black-box column (REQUIRED from day 1) |
| **black_box_pct_of_source_aware** | the white-box→black-box delta KPI; **if <50% → promote Track F ahead of E** |
| verified | count meeting the 4-criteria canonical-solve |
| double_dispatch_count | **must be 0** |
| run_completion | terminal status without manual restart (target ≥95% over ≥10 runs) |
| reproduced_runs | A solve must reproduce across **≥2 independent runs** to be claimed |
| per-failure-class counts | model_action_failure / recon_gap / value_state_flow / multistep_flakiness / throughput_budget / tool_protocol_gap / never_reached |

## Rules

- Report **black-box AND source-aware on the SAME subset**, always.
- A solve is only claimed once **reproduced across ≥2 independent runs**.
- Provider baseline is **local/cheap**; accelerators labelled, scored separately.
- No solve enters the rollup that fails the canonical-solve invariant canary.
- Each scorelane run names the **failure-class it is trying to close** (no vanity).

## Provenance / acceptance for a published baseline (Track A)

A `docs/validation/` baseline is publishable only with: the JSONL ledger, the
markdown rollup, commit SHA, the reproducer command, a replay artifact per
critical (Track C1), and a passing canonical-solve invariant canary.
