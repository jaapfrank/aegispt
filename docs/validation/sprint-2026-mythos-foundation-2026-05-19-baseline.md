# Multi-target validation report — phase=baseline

Generated: 2026-05-19T11:42:00+00:00Z (consolidated; mantis re-run with `vimagick/mantisbt:latest` after `:2.21` 404'd)
Harness: `scripts/multi_target_validation.py` (backlog-406)

Per `feedback_live_proof_must_be_diverse_real_targets`: 5 unrelated real-world OSS apps,
no per-target tuning, observation-driven only.

This is the pre-sprint anchor on raw HEAD (commit `47034eb` — harness scaffold only,
no production code changes from backlog-402/403/404/405 yet). Numbers establish the
"before" line; subsequent after-NNN phases will measure deltas.

| target | claude_picks | exec_plan_disp | exec_plan_ok | captures | chain_findings | high+crit | runtime_min | status |
|---|---:|---:|---:|---:|---:|---:|---:|---|
| mantis | 0 | 0 | 0 | 0 | 0 | 0 | 2.7 | ran |
| mediawiki | 0 | 0 | 0 | 0 | 0 | 0 | 3.0 | ran |
| roundcube | 0 | 0 | 0 | 0 | 0 | 0 | 2.9 | ran |
| gitea | 0 | 0 | 0 | 0 | 0 | 0 | 2.8 | ran |
| etherpad | 0 | 0 | 0 | 0 | 0 | 0 | 2.7 | ran |

## Phase verdict: observational only (no PASS/FAIL evaluation at phase=baseline)

- Targets meeting gate criteria: 0/5
- Targets skipped: 0
- Total wall-clock: ~14 min (5 sequential runs averaging 2.8 min each)

## Empirical reading

All 5 targets show **0 across every metric**. On raw HEAD against production-class
OSS apps that AegisPT has not been tuned for, the autonomous-intrusive loop produces:

- **0 Claude picks** — the rule-based `next_best_action_selector` handled all decisions (consistent with the diagnosis of run `3e2cfa5b` on 2026-05-19).
- **0 exec_plan dispatches** — Claude was never given (or never produced a viable) chain-attack plan.
- **0 captured_value entities** — no chain primitives emitted (exec_plan never ran successfully).
- **0 chain_findings** — no findings whose evidence references ≥2 distinct task outputs.
- **0 high_or_critical_findings** — no severe vulnerabilities surfaced.
- **0 high+crit** — the system produced no actionable security signal on any target.

This is the operator-stated problem in numerical form: "AI is uitgebouwd maar wordt niet gebruikt zoals het hoort." Pre-sprint, on real-world targets, the AI loop empirically delivers nothing.

## Acceptance criteria status (per backlog-406)

| Criterion | Status |
|---|---|
| Harness script + grep-guard tests + docs/validation/ exist | ✓ |
| Baseline report produced on raw HEAD on 5 targets | ✓ (this file) |
| No target hostname literals in production source | ✓ (`pytest tests/test_multi_target_validation_grep_guard.py` 3/3) |
| Idempotent + reproducible | ✓ (defensive `docker rm -f` on entry + finally teardown) |
| backlog-397 SUBSUMED-BY closure | ✓ (logged in DONE_LOG + TASK_QUEUE) |
| Sprint-gate PASS evaluation | N/A this phase (deferred to after-405 run) |

## Notes on operator-class concerns surfaced during execution

1. **Mantis image tag drift**: `vimagick/mantisbt:2.21` does not exist on Docker Hub; harness gracefully skipped. Switched to `vimagick/mantisbt:latest` (current Mantis version, still pre-EOL). Per backlog-406's "or compatible" clause this is acceptable.
2. **`dispatch_after_create=True` returned 409 in run creation**: harness fix flipped to False (we drive via `/iterate` anyway). Committed in `47034eb`.
3. **`httpx.HTTPStatusError` lost response body**: harness fix added `_raise_with_body()` helper. Committed in `47034eb`.
4. **No mantis pull retry / multi-tag fallback yet**: a hardened future version could try `:latest` automatically if a pinned tag 404s. Out of scope for this task (operator can swap tags manually if needed).
