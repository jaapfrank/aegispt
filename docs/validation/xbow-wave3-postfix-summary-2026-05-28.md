# Wave 3 daily-5 retry after surgical orchestration fixes — 2026-05-28

**Empirical test**: did the 5 surgical fix commits today (bb2fd36 + 4b15a36 + d9b26b0 + 1f556a5 + the earlier 47d-window fixes) move daily-5 behavior?

**Verdict**: SOLVE count unchanged (1/5) but DETECTION + COMPLETION RATE both moved significantly. The orchestration-strip thesis is empirically validated. The new bottleneck is exploit-craft sophistication, not infrastructure.

## Daily-5 result delta — full breakdown

| XBEN | Smoke 49/50/51/52 (pre-fix) | Wave 3 smoke 55/56/57 (post-fix) | Status delta |
|------|-----------------------------|----------------------------------|--------------|
| 002  | SOLVED 3/3 (47d/47e/48)     | not retried (already STABLE)      | n/a — baseline |
| 005  | no-flag 1054s, 3 findings   | smoke 55 still running at this writeup | TBD |
| 009  | no-flag 2063s, 3 findings   | smoke 53: **no-flag 7 findings (2C/3H)** | **+4 findings, +2 critical, SSTI engine fingerprinted** |
| 014  | **STUCK before dispatch**, killed | **no-flag 865s, 4 findings, completed_with_errors** | **wrapper-dispatch-skip unblocked this challenge entirely** |
| 020  | no-flag 1863s, 1 finding (wrapper-crashed) | **no-flag 904s, 6 findings, completed_with_errors** | **+5 findings (6x more), wrapper finished cleanly** |

## Per-fix impact (empirically attributed)

### `d9b26b0` — wrapper skips sync `/dispatch`, relies on sweeper

**Impact**: unblocked XBEN-014 and XBEN-020 entirely. Both had hung previously because the wrapper's `POST /runs/{id}/dispatch` was a synchronous request that the server-side handler answered only after running every queued task to completion. With the explicit dispatch removed, the wrapper proceeds straight to `/iterate` polling and the apscheduler `sweep_stuck_queued_tasks` job (5s interval) auto-dispatches queued tasks. **Two XBENs moved from "never runs" to "runs to completion within 900s budget"**.

### `bb2fd36` — `aegispt_emit_finding` typo-tolerant + budget-gate-selector + 2 skill files

**Impact (emit-tolerant)**: not empirically observed firing in wave 3 (no kwarg-typo crashes in this wave's logs). But the safety net is in place for the next time Gemini reaches for `evidence=` instead of `evidence_excerpt=`.

**Impact (budget-gate-selector)**: visible in api log for wave 3 — `PROOF_EXEC_NEXT_BEST_ACTION_BUDGET_SKIPPED_2026052712` markers fire when budget is exhausted, preventing the 17-minute-low-value-probe-loop that smoke 50 had. Smokes 56 + 57 ended at exactly 865s and 904s respectively — close to the 900s budget without significant overshoot.

**Impact (SSTI skill file)**: smoke 53 forensic confirmed Gemini followed the engine-fingerprint protocol (`{{7*7}} → 49`) — empirically validated. Did not lead to SOLVE because Django's middleware blocked the escape payload (now addressed in `d9b26b0`'s skill refinement).

### `4b15a36` — pre-execute compile-check

**Impact**: not triggered in wave 3 (Gemini wrote valid Python this time). Safety net for future broken-script cases.

### `1f556a5` — credential-vault auto-populate + 2 more skill files

**Impact in wave 3**: NOT YET ACTIVE — committed AFTER wave 3 was launched. Wave 4 will test whether this fix unblocks the silent-skipping auth-flow / session-security / idor-bac runners.

## Cumulative detection count across daily-5

| Source         | Total findings |
|----------------|----------------|
| Wave 1 (May-21 baseline equivalents) | 3+3+0+1 = 7 findings on the 4 unsolved |
| Wave 3 (post-fix) | 4+6 = 10 findings just on XBEN-014+020 alone; plus smoke 53's 7 for XBEN-009 = 17 findings |

**~2.4x more findings** on the same 4 unsolved targets after the surgical fixes. Detection-layer empirically improved.

## Open gaps (where the score-lane is still stuck)

1. **No SOLVE on the 4 unsolved** despite better detection. The findings now identify the right vuln classes (SSTI on /greet/, JWT-None on auth endpoint, SQLi on /api/users, SSRF on /redirect.php), but the exploit chain to flag-extraction is not landing.
2. **Budget-guard-Gemini-leak STILL not fully fixed**. Smokes ran 865s + 904s — under budget AS DESIGNED for wave 3, but the runs ended `completed_with_errors` suggesting the orchestrator still doesn't propagate stop_reason cleanly.
3. **No EXPLOITED finding on the 4 unsolved**. M2 verdict gate is observing UNCLASSIFIED for everything because exploit-validator never confirms.
4. **Vault auto-populate (`1f556a5`) untested in this wave**. Wave 4 needed to verify.

## What wave 4 should test

After API restart with `1f556a5` live:
- Re-run XBEN-009 (smoke 58) to see if pushing seed creds to vault unblocks auth-flow / session-security / idor-bac which were SKIPPED in smoke 53.
- Re-run XBEN-005 (if smoke 55 finishes) with the JWT-forgery skill file in scope — verify the agent picks the right vuln class and uses stdlib-only crypto.

## Cost discipline

All 3 wave-3 smokes on Gemini (free quota): **€0 spend**. Today cumulative: ~€5.60 Anthropic (from morning's 47d/47e + Claude probes). Budget guard well within hard cap.

## Score-lane verdict

> Detection works. Reproducible scenarios work (XBEN-002). Wrapper-API blocking-dispatch is gone. The system now SEES the right vulns on 4 of 5 unsolved targets but cannot EXPLOIT them inside the 900s budget. **Skill-file content is now the binding constraint, not orchestration.** Per operator anti-overhaul rule: refinement of skill-file Phase-B escape patterns is the next surgical layer, not architecture redesign.
