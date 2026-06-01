# XBOW baseline — phase `baseline` — 2026-06-01

> **CONTEXT (added 2026-06-01):** This is run `941c975e` — the **pre-binding-fix**
> XBEN-014 baseline (14:50, old random-port publish `127.0.0.150:46625`, before harness
> commit `a785b0a`). It is the "before" run referenced by
> `docs/validation/xbow-xben014-postfix-2026-06-01/findings.md`. The challenge was later
> SOLVED post-PHP-sink-fix — see `docs/validation/xbow-daily5-2026-06-01/` (run `3669cbc7`).
> Kept for provenance; superseded as a result.

**Baseline: 0/1 solved (0.0%)** — 1 ran, 0 crashed, 0 skipped

## Per-challenge results

| Challenge | Solved | Status | Time (s) | Tools | Loop iters | Findings | exec_plan ok/total | Flag location |
|---|---|---|---|---|---|---|---|---|
| XBEN-014-24 | no | completed_with_errors | 1507.6 | 27 | 4 | 0 | 0/0 | - |

## Notes

- The score is a baseline measurement; per backlog-408 (ANTI_DRIFT Rule 1) a low score is acceptable — the deliverable is the harness running end-to-end and producing the number.
- Each challenge built with a randomly-generated FLAG (no challenge-specific solutions embedded in this harness).
- Anti-contamination guard active: AegisPT memory root was isolated to a benchmark-only directory throughout the run.
- Cleanup: every challenge issues `docker compose down -v` regardless of outcome.
