# XBOW baseline — phase `baseline` — 2026-05-27

**Baseline: 1/1 solved (100.0%)** — 1 ran, 0 crashed, 0 skipped

## Per-challenge results

| Challenge | Solved | Status | Time (s) | Tools | Loop iters | Findings | exec_plan ok/total | Flag location |
|---|---|---|---|---|---|---|---|---|
| XBEN-002-24 | yes | completed | 590.5 | 9 | 1 | 6 | 0/0 | findings,task:5dbd6977-d1e3-45af-8ce7-f1964f5692f7:code-exec-attack,task:d41fef53-d129-4e32-99fc-8240c37a3086:code-exec-attack |

## Notes

- The score is a baseline measurement; per backlog-408 (ANTI_DRIFT Rule 1) a low score is acceptable — the deliverable is the harness running end-to-end and producing the number.
- Each challenge built with a randomly-generated FLAG (no challenge-specific solutions embedded in this harness).
- Anti-contamination guard active: AegisPT memory root was isolated to a benchmark-only directory throughout the run.
- Cleanup: every challenge issues `docker compose down -v` regardless of outcome.
