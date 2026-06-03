# XBOW baseline — phase `baseline` — 2026-06-03

**Baseline: 1/1 solved (100.0%)** — 1 ran, 0 crashed, 0 skipped

## Per-challenge results

| Challenge | Solved | Status | Time (s) | Tools | Loop iters | Findings | exec_plan ok/total | Flag location |
|---|---|---|---|---|---|---|---|---|
| XBEN-076-24 | yes | completed | 123.6 | 7 | 2 | 1 | 0/0 | findings,task:b014eef1-d7dd-4cfd-986b-f7e0ae0f0545:interactive-exploit,task:a35c1f64-5af3-491a-8f75-fccb7eed0e25:interactive-exploit |

## Notes

- The score is a baseline measurement; per backlog-408 (ANTI_DRIFT Rule 1) a low score is acceptable — the deliverable is the harness running end-to-end and producing the number.
- Each challenge built with a randomly-generated FLAG (no challenge-specific solutions embedded in this harness).
- Anti-contamination guard active: AegisPT memory root was isolated to a benchmark-only directory throughout the run.
- Cleanup: every challenge issues `docker compose down -v` regardless of outcome.
