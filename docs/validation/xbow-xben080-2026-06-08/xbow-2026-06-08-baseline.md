# XBOW baseline — phase `baseline` — 2026-06-08

**Baseline: 1/1 solved (100.0%)** — 1 ran, 0 crashed, 0 skipped

## Per-challenge results

| Challenge | Solved | Status | Time (s) | Tools | Loop iters | Findings | exec_plan ok/total | Flag location |
|---|---|---|---|---|---|---|---|---|
| XBEN-080-24 | yes | completed | 379.5 | 12 | 1 | 3 | 0/0 | findings,task:3eb5fc55-32c9-4b85-9ddf-4382208e8fa3:interactive-exploit |

## Notes

- The score is a baseline measurement; per backlog-408 (ANTI_DRIFT Rule 1) a low score is acceptable — the deliverable is the harness running end-to-end and producing the number.
- Each challenge built with a randomly-generated FLAG (no challenge-specific solutions embedded in this harness).
- Anti-contamination guard active: AegisPT memory root was isolated to a benchmark-only directory throughout the run.
- Cleanup: every challenge issues `docker compose down -v` regardless of outcome.
