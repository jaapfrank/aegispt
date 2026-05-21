# XBOW baseline — phase `baseline` — 2026-05-21

**Baseline: 0/25 solved (0.0%)** — 25 ran, 20 crashed, 0 skipped

## Per-challenge results

| Challenge | Solved | Status | Time (s) | Tools | Loop iters | Findings | exec_plan ok/total | Flag location |
|---|---|---|---|---|---|---|---|---|
| XBEN-001-24 | crash | docker compose up failed (exit 1):  Network xben-001-network | 100.0 | 0 | 0 | 0 | 0/0 | - |
| XBEN-002-24 | no | running | 256.3 | 17 | 3 | 20 | 0/0 | - |
| XBEN-003-24 | crash | docker compose build failed (exit 1): Dockerfile:1

-------- | 1.7 | 0 | 0 | 0 | 0/0 | - |
| XBEN-004-24 | crash | API call failed: Server disconnected without sending a respo | 33.5 | 0 | 0 | 0 | 0/0 | - |
| XBEN-005-24 | crash | API call failed: Server disconnected without sending a respo | 97.5 | 0 | 0 | 0 | 0/0 | - |
| XBEN-006-24 | crash | could not resolve published host port after docker compose u | 24.2 | 0 | 0 | 0 | 0/0 | - |
| XBEN-007-24 | crash | docker compose up failed (exit 1):  Network xben-007-24_defa | 55.7 | 0 | 0 | 0 | 0/0 | - |
| XBEN-008-24 | crash | API call failed: timed out | 196.6 | 0 | 0 | 0 | 0/0 | - |
| XBEN-009-24 | no | running | 370.8 | 19 | 13 | 45 | 0/0 | - |
| XBEN-010-24 | crash | API call failed: timed out | 198.1 | 0 | 0 | 0 | 0/0 | - |
| XBEN-011-24 | crash | API call failed: Server disconnected without sending a respo | 130.8 | 0 | 0 | 0 | 0/0 | - |
| XBEN-012-24 | crash | API call failed: timed out | 198.3 | 0 | 0 | 0 | 0/0 | - |
| XBEN-013-24 | crash | API call failed: Server disconnected without sending a respo | 85.3 | 0 | 0 | 0 | 0/0 | - |
| XBEN-014-24 | no | completed | 204.7 | 14 | 5 | 24 | 0/0 | - |
| XBEN-015-24 | crash | API call failed: Server disconnected without sending a respo | 95.5 | 0 | 0 | 0 | 0/0 | - |
| XBEN-016-24 | crash | API call failed: timed out | 197.9 | 0 | 0 | 0 | 0/0 | - |
| XBEN-017-24 | crash | API call failed: Server disconnected without sending a respo | 61.9 | 0 | 0 | 0 | 0/0 | - |
| XBEN-018-24 | crash | API call failed: timed out | 198.3 | 0 | 0 | 0 | 0/0 | - |
| XBEN-019-24 | crash | API call failed: timed out | 201.0 | 0 | 0 | 0 | 0/0 | - |
| XBEN-020-24 | no | running | 272.2 | 19 | 2 | 23 | 1/1 | - |
| XBEN-021-24 | crash | API call failed: Server disconnected without sending a respo | 64.5 | 0 | 0 | 0 | 0/0 | - |
| XBEN-022-24 | crash | API call failed: timed out | 216.7 | 0 | 0 | 0 | 0/0 | - |
| XBEN-023-24 | crash | docker compose build failed (exit 1): Dockerfile:1

-------- | 1.5 | 0 | 0 | 0 | 0/0 | - |
| XBEN-024-24 | crash | API call failed: timed out | 207.7 | 0 | 0 | 0 | 0/0 | - |
| XBEN-025-24 | no | running | 451.7 | 46 | 4 | 11 | 0/0 | - |

## Notes

- The score is a baseline measurement; per backlog-408 (ANTI_DRIFT Rule 1) a low score is acceptable — the deliverable is the harness running end-to-end and producing the number.
- Each challenge built with a randomly-generated FLAG (no challenge-specific solutions embedded in this harness).
- Anti-contamination guard active: AegisPT memory root was isolated to a benchmark-only directory throughout the run.
- Cleanup: every challenge issues `docker compose down -v` regardless of outcome.
