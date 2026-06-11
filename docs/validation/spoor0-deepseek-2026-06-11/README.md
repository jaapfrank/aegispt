# Spoor 0 live proof — system resurrected off the single-Claude dependency (2026-06-11)

**Claim:** the `picker_retry_exhausted` death (100% of runs for ~10h, because the picker was
pinned to Anthropic and Claude credits were exhausted) is fixed. The system now runs
end-to-end on DeepSeek (uncensored, no GPU, no Claude) via the new picker failover chain.

## Before (old code, Anthropic-pinned)

```
2026-06-11 03:10:03 WARNING assessment_loop: AI loop: picker exhausted retries (3 attempts)
2026-06-11 03:10:03 INFO    assessment_loop: finalized run=b017d979 status=completed
                            stop_reason=picker_retry_exhausted (tasks: 12 completed, 0 failed)
```
Every run finalized with `stop_reason=picker_retry_exhausted`. Root cause: the Claude picker
(hardcoded `model="claude-opus-4-8"`) returned HTTP 400 "credit balance too low"; no failover.

## After (this branch, DeepSeek failover)

Loaded code carries the new branch (verified on the running service):
```
_claude_select_next_action source contains "deepseek" + "_picker_provider_chain": True
```

Run on `--llm-provider deepseek-v3` (engagement b7c5386a, run d47d8ccc, XBEN-080-24, source-aware):

- The picker drives the loop on DeepSeek — repeated successful calls:
  ```
  2026-06-11 05:44:13 INFO httpx: POST https://api.deepseek.com/v1/chat/completions "HTTP/1.1 200 OK"
  2026-06-11 05:45:24 INFO httpx: POST https://api.deepseek.com/v1/chat/completions "HTTP/1.1 200 OK"
  2026-06-11 05:48:52 INFO httpx: POST https://api.deepseek.com/v1/chat/completions "HTTP/1.1 200 OK"
  ```
- **Zero** `PROVIDER_UNHANDLED provider_kind=deepseek` after the restart that loaded this code
  (was logged every iteration on the old code).
- **Zero** `picker_retry_exhausted` on the DeepSeek runs.
- Tasks completed on DeepSeek (DB, engagement b7c5386a): target-intel, pre-recon-source,
  content-discovery, smart-web-probe, headers-security, xss-extended x4, exec-plan x3.

## Honest gap (model quality, not infrastructure)

DeepSeek runs the loop but did **not** reproduce the XBEN-080 SSTI *solve* gpt-5.5 got: its
picker chose exec-plan / xss-extended instead of the SSTI -> interactive-exploit gate path, so
no flag was captured this run. That is a brain-quality difference, **separate from Spoor 0**:
the infrastructure (off-Claude, failover, runs end-to-end) is proven; the strongest
non-refusing solve brain is the local GPU model, which is currently blocked on operator sudo
(nvidia-container-toolkit not installed — `--gpus` passthrough fails). See STATE.md.

## Unit proof
- `api/tests/test_picker_provider_failover.py` — 8/8 green (chain ordering, Anthropic-last,
  explicit-first, cred filtering, env override, DeepSeek detection).

## Reproduce
```
set -a; . ~/.aegispt-secrets; set +a
.venv/bin/python scripts/xbow_benchmark.py --xbow-repo ~/xbow-validation-benchmarks \
  --target XBEN-080-24 --max-challenges 1 --source-aware --llm-provider deepseek-v3 \
  --wait-seconds 1000 --out-dir /tmp/xbow-out-proof
# observe /tmp/aegispt-api.log: api.deepseek.com 200 OK, no picker_retry_exhausted
```
