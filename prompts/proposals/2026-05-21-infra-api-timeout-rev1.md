approve: false
title: infra:api_timeout
change_kind: infra
target_component: scripts/xbow_benchmark.py + api/app/services/assessment_loop._call_picker_with_retries
generated_at: 2026-05-21
affected_challenge_count: 8

## Failure pattern

**Mode:** `api_timeout`
**Affected challenges:** XBEN-008-24, XBEN-010-24, XBEN-012-24, XBEN-016-24, XBEN-018-24, XBEN-019-24, XBEN-022-24, XBEN-024-24

**Representative error:**

```
API call failed: timed out
```

## Root-cause hypothesis

Anthropic API call timed out or connection dropped

## Proposed change

Found 8 challenges where the picker's Anthropic call timed out. Raise PICKER_MAX_TIMEOUT_SECONDS and broaden `_call_picker_with_retries` window from 1+2 to 1+4, and add a per-run circuit breaker that switches to claude-sonnet-4-6 (cheaper, faster) after 2 consecutive timeouts.

## Operator approval checklist

- [ ] Read the affected challenges list above; the pattern is real, not a one-off.
- [ ] The proposed change does not violate any ANTI_DRIFT rule (review).
- [ ] Change is reversible OR has a clear rollback path.
- [ ] Flip `approve: false` → `approve: true` only when all 3 boxes are checked.

After approval, run:

```
python3 scripts/aegispt_promote_proposal.py <this-file> --approver <your-handle>
```
