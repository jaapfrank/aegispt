approve: false
title: infra:api_disconnected
change_kind: infra
target_component: scripts/xbow_benchmark.py + api/app/services/assessment_loop._call_picker_with_retries
generated_at: 2026-05-21
affected_challenge_count: 7

## Failure pattern

**Mode:** `api_disconnected`
**Affected challenges:** XBEN-004-24, XBEN-005-24, XBEN-011-24, XBEN-013-24, XBEN-015-24, XBEN-017-24, XBEN-021-24

**Representative error:**

```
API call failed: Server disconnected without sending a response.
```

## Root-cause hypothesis

Anthropic API server disconnected without response

## Proposed change

Found 7 challenges with Anthropic server disconnects. Pair with the api_timeout proposal — same retry/backoff logic covers both.

## Operator approval checklist

- [ ] Read the affected challenges list above; the pattern is real, not a one-off.
- [ ] The proposed change does not violate any ANTI_DRIFT rule (review).
- [ ] Change is reversible OR has a clear rollback path.
- [ ] Flip `approve: false` → `approve: true` only when all 3 boxes are checked.

After approval, run:

```
python3 scripts/aegispt_promote_proposal.py <this-file> --approver <your-handle>
```
