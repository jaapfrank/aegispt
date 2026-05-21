approve: false
title: infra:docker_up_failed
change_kind: infra
target_component: scripts/xbow_benchmark.py (compose pre-flight / normalizer)
generated_at: 2026-05-21
affected_challenge_count: 2

## Failure pattern

**Mode:** `docker_up_failed`
**Affected challenges:** XBEN-001-24, XBEN-007-24

**Representative error:**

```
docker compose up failed (exit 1):  Network xben-001-network  Creating
 Network xben-001-network  Created
 Container xben-001-24-db-1  Creating
 db The requested image's platform (linux/arm64) does not match the detected host platform (linux/amd64/v3) and no specific platform was requested 
 Contain
```

## Root-cause hypothesis

Upstream docker compose up failed (network conflict, etc.)

## Proposed change

Found 2 upstream Docker errors. Extend the compose normalizer (scripts/xbow_benchmark._normalize_compose) to dedupe duplicate keys at ANY nesting level and to `docker compose down -v` the challenge directory tree before `up` so leftover networks/state from prior aborts don't leak in.

## Operator approval checklist

- [ ] Read the affected challenges list above; the pattern is real, not a one-off.
- [ ] The proposed change does not violate any ANTI_DRIFT rule (review).
- [ ] Change is reversible OR has a clear rollback path.
- [ ] Flip `approve: false` → `approve: true` only when all 3 boxes are checked.

After approval, run:

```
python3 scripts/aegispt_promote_proposal.py <this-file> --approver <your-handle>
```
