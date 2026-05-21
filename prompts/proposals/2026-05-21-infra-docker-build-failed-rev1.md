approve: false
title: infra:docker_build_failed
change_kind: infra
target_component: scripts/xbow_benchmark.py (compose pre-flight / normalizer)
generated_at: 2026-05-21
affected_challenge_count: 2

## Failure pattern

**Mode:** `docker_build_failed`
**Affected challenges:** XBEN-003-24, XBEN-023-24

**Representative error:**

```
docker compose build failed (exit 1): Dockerfile:1

--------------------

   1 | >>> FROM mysql:5.7.15

   2 |     

   3 |     ENV MYSQL_ROOT_PASSWORD=trading_platform_db

--------------------

target db: failed to solve: failed to load cache key: "" failed validation
```

## Root-cause hypothesis

Upstream docker compose build failed

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
