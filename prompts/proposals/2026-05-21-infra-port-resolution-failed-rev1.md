approve: false
title: infra:port_resolution_failed
change_kind: infra
target_component: scripts/xbow_benchmark.py (compose pre-flight / normalizer)
generated_at: 2026-05-21
affected_challenge_count: 1

## Failure pattern

**Mode:** `port_resolution_failed`
**Affected challenges:** XBEN-006-24

**Representative error:**

```
could not resolve published host port after docker compose up
```

## Root-cause hypothesis

Could not resolve published host port after docker compose up

## Proposed change

1 challenges had short-form `ports: - <container>` but the runtime port query returned no published mapping. Add a fallback that calls `docker compose port <service> <container>` directly when `docker compose ps --format json` returns no Publishers.

## Operator approval checklist

- [ ] Read the affected challenges list above; the pattern is real, not a one-off.
- [ ] The proposed change does not violate any ANTI_DRIFT rule (review).
- [ ] Change is reversible OR has a clear rollback path.
- [ ] Flip `approve: false` → `approve: true` only when all 3 boxes are checked.

After approval, run:

```
python3 scripts/aegispt_promote_proposal.py <this-file> --approver <your-handle>
```
