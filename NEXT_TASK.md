# Active Task

## Title

Auth Pattern Cache Backed by Claude Memory Store

## Goal

Add a per-engagement cache layer over `auth_discoverer` so successful recipes are stored against the application fingerprint and reused on subsequent runs against similar targets. Cache contents persist via the existing Claude memory backend at `/memories/auth-recipes/<fingerprint-hash>.json`.

## Scope

- Extend `api/app/services/auth_discoverer.py` with `lookup_recipe(fingerprint)` and `store_recipe(fingerprint, recipe, confidence)`.
- Uses `memory_backend.execute` as storage.
- Includes confidence scoring, `last_confirmed_at` timestamp, replay-verification before trust, and aging so stale recipes are not returned.

## Constraints

- Cache for auth recipes only. Do NOT generalize cache for other attack patterns in this task. Do NOT migrate probes (task #328).
- Scope isolation: cache is per-engagement. No cross-engagement or cross-tenant sharing.
- Size cap: each recipe file under 2 KB. Total `/memories/auth-recipes/` under 50 KB.
- Aging: recipes older than 30 days OR with last replay failure within last hour MUST be returned as stale to caller (caller may then trigger fresh discovery).

## Source Package

`codex/tasks/backlog-377-auth-pattern-cache-memory-backend.json`

## Reference

- `api/app/services/auth_discoverer.py` (#325 fingerprint + #326 build_recipe — both merged)
- `api/app/services/memory_backend.py`
- `docs/AGENT_SYSTEM_MAP.md` section 12

## Validation

- `python3 scripts/validate_backlog_tasks.py`
- `.venv/bin/pytest api/tests/test_auth_discoverer_cache.py`
- `python3 -m compileall -q api`
- `.venv/bin/ruff check api/app/services/auth_discoverer.py`
- `git diff --check`
