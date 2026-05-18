# Active Task

## Title

Auth-recipe cache eviction policy + schema migration path (closes the \#327 silent-fail gap) (backfill 5 of 6)

## Goal

\#327 made `store_recipe` REJECT new entries when the 50 KB dir cap engages — no eviction, no LRU, just permanent rejection. Once the cache is full, NEW fingerprints get an absent verdict forever and pay the Claude Haiku call on EVERY run. Same problem: `schema_version` mismatch returns absent (forward-compat), but there is no migration path — older recipes are simply ignored forever (re-paying the AI call) until manually deleted. This task adds (a) an LRU eviction policy when the dir cap engages, keyed on `last_confirmed_at`, and (b) a schema-migration hook that upgrades v1→v2 recipes in place on first read (or marks them for re-derivation in a bounded way) instead of silently discarding them.

## Scope

- Extend `api/app/services/auth_discoverer.py` `store_recipe()`: when dir-cap is breached, instead of returning False, evict the N oldest entries (by `last_confirmed_at`, falling back to `created_at`) until the new entry fits, then proceed. Cap eviction at 25% of entries per call to prevent thrashing.
- Add `_migrate_recipe(recipe_dict, *, target_schema_version)` that handles known version-up patterns (v1→v2 field renames if any exist by then); for unknown source versions, return None and log a single warning per fingerprint per process (not per call).
- Update `lookup_recipe` to call `_migrate_recipe` before returning fresh.

## Constraints

- Eviction + migration ONLY. Do NOT change the 2 KB per-file cap (\#327 contract), do NOT change the 50 KB dir cap (\#327 contract), do NOT alter the verdict vocabulary (`fresh`/`stale`/`absent` — \#327 contract), do NOT touch the `build_recipe` AI path (\#326 contract).
- Eviction caps at 25% of entries per `store_recipe` call to prevent thrashing under churn.
- If two entries have the SAME `last_confirmed_at`, evict the one with the lower confidence score; ties beyond that → evict neither (force the store call to return False rather than make an arbitrary choice).
- Calling `_migrate_recipe` on an already-migrated recipe is a no-op (returns input unchanged).
- Must NOT touch: `api/app/services/memory_backend.py` public API, `build_recipe` / `fingerprint_application` / `verify_recipe` (\#325/\#326 contracts), the 5 migrated probes (they consume the cache through `lookup_recipe` unchanged), `workers/runners/`, `workers/orchestration/`.

## Source Package

`codex/tasks/backlog-396-auth-recipe-cache-eviction.json`

## Reference

- `api/app/services/auth_discoverer.py` — existing `store_recipe`, `lookup_recipe`, `mark_recipe_stale`, `verify_recipe`, `_list_cache_files`, `_current_cache_size_bytes`
- `api/tests/test_auth_discoverer_cache.py` — 29 existing tests must continue to pass; new eviction + migration tests added here
- DONE_LOG entry for \#327 (Auth Pattern Cache) for the cache contract this task extends

## Validation

- `python3 scripts/validate_backlog_tasks.py`
- `.venv/bin/pytest api/tests/test_auth_discoverer_cache.py api/tests/test_auth_discoverer_recipe.py api/tests/test_auth_discoverer.py api/tests/test_auth_discoverer_acquire_session.py`
- `python3 -m compileall -q api`
- `.venv/bin/ruff check api/app/services/auth_discoverer.py`
- `git diff --check`
