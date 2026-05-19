# Active Task

## Title

Stack-hint extraction: broaden matching + add explicit `stack_family` field from target_intel so \#338's augmentation actually fires on live targets (live-validation follow-up)

## Goal

Live Gruyere run 2026-05-19 (`3e2cfa5b`) confirmed that \#338's plumbing works (`paths_for_stack` returns correct values; orchestrator threads `stack_hints` via `runner_params`) but the NORMALIZER does not match what `target_intel` actually emits.

`target_intel` produced:

```
technology_stack=['Python/AppEngine (Google Frontend server)',
                  'HTML 4.01 Transitional',
                  'Custom JavaScript (lib.js)',
                  'Custom backend application']
```

NONE of the keywords in `_STACK_KEYWORD_HINTS` (gruyere / tomcat / rails / django / ...) appear. Result: `hints=[]`, no augmentation, `/dump.gtl` never probed. The 0/17 problem on the info-disclosure category persists despite \#338 landing.

Two fixes:

1. **Broaden the keyword table** in `workers/runners/_path_augmentation.py` with App Engine, ASP.NET Core, Spring, Symfony patterns commonly emitted by `target_intel`.
2. **Add explicit `stack_family` field** to `target_intel`'s asset observation — a single registry-key string (`python_gruyere` / `aspnet` / `ruby_rails` / …) derived from Claude's response. `stack_hints_from_observations()` prefers this field when present, falls back to the keyword table when absent.

## Scope

- Extend `_STACK_KEYWORD_HINTS` in `workers/runners/_path_augmentation.py` with patterns: `appengine`, `app engine`, `python/`, `asp.net core`, `spring boot`, `symfony`, `flask`, `fastapi`, etc.
- Update `workers/runners/target_intel/runner.py` to emit `attributes_json['stack_family']` as a single registry-key string from Claude's response (a new field, not a replacement of `technology_stack`).
- `stack_hints_from_observations()` prefers `stack_family` when present, falls back to the keyword table.
- New tests: target_intel emits stack_family; normalizer prefers it; keyword fallback still works.

## Constraints

- Two changes only: broaden normalizer keyword table + add explicit `stack_family` field to `target_intel` asset observation. Do NOT add new categories to the path registry. Do NOT change the 5 probe runners. Do NOT touch the orchestrator wiring.
- Per `feedback_no_prescriptive_recipes`: do NOT add hostname-derived shortcuts (e.g. "if host contains gruyere → python_gruyere"). The hint must come from `target_intel`'s AI analysis of the actual response, not from hardcoded URL patterns. `test_no_gruyere_strings_in_module` must continue to pass.
- `target_intel`'s Claude prompt is updated to ask for a `stack_family` classification using a documented vocabulary (the registry keys). The path-augmentation registry only consumes that classification — it doesn't try to do the classification itself.

## Source Package

`codex/tasks/backlog-401-stack-hint-extraction-broaden.json`

## Reference

- `workers/runners/_path_augmentation.py` — existing `_STACK_KEYWORD_HINTS` + `stack_hints_from_observations` (from \#338)
- `workers/runners/target_intel/runner.py` — existing asset observation emission
- Live run `3e2cfa5b-d74d-4089-b01c-1730a592afbb` — empirical evidence of the gap
- `_STACK_PATH_REGISTRY` keys = the documented stack_family vocabulary

## Validation

- `python3 scripts/validate_backlog_tasks.py`
- `.venv/bin/pytest workers/tests/test_path_augmentation.py workers/tests/test_target_intel_runner.py workers/tests/test_info_disclosure_probe.py`
- `python3 -m compileall -q workers`
- `.venv/bin/ruff check workers/runners/_path_augmentation.py workers/runners/target_intel/runner.py`
- `git diff --check`
- Live re-test on Gruyere (operator-class): `hints` should contain `python_gruyere`, `/dump.gtl` should be probed, info-disclosure finding should be emitted.
