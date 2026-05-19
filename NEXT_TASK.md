# Active Task

## Title

Probe path-catalogs are stack-aware: target_intel observations augment info_disclosure / file_upload / param_pollution / cookie_tamper / stored_xss PROBE_PATHS at runtime (live-reliability fix 3 of 3)

## Goal

The 5 \#328-migrated probes (`info_disclosure_probe` / `stored_xss_probe` / `file_upload_probe` / `param_pollution_probe` / `cookie_tamper_probe`) each carry a hardcoded path catalog. \#328 stripped Gruyere-specific `.gtl` paths "for generality", but the generic catalog covers 0% of Gruyere's surface on live testing (verified 2026-05-18: `/dump.gtl` returns HTTP 200 with `_cookie: {'is_admin': False, 'is_author': False, 'uid': None}` — a textbook info-disclosure leak — but our catalog doesn't probe that path).

This task makes the catalogs stack-aware: `target_intel` observations carry `stack_hints`; the probes consult those hints to augment their paths at runtime. No Gruyere-specific seed in the runner source — the augmentation lives in a registry keyed on stack_hint values.

## Scope

- New module `workers/runners/_path_augmentation.py` exposing `paths_for_stack(stack_hints: list[str], category: str) -> list[tuple[str, str]]`. Category covers `debug-dump` / `file-upload-target` / `register-action` / `mass-assignment-target` / `cookie-name`.
- Stack registry maps known hints:
  - `python_gruyere` → `.gtl` debug paths
  - `java_jsp` → `/admin/console.jsp`
  - `aspnet` → `/elmah.axd`, `/trace.axd`
  - `php` → `/info.php`, `/phpmyadmin/`
  - `node_express` → `/.well-known/express-status`
- Each of the 5 probes calls `paths_for_stack(stack_hints, category)` and merges with its hardcoded base catalog.
- `stack_hints` come from `EvidenceObservation` rows with `entity_type=stack_hint` or `attributes_json['technology_stack']`, written by target_intel.

## Constraints

- New `_path_augmentation` module + 5 small probe-side consumers. Do NOT change the existing hardcoded base catalogs (they keep working for the stacks they cover). Do NOT add app-instance-specific paths (e.g. Gruyere's per-user instance ID); only stack-family-level paths (e.g. `.gtl` for the python_gruyere family).
- Per `feedback_no_prescriptive_recipes`: a path like `/dump.gtl` is a discovery hint, not an exploit recipe. We're saying "look here too", not "send this specific payload to this path". The probes still apply their existing detection heuristics on whatever the path returns.
- `stack_hints` MUST come from `target_intel`-emitted `EvidenceObservation` rows (`entity_type='stack_hint'` or `attributes_json['technology_stack']`). Do NOT seed stack_hints from the probe runner itself or from hardcoded URL pattern matching — the AI/recon stage owns stack detection.
- Must NOT touch: `target_intel` runner (we only consume its observations), `build_recipe` (\#326), `acquire_session` (\#328a — was fixed in backlog-399). Anti-pattern: NO seeding of `/saveprofile?action=new` style payload-bearing patterns. Only path strings.

## Source Package

`codex/tasks/backlog-400-probe-path-stack-augmentation.json`

## Reference

- `workers/runners/info_disclosure_probe/runner.py` — existing PROBE_PATHS (51 entries, none match Gruyere)
- `workers/runners/{stored_xss,file_upload,param_pollution,cookie_tamper}_probe/runner.py` — 4 other probes with similar hardcoded path patterns
- `workers/runners/target_intel/runner.py` — produces `EvidenceObservation` with `technology_stack` (read-only consumer)
- `api/app/services/auth_discoverer.py` — already has `_STACK_REGISTER_PATHS` / `_STACK_LOGIN_PATHS` pattern (#337 landed today); follow that shape

## Validation

- `python3 scripts/validate_backlog_tasks.py`
- `.venv/bin/pytest workers/tests/test_info_disclosure_probe.py workers/tests/test_stored_xss_probe.py workers/tests/test_file_upload_probe.py workers/tests/test_param_pollution_probe.py workers/tests/test_cookie_tamper_probe.py workers/tests/test_path_augmentation.py`
- `python3 -m compileall -q workers`
- `.venv/bin/ruff check workers/runners/_path_augmentation.py workers/runners/info_disclosure_probe/ workers/runners/stored_xss_probe/ workers/runners/file_upload_probe/ workers/runners/param_pollution_probe/ workers/runners/cookie_tamper_probe/`
- `git diff --check`
