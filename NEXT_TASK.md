# Active Task

## Title

auth_discoverer: discover register/login from target_intel hints + index link-scan, not just a hardcoded REGISTER_PATHS list (live-reliability fix 2 of 3)

## Goal

`auth_discoverer.fetch_auth_pages` probes a hardcoded list of 15 register-paths + 13 login-paths. When a target's real auth endpoints are NOT in that list (Gruyere's `signup.gtl` + `saveprofile?action=new`; most production apps with `/account/new` variants, `/users` POST endpoints, SPA-routed `#/signup`, framework-specific paths like Rails `/users/sign_up`, ASP.NET `Account/Register`), `fingerprint_application` returns `register_form=None`. `acquire_session()` then returns `None`, and the 5 \#328-migrated probes that consume it no-op with 0 findings.

Live Gruyere 2026-05-18 confirms this: 16 pages fetched (Gruyere serves HTTP 200 on every path — soft-404), 0 with a register form, fingerprint says `register_form=None`. The actual Gruyere register endpoint is `/signup.gtl` — `.gtl` paths were specifically stripped "for generality" in \#328 and the generic catalog covers 0% of Gruyere's auth surface.

## Scope

- Extend `api/app/services/auth_discoverer.fetch_auth_pages` to derive its probe-path set from TWO sources additive to the existing catalog:
  - (1) URLs in the target's homepage HTML that text-match `REGISTER_LINK_KEYWORDS` / `LOGIN_LINK_KEYWORDS` (the existing link-scan in lines 292-340 already does this but is bounded by `probe_limit + 5` AND only fires when the index path is the FIRST candidate)
  - (2) Stack-specific extensions injected from `target_intel` observations — if `stack_hints` contains `python_gruyere`, append `signup.gtl` + `saveprofile`; for `aspnet_webforms` append `Account/Register.aspx`; for `rails`, `/users/sign_up`; for `django`, `accounts/signup`
- When `fingerprint_application` returns `register_form=None` BUT a form exists on a page classified as `kind=register` (even if score < threshold), elevate it to `register_form` rather than discard

## Constraints

- Additive paths only — do NOT remove anything from the existing `REGISTER_PATHS` / `LOGIN_PATHS` catalogs (they still work for the apps they cover). Do NOT add app-specific RECIPES; only path-DISCOVERY hints. The recipe construction stays Claude-driven via `build_recipe`.
- Per `feedback_no_prescriptive_recipes`: a `signup.gtl` path-string is a discovery hint, not an exploit recipe. The probes still need `build_recipe` / `acquire_session` to learn the form fields + flow. We're only saying "try this path too", not "send is_admin=True to this path".
- Tighten the existing index-page link-scan: when the index returns 200 + a body, scan ALL anchor hrefs (not just the first `probe_limit + 5`), and ALWAYS include matched register/login candidates even if they put us over probe_limit. Probe limit was meant to bound NETWORK cost, not discovery breadth.
- Must NOT touch: `build_recipe` (\#326 contract — still synthesizes recipes from fingerprint), 5 migrated probes (consume `acquire_session` unchanged), `workers/runners/target_intel/runner.py` (we only READ its observations; no signature change), `memory_backend` / cache layer (\#327 contract), `_AI_PICKER_SYSTEM_PROMPT`.

## Source Package

`codex/tasks/backlog-399-auth-discoverer-app-specific-paths.json`

## Reference

- `api/app/services/auth_discoverer.py` — existing `fetch_auth_pages` lines 163-340 (probe loop + link-scan), `fingerprint_application` line 568, `REGISTER_LINK_KEYWORDS` / `LOGIN_LINK_KEYWORDS` regex
- `workers/runners/target_intel/runner.py` — produces `EvidenceObservation` rows with `stack_hints` / `technology_stack` in `attributes_json` (read-only consumer)
- Live Gruyere diag from 2026-05-18: 16 pages fetched (all 200, soft-404), 0 with form, register_form=None
- backlog-398 / \#336 just landed — assessment_planner now respects `autonomous_intrusive_allowed`. This unblocks the exec_plan path the live re-test will exercise once \#337 + \#338 ship.

## Validation

- `python3 scripts/validate_backlog_tasks.py`
- `.venv/bin/pytest api/tests/test_auth_discoverer.py api/tests/test_auth_discoverer_acquire_session.py api/tests/test_auth_discoverer_recipe.py api/tests/test_auth_discoverer_cache.py api/tests/test_auth_discoverer_credentialed.py`
- `python3 -m compileall -q api`
- `.venv/bin/ruff check api/app/services/auth_discoverer.py`
- `git diff --check`
