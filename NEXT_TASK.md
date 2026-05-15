# Active Task

## Title

Migrate Five Probes from Gruyere Auth Pattern to Auth Discoverer

## Goal

Refactor `info_disclosure_probe`, `param_pollution_probe`, `stored_xss_probe`, `cookie_tamper_probe`, and `file_upload_probe` to call `auth_discoverer` (cache → fingerprint → AI recipe → verify) instead of their hardcoded `saveprofile?action=new` pattern. Validate that all five produce non-zero findings on at least 2 non-Gruyere targets and continue to find Gruyere R1/R2/R3/R5/R7/R10/R15/R20 on Gruyere.

## Scope

- Replace each probe's local `_register_as_author` / `_register_with_delimiter` logic with a call to the auth_discoverer pipeline (lookup_recipe → build_recipe → verify_recipe → store_recipe).
- Keep each probe's vulnerability-specific testing logic.
- Add an empirical generality test (`scripts/test_probe_generality.py`) that runs each probe against Gruyere + juice-shop + demo.testfire.net + testasp.vulnweb.com and records `findings_count` per `(probe, target)`.
- Update `docs/AGENT_SYSTEM_MAP.md` section 3 to move the 5 probes from "Gruyere-specific" to "Verified-generic" once parity + generality are met.

## Constraints

- Migrate ONLY the named 5 probes. Do NOT touch `xss_proof`, `smart_web_probe`, or other runners.
- No-regression on Gruyere: each migrated probe MUST still find the same vulnerability classes it found before migration (R1/R2/R3/R5/R7/R10/R15/R20 as applicable).
- Test targets: probes must be validated against at least Gruyere + 2 of {juice-shop.herokuapp.com, demo.testfire.net, testasp.vulnweb.com}. Zero-findings is acceptable on targets that lack the vulnerability class, but `attempts > 0` is required.
- Must NOT touch: `api/app/services/assessment_loop.py`, `api/app/services/auth_discoverer.py` core API, `workers/runners/xss_proof/`, `workers/runners/smart_web_probe/`, `workers/orchestration/tasks.py` SUPPORTED_TOOLS set.

## Source Package

`codex/tasks/backlog-378-migrate-five-probes-to-auth-discoverer.json`

## Reference

- `api/app/services/auth_discoverer.py` (#325 + #326 + #327 — all merged)
- `workers/runners/xss_proof/runner.py` (reference for auth-aware probe pattern; do NOT modify)
- `docs/AGENT_SYSTEM_MAP.md` section 3

## Validation

- `python3 scripts/validate_backlog_tasks.py`
- `.venv/bin/pytest workers/tests/test_info_disclosure_probe.py workers/tests/test_param_pollution_probe.py workers/tests/test_stored_xss_probe.py workers/tests/test_cookie_tamper_probe.py workers/tests/test_file_upload_probe.py`
- `python3 -m compileall -q workers`
- `.venv/bin/ruff check workers/runners/info_disclosure_probe workers/runners/param_pollution_probe workers/runners/stored_xss_probe workers/runners/cookie_tamper_probe workers/runners/file_upload_probe`
- `python3 scripts/test_probe_generality.py`
- `git diff --check`
