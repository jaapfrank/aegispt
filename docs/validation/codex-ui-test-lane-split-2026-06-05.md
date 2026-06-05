# Codex UI Test Lane Split Validation

Date: 2026-06-05

## Scope

Codex split the UI test commands so legacy `/app` tests and React `/app-v2`
tests no longer share a misleading harness.

## Change Summary

- `scripts/run_app_tests.sh` runs only legacy `/app` Python/pytest Playwright
  smoke tests from `ui/tests`.
- `scripts/run_app_v2_tests.sh` builds `ui-v2`, runs the i18n checker, and runs
  Node Playwright tests from `ui-v2/tests`.
- `scripts/run_ui_fast_tests.sh` remains as a compatibility wrapper for legacy
  `/app` fast tests only.
- `.github/workflows/ci.yml` calls the legacy `/app` test script by name.
- `.github/workflows/app-v2-tests.yml` is the React `/app-v2` CI target.
- `scripts/tests/test_ui_test_split_scripts.py` prevents the v2 build/test path
  from being reintroduced into the legacy fast-test wrapper.

## Validation

Completed locally:

- `bash -n scripts/run_app_tests.sh scripts/run_app_v2_tests.sh scripts/run_ui_fast_tests.sh`
- `python3 -m pytest -q scripts/tests/test_ui_test_split_scripts.py`
- `bash scripts/run_app_v2_tests.sh tests/i18n.spec.ts`
- `bash scripts/run_app_tests.sh` was attempted against the legacy `/app`
  smoke files and reached the legacy browser tests without building React v2;
  current legacy result was `54 passed, 5 failed, 4 errors`
- `python3 scripts/validate_backlog_tasks.py`
- `git diff --check`

Legacy residual failures were in existing `/app` UI expectations and fixture
startup/import behavior, including `conversation-question` visibility,
`/app/assets/modules/settings.js` dynamic imports during settings tests, and
actor/API-key state assertions. They are not caused by React v2 build/test
coupling; the split regression test verifies that `run_app_tests.sh` no longer
references `ui-v2` or `build_ui_v2.sh`.
