# Backlog 169 - Pack Forge Codex Build-Lane Visibility

## Result

Pack Forge now hides Codex build-lane panels by default for normal operators. Adaptive Planning, Pack Summary, Registry, and the pack validate/approve/deploy controls remain visible. A new Settings > Instance checkbox, `instance.build_lane_mode`, exposes the supervised Codex task planner and build-lane output panels for developer/build-lane operation.

## Changed Files

- `api/app/services/settings.py`
- `ui/index.html`
- `ui/assets/modules/packs.js`
- `ui/tests/test_operator_console_smoke_e2e.py`
- `ui/tests/test_product_feature_matrix_e2e.py`

## Validation Evidence

- `python3 scripts/validate_backlog_tasks.py` passed with 193 queued task packages mapped one-to-one and exactly one active task.
- `source .venv/bin/activate && python -m pytest -s -q api/tests/test_health.py` passed.
- `source .venv/bin/activate && python -m pytest -s -q api/tests/test_settings.py` passed.
- `source .venv/bin/activate && python -m pytest -s -q ui/tests/test_operator_console_smoke_e2e.py::test_pack_forge_build_lane_panels_are_gated_by_developer_mode` passed.
- `source .venv/bin/activate && python -m pytest -s -q ui/tests/test_product_feature_matrix_e2e.py::test_pack_forge_surfaces_codex_suggestions_preview_and_prepared_task` passed after explicitly enabling `instance.build_lane_mode`.
- `source .venv/bin/activate && python -m pytest -s -q api/tests/test_product_feature_matrix.py::test_adaptive_pack_pipeline_binds_to_run_and_exports_reports_end_to_end` passed as pack lifecycle regression coverage.
- Live Playwright acceptance against `http://127.0.0.1:8000/app/` passed: default Pack Forge hid both build-lane panels while lifecycle controls stayed visible; browser-state build-lane mode exposed the panels again.
- `git diff --check` passed.

## Blocked / Not Claimed

- `source .venv/bin/activate && python -m pytest api/tests/test_health.py -q` failed with the known local `_pytest/capture.py FileNotFoundError`. The same health tests passed with `-s`, so product health behavior is validated but the normal-capture command is not claimed green.

## Remaining Risk

This slice does not redesign Pack Forge copy, remove Codex functionality, or change pack validation, approval, deployment, runtime binding, or Codex task generation. It only gates operator visibility of the developer build-lane panels.
