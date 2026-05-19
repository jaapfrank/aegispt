# backlog-171 Report Center Copy Cleanup

## Result

Completed backlog-171. Report Center copy now uses operator-facing language for the report reader, comparison panel, and dossier context. Internal design or developer-facing phrases such as `metadata rail`, `History & Comparison`, `Prior Report Delta`, `Open Explorer Compatibility`, and release-style `now carries` language were removed from the product source touched by this slice.

The visible Report Center heading already used the required copy:

`Review and export technical, executive, and compliance reports for the selected run.`

The comparison empty state now says:

`Select a previous run to compare findings, coverage, and risk score changes.`

The report reader empty states now give one direct action for markdown and HTML preview generation.

## Files Changed

- `ui/assets/modules/reports.js`
- `ui/index.html`
- `ui/tests/test_operator_console_smoke_e2e.py`
- `CURRENT_STATE.md`
- `DONE_LOG.md`
- `NEXT_TASK.md`

## Validation

- `python3 scripts/validate_backlog_tasks.py` passed before implementation with 193 queued task packages and exactly one active task.
- `node --input-type=module --check < ui/assets/modules/reports.js` passed.
- `python3 -m py_compile ui/tests/test_operator_console_smoke_e2e.py` passed.
- `source .venv/bin/activate && python -m pytest -s -q ui/tests/test_operator_console_smoke_e2e.py::test_report_center_copy_is_operator_ready_and_empty_states_are_clear` passed.
- `source .venv/bin/activate && python -m pytest -s -q ui/tests/test_operator_console_e2e.py::test_reports_use_verified_hash_label_and_history_empty_state_is_guided` passed.
- `rg -n "without a side metadata rail|History & Compared|History & Comparison|metadata rail|Prior Report Delta|Open Explorer Compatibility|now carries|Generate a markdown preview to inspect|Generate an HTML preview to render|No HTML report preview|No report preview loaded" ui/assets/modules/reports.js ui/index.html` returned no matches.
- `curl -fsS http://127.0.0.1:8000/health/live` returned healthy JSON before implementation.
- `curl -fsS http://127.0.0.1:8000/app/ | rg -n "Review and export technical, executive, and compliance reports for the selected run|without a side metadata rail|Prior Report Delta|History & Compared|metadata rail|Compare with Earlier Run|Run Dossier"` confirmed the live HTML contains the cleaned heading, `Compare with Earlier Run`, and `Run Dossier`, with no banned static HTML hits.
- `source .venv/bin/activate && python -m pytest -q api/tests/test_health.py` hit the known local `_pytest/capture.py FileNotFoundError` during capture teardown and is not claimed green.
- `source .venv/bin/activate && python -m pytest -s -q api/tests/test_health.py` passed.
- `python3 scripts/validate_backlog_tasks.py` passed after implementation and after promotion.
- `git diff --check` passed after implementation and after promotion.

## Additional Report Flow Checks

The following broader report-flow checks were run as extra signal but are not claimed green because they fail outside the copy-only scope:

- `source .venv/bin/activate && python -m pytest -s -q ui/tests/test_operator_console_e2e.py::test_discovery_report_center_shows_inventory_even_without_findings ui/tests/test_operator_console_e2e.py::test_authenticated_webapp_flow_supports_reports_and_secret_binding`
  - `test_discovery_report_center_shows_inventory_even_without_findings` kept the reader on the placeholder after triggering markdown preview and did not reach `## Discovery Summary`.
  - `test_authenticated_webapp_flow_supports_reports_and_secret_binding` found the markdown preview button disabled.
- `source .venv/bin/activate && python -m pytest -s -q ui/tests/test_product_feature_matrix_e2e.py::test_commercial_ui_font_stacks_are_local_safe ui/tests/test_product_feature_matrix_e2e.py::test_report_center_surfaces_codex_reviewed_adaptive_change_summary`
  - the font-stack test passed.
  - `test_report_center_surfaces_codex_reviewed_adaptive_change_summary` found the markdown preview button disabled.

These failures are not caused by string cleanup and would require report availability/preview-flow work that is explicitly outside backlog-171.

## Residual Risk

- Broader report preview availability has existing failures and remains a separate product/test debt item.
- The exact no-`-s` health pytest command still fails in this shell because of the known pytest capture tempfile issue; the same health tests pass with capture disabled.
- This slice intentionally did not restructure Report Center, change report generation/export, or modify backend report APIs/PDF generation.
