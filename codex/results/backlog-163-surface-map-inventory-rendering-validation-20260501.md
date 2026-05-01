# Backlog 163 - Surface Map Inventory Rendering Validation

## Summary

Backlog-163 is complete. Surface Map now renders host nodes when the selected inventory snapshot has explicit hosts or service-only host data. When no inventory exists, the empty state tells the operator to run Passive Network Discovery to populate the map. Asset Browser filter tabs now include inventory-backed counts.

## Files Changed

- `ui/assets/modules/mission-control.js`
- `ui/assets/app.js`
- `ui/index.html`
- `ui/tests/test_operator_console_smoke_e2e.py`
- `.gitignore`

## Implementation Notes

- Added service-derived host normalization so snapshots with services but no explicit `hosts` array still produce visible Surface Map nodes.
- Kept service-derived nodes labeled as derived from mapped services so provenance is clear.
- Updated no-inventory/no-renderable-inventory empty states with actionable Passive Network Discovery guidance.
- Added counted Asset Browser filter labels such as `Services (2)` and `Hosts (0)`.
- Cache-busted UI assets so the live console receives the updated Mission Control module.
- Added `.aegispt-artifacts/` to `.gitignore` after confirming local runtime run artifacts were untracked but still visible in `git status`.

## Validation

- `python3 scripts/validate_backlog_tasks.py` passed before implementation.
- `node --input-type=module --check < ui/assets/modules/mission-control.js` passed.
- `node --input-type=module --check < ui/assets/app.js` passed.
- `source .venv/bin/activate && python -m pytest ui/tests/test_operator_console_smoke_e2e.py -s -q -k "surface_map"` passed.
- `source .venv/bin/activate && python -m pytest ui/tests/test_operator_console_e2e.py -s -q -k "surface_map"` passed.
- `source .venv/bin/activate && python -m pytest ui/tests/test_product_feature_matrix_e2e.py -s -q -k "attack_path_summary_surface"` passed.
- `source .venv/bin/activate && python -m pytest api/tests/test_health.py -q` hit the known local `_pytest/capture.py FileNotFoundError` and is not claimed green.
- `source .venv/bin/activate && python -m pytest api/tests/test_health.py -s -q` passed.
- `curl --max-time 5 -fsS http://127.0.0.1:8000/health/live` returned healthy JSON.
- Live Playwright acceptance against `http://127.0.0.1:8000/app/` passed for service-derived host rendering, counted Asset Browser filters, and insight text.
- `git diff --check` passed before documentation/promotion.

## Residual Risk

- This task fixes rendering and empty-state clarity only. It does not redesign Surface Map, change inventory persistence, alter runner output, or add new discovery tooling.
- The exact no-`-s` health command remains blocked by the local pytest capture issue.
- Live validation used injected safe UI state and did not launch scans or touch live targets.
