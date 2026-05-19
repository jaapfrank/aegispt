# Backlog 158 - Engagement Cleanup Label Validation

Date: 2026-05-01

## Scope

Fixed the topbar engagement action language so it no longer promises a generic engagement manager while opening the delete/cleanup flow. The visible button was already labeled `Cleanup`; this slice aligned the internal UI flow names with that product truth and added focused regression coverage.

## Files Changed

- `ui/assets/app.js`
- `ui/tests/test_operator_console_smoke_e2e.py`
- `ui/tests/test_operator_console_e2e.py`

## Acceptance Evidence

- Topbar action text is `Cleanup`, not `Manage`.
- The action retains `aria-label="Open engagement cleanup"` and `title="Open engagement cleanup"`.
- Clicking the action opens the existing Data Cleanup / Engagement Cleanup modal.
- The existing engagement-delete list and bulk-delete behavior remain unchanged.
- No new engagement CRUD manager was added.

## Validation

Passed:

- `python3 scripts/validate_backlog_tasks.py`
- `source .venv/bin/activate && python -m pytest -s -q ui/tests/test_operator_console_smoke_e2e.py::test_topbar_engagement_cleanup_label_matches_delete_modal ui/tests/test_operator_console_e2e.py::test_bulk_delete_run_and_cleanup_engagement_controls`
- `source .venv/bin/activate && python -m pytest -s -q ui/tests/test_live_system_audit_2026_05_01.py::test_topbar_cleanup_not_manage`
- `source .venv/bin/activate && python -m pytest -s -q api/tests/test_health.py`
- `node --input-type=module --check < ui/assets/app.js`
- `git diff --check`
- `curl --max-time 5 -fsS http://127.0.0.1:8000/health/live` after restarting the local inline host

Not claimed green:

- Exact required command `source .venv/bin/activate && python -m pytest api/tests/test_health.py -q` hit the known local pytest capture failure: `FileNotFoundError` in `_pytest/capture.py`. The same health tests passed with `-s`.
- The first live health probe timed out because no process was listening on `127.0.0.1:8000`; `AEGISPT_LOCAL_ENSURE_ZAP=0 bash scripts/restart_local_inline_host.sh` started the local inline host, after which `/health/live` returned healthy JSON.

## Remaining Risk

This slice only corrects the engagement cleanup action intent. It does not add engagement create/rename/archive functionality and does not alter the bulk-delete API or modal behavior.
