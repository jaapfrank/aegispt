# backlog-159 AutoFix Findings Drawer Validation - 2026-05-01

## Result

Completed backlog-159 `Fix AutoFix Suggested Fix section absent from findings drawer when ai.autofix_enabled=false`.

The Findings drawer now always renders an AutoFix section:

- disabled AutoFix shows `AutoFix is disabled - enable in Settings > AI Provider` with a direct Settings action
- enabled AutoFix with a stored `ai_fix_suggestion` / generated patch renders the advisory suggestion and testing disclaimer
- enabled AutoFix without a suggestion shows `No suggestion available - re-run with AutoFix enabled`

No API endpoints were added and no auto-apply or repository mutation behavior was introduced.

## Files

- `ui/assets/modules/findings.js`
- `ui/tests/test_operator_console_smoke_e2e.py`

## Validation

- `python3 scripts/validate_backlog_tasks.py`
  - Passed: `187 queued task packages mapped one-to-one, and NEXT_TASK.md contains exactly one active task.`
- `node --input-type=module --check < ui/assets/modules/findings.js`
  - Passed.
- `source .venv/bin/activate && python -m pytest ui/tests/test_operator_console_smoke_e2e.py -s -q -k "autofix"`
  - Passed: the disabled, enabled-without-suggestion, and enabled-with-suggestion drawer states rendered correctly.
- `source .venv/bin/activate && python -m pytest api/tests/test_health.py -q`
  - Blocked by host-level pytest capture cleanup: `_pytest/capture.py FileNotFoundError`.
  - This is the same local capture issue observed in previous tasks and is not claimed green.
- `source .venv/bin/activate && python -m pytest api/tests/test_health.py -s -q`
  - Passed.
- `git diff --check`
  - Passed before and after documentation/promotion updates.
- `curl --max-time 5 -fsS http://127.0.0.1:8000/health/live`
  - Passed with healthy JSON from the local live service.

## Evidence Notes

The acceptance coverage is browser-backed through the existing Playwright smoke fixture. The live `:8000` service was relevant because this is a UI/operator-flow task; safe live validation was limited to health/liveness and did not run any customer or intrusive targets.

## Residual Risk

The exact no-`-s` health pytest command remains blocked by the local pytest capture cleanup issue. Broader AutoFix value still depends on the existing backend provider, settings, OAuth state, and stored `FindingRemediation.ai_fix_suggestion`; this task only fixes drawer visibility and truthful UI states.
