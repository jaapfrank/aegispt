# backlog-162 - NVD Rate Limit API Key Hint

## Result

Completed. Settings > Threat Intel now shows an actionable NVD API key hint when the NVD source reports HTTP 429 or `reason=rate_limited`. The hint is UI-only and points to the existing `threat_intel.nvd_api_key` setting field by opening/focusing that field.

## Files Changed

- `ui/assets/modules/settings.js`
- `ui/tests/test_operator_console_smoke_e2e.py`
- `ui/assets/app.js`
- `ui/index.html`
- `CURRENT_STATE.md`
- `DONE_LOG.md`
- `NEXT_TASK.md`

## Validation

- `python3 scripts/validate_backlog_tasks.py` passed before implementation.
- `node --input-type=module --check < ui/assets/app.js` passed.
- `node --input-type=module --check < ui/assets/modules/settings.js` passed.
- `source .venv/bin/activate && python -m pytest ui/tests/test_operator_console_smoke_e2e.py -s -q -k "nvd_rate_limit_hint"` passed.
- `source .venv/bin/activate && python -m pytest api/tests/test_health.py -q` failed before assertions with the known local `_pytest/capture.py FileNotFoundError`; not claimed green.
- `source .venv/bin/activate && python -m pytest api/tests/test_health.py -s -q` passed.
- `curl --max-time 5 -fsS http://127.0.0.1:8000/health/live` returned healthy JSON.
- Live Playwright acceptance against `http://127.0.0.1:8000/app/` passed: an injected NVD 429/rate_limited status rendered the hint and the focus action opened/focused `threat_intel.nvd_api_key`.
- `git diff --check` passed before documentation updates.
- `python3 scripts/validate_backlog_tasks.py` passed after promotion to backlog-163.
- `git diff --check` passed after documentation and promotion updates.

## Safety / Scope

- No backend endpoints, migrations, schemas, runner behavior, pack registry, approval, deployment, or runtime binding paths changed.
- No live target or intrusive action was run.
- Prompt 1 and Prompt 2 foundations were not touched.

## Residual Risk

- The exact no-`-s` health pytest command remains blocked by the local pytest capture issue.
- This slice only improves Settings guidance for NVD rate limiting; it does not provision an NVD key or change feed-sync retry behavior.
