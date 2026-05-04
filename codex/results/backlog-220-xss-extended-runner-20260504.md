# backlog-220 XSS Extended Runner Evidence

## Outcome

backlog-220 is complete. AegisPT now has a dedicated approval-gated `xss-extended` active runner for approved web/API roots.

## Implemented

- Added `workers/runners/xss_extended/runner.py`.
- Detects same-origin unrestricted HTML upload by uploading a bounded HTML/script payload to explicit upload contexts and confirming that the served file is not forced to `text/plain` or `Content-Disposition: attachment`.
- Detects AJAX/JSON response-context XSS when configured endpoints reflect the bounded payload in browser-executable content.
- Detects XSSI-sensitive JSON exposure when unprotected JSON responses expose user/session/account-like fields without expected anti-XSSI signals.
- Emits `xss-extended-results.json` with structured findings, checks, replay metadata, summary counts, and safety metadata.
- Registered `xss-extended` in supported worker tools, dispatch, command previews, standard finding extraction, target planning, configuration validation, AI/manual proposal allowlists, methodology mapping, an `active-web-xss-extended` run profile, and the Tool Library.

## Task Package Exception

The task package goal mentioned extending existing ZAP coverage, while its constraints and `NEXT_TASK.md` prohibit changing existing ZAP runner configuration unless repo-truth requires it. This slice therefore implements the required three variants as a standalone `xss-extended` runner and records `zap_configuration_changed=false`.

## Validation

- `python3 scripts/validate_backlog_tasks.py` passed before implementation.
- `source .venv/bin/activate && python -m py_compile workers/runners/xss_extended/runner.py workers/orchestration/tasks.py workers/orchestration/findings.py api/app/services/runs.py api/app/services/run_profiles.py api/app/services/ai_agent.py api/app/methodology.py` passed.
- `source .venv/bin/activate && python -m pytest workers/tests/test_xss_extended_runner.py api/tests/test_pentest_depth_registration.py api/tests/test_runs.py::test_list_run_profiles api/tests/test_runs.py::test_active_xss_extended_profile_requires_approval_and_queues_task -q` passed.
- `source .venv/bin/activate && python -m pytest api/tests/ -q` passed with existing Alembic deprecation warnings.
- `python3 scripts/validate_backlog_tasks.py` passed during validation.
- `git diff --check` passed during validation.
- `curl -sS http://127.0.0.1:8000/health/live` returned healthy development runtime.
- `curl -sS http://127.0.0.1:8000/app/assets/modules/packs.js | rg -n "xss-extended|XSS Extended"` confirmed the live-served Tool Library module contains the new entry.

## Remaining Risk

- No public Gruyere or WebGoat target was actively exercised during this build-lane slice; proof is from deterministic safe local fixtures.
- The runner requires explicit upload, AJAX, JSON, evidence, or candidate contexts. It does not crawl the whole application to discover every candidate by itself.
- XSSI detection is heuristic and evidence-first: it flags sensitive JSON exposure with missing response protections, not every possible browser inclusion behavior.
- The running `127.0.0.1:8000` API process may still need a normal restart/redeploy before API profile defaults reflect this code, although static Tool Library assets are live-served from disk.
