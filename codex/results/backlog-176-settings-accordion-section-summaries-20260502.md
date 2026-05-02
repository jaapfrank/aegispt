# backlog-176 Settings accordion summaries validation

## Outcome

Settings disclosure headers now render one-line summaries that describe the current configured state where existing Settings state makes that possible:

- AI Provider shows selected/connected provider state and enabled helper count.
- Default Network Scope shows the configured CIDR or a short setup description.
- Default Scan Profile shows profile, safety level, and execution lane.
- Runtime Execution shows the configured parallel worker limit.
- Integrations and Notifications show configured/unconfigured operator state.
- Threat Intel, Evidence Integrity, Remediation, and Instance show concise status based on existing setting values.

No Settings fields, backend APIs, data model, save/load logic, pack gates, approval flow, deployment, or runtime binding behavior changed.

## Browser acceptance

Live acceptance against `http://127.0.0.1:8000/app/` passed. The rendered Settings summaries included:

- `AI Provider: ChatGPT OAuth selected · 0 helpers on`
- `Default scope: 10.0.20.0/24`
- `Profile: Standard · passive · passive-network-discovery`
- `4 parallel task workers`
- `Configure Jira and webhook handoffs`
- `Critical alerts: none · completion off`
- `Daily CVE sync on · NVD key not set`
- `Timestamping on · TSA configured`
- `Operator: operator-ui · http://127.0.0.1:8000`

The live browser check also collapsed and expanded the Default Network Scope disclosure and confirmed the existing `network.default_lan_cidr` field became visible when expanded.

## Validation

- `python3 scripts/validate_backlog_tasks.py` passed before implementation with `193` queued task packages and exactly one active task.
- `curl -fsS http://127.0.0.1:8000/health/live` returned healthy JSON.
- `node --input-type=module --check < ui/assets/modules/settings.js` passed.
- `python3 -m py_compile ui/tests/test_operator_console_smoke_e2e.py` passed.
- `source .venv/bin/activate && python -m pytest -s -q ui/tests/test_operator_console_smoke_e2e.py::test_settings_collapsed_sections_show_status_summaries_and_still_toggle` passed.
- Focused Settings smoke coverage passed for actor-backed Settings, collapsed section summaries, readiness, scheduled scans, Threat Intel NVD hint, and Jira configuration fields.
- Live Playwright browser acceptance passed.
- `source .venv/bin/activate && python -m pytest api/tests/test_health.py -q` failed with the known local `_pytest/capture.py FileNotFoundError`; this is not claimed green.
- `source .venv/bin/activate && python -m pytest -s -q api/tests/test_health.py` passed.
- `python3 scripts/validate_backlog_tasks.py` passed after promoting backlog-177.
- `git diff --check` passed.

## Residual risk

- The exact no-`-s` health pytest command is still expected to hit the known local `_pytest/capture.py FileNotFoundError`; the same health tests are rerun with `-s` for truthful local health evidence.
- The summaries intentionally use existing JS state only. They do not verify external integrations or provider connectivity beyond state already loaded into the operator console.
