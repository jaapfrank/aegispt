# Backlog 164 WiFi / Wireless Readiness Evidence

## Scope

Task: `backlog-164-wifi-wireless-assessment-surface`

This evidence covers the first passive-only WiFi foundation slice. It does not enable or test deauthentication, jamming, evil-twin simulation, handshake capture, WPS PIN brute force, credential harvesting, or password cracking.

## Implemented Coverage

- Wizard tile: `WiFi / Wireless` with explicit site/location, approved SSIDs, approved BSSIDs, adapter/interface context, exclusions, and wireless ROE acknowledgement.
- Run profile: `passive-wifi-survey` using the `wifi-survey` runner.
- Runner: fixture-backed passive WLAN evidence import for `iw scan` and `airodump-ng` CSV style outputs.
- Inventory: normalized `wireless_access_points` and `wireless_networks` in existing inventory snapshots.
- Findings: conservative evidence-backed WiFi findings using the existing finding schema.
- Mission Control: WiFi task focus shows site, adapter, approved SSID/BSSID scope, passive-only boundary, and stdout.
- Settings readiness: wireless adapter/tool readiness states with safe parallelism and passive-only boundaries.
- Reports: `WiFi Security Summary` appears only when WiFi evidence exists.

## Host Readiness State

Validation is safe and non-RF-disruptive:

- Settings readiness supports `ready`, `degraded`, and `blocked` wireless states through test-controlled adapter/tool detection.
- Live app health was checked at `http://127.0.0.1:8000/health/live` and returned `status=ok`.
- The current host may not have authorized WiFi hardware attached; that is represented as blocked/degraded readiness rather than silently hiding WiFi.

## Validation Evidence

- `python3 -m py_compile api/app/routers/runs.py api/app/services/runs.py api/app/services/inventory.py api/app/services/reports.py api/app/services/settings.py workers/orchestration/findings.py workers/orchestration/tasks.py workers/runners/wifi_survey/runner.py api/tests/test_wifi_assessment.py workers/tests/test_wifi_survey_runner.py` passed.
- `python3 -m pytest -s workers/tests/test_wifi_survey_runner.py api/tests/test_wifi_assessment.py ui/tests/test_wizard_input_prediction_matrix_e2e.py ui/tests/test_operator_console_smoke_e2e.py -k 'settings_readiness_panel_exposes_tools_and_export or wifi_mission_control or wizard_prediction_matrix or wizard_launch_flow or wifi_survey or wifi_assessment'` passed: `10 passed, 31 deselected`.
- `python3 scripts/validate_backlog_tasks.py` passed before completion.
- `git diff --check` passed.

## Known Lab Gap

Monitor-mode capability, per-channel support, real RF adapter stability, and real site survey capture remain unclaimed until a future explicitly approved lab/hardware validation task. The foundation runner intentionally uses fixtures and existing evidence import so no live RF action is launched by this task.

## Non-WiFi Observation

A broad smoke run of `ui/tests/test_operator_console_smoke_e2e.py` surfaced an unrelated existing failure in `test_settings_threat_intel_nvd_rate_limit_hint_focuses_api_key_field`: the NVD API-key focus assertion did not focus the password input. This is outside backlog 164 and was not changed here.
