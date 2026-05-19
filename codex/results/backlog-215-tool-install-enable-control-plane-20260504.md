# backlog-215 Tool Install and Enable Control Plane

Date: 2026-05-04

## Scope

Implemented the active task package `codex/tasks/backlog-215-tool-install-and-enable-control-plane.json`.

This slice makes software tool readiness actionable and keeps enablement governed:

- no pentest tool is executed against a target
- no approval, scope, ROE, pack validation, deployment, runtime binding, credential gate, or kill-switch behavior is bypassed
- Settings quick actions only copy install commands, focus fields, or patch safe instance settings

## Implementation Evidence

Touched files:

- `api/app/schemas/settings.py`
- `api/app/services/settings.py`
- `api/tests/test_settings.py`
- `docs/host_service_install.md`
- `infra/compose/Dockerfile`
- `scripts/install_security_tools.sh`
- `scripts/verify_host.sh`
- `ui/assets/modules/settings.js`
- `ui/tests/test_operator_console_smoke_e2e.py`

Readiness changes:

- Tool readiness now reports required binary groups, detected paths, missing binaries, official install/repair commands, and whether hardware is separate from software.
- `httpx-toolkit` is preferred over a conflicting Python `httpx` CLI while still accepting either valid command.
- NetExec readiness accepts `nxc`, `netexec`, or `crackmapexec`.
- Impacket readiness accepts `.py` commands and compatibility aliases.
- WiFi software readiness is distinct from wireless adapter hardware readiness.
- Settings renders copyable install/repair commands for missing software groups.
- Settings renders governed Enable/Configure actions for supported disabled/configurable capabilities; setting-patch actions only update Settings.

Installer/image changes:

- Host installer adds compatibility links for Impacket `GetUserSPNs` / `GetNPUsers` aliases and NetExec `nxc` -> `netexec`.
- Compose image includes the tracked tool families plus supporting commands used by verification.
- Compose image adds compatibility links for ProjectDiscovery httpx and Impacket command aliases.
- `scripts/verify_host.sh` accepts real command aliases and handles NetExec's non-zero version exit while still requiring a binary to exist.

## Validation

Passed:

- `python3 scripts/validate_backlog_tasks.py`
  - `240 queued task packages mapped one-to-one, and NEXT_TASK.md contains exactly one active task`
- `source .venv/bin/activate && python -m pytest api/tests/test_settings.py -q`
  - exit 0
- `source .venv/bin/activate && python -m pytest ui/tests/test_operator_console_smoke_e2e.py -q`
  - exit 0
- `bash scripts/verify_host.sh`
  - exit 0
  - verified Docker, Python/venv, Nuclei, ZAP, Nmap, ProjectDiscovery httpx, ffuf, feroxbuster, testssl.sh presence, Semgrep, ssh-audit, AWS CLI, Responder, NetExec, hashcat, Metasploit, LDAP, SNMP, iw, aircrack-ng, airodump-ng, Impacket commands, BloodHound Python, kerbrute, and subfinder
- `git diff --check`
  - exit 0

Safe live/local acceptance:

- `curl --fail --silent --show-error --max-time 5 http://127.0.0.1:8000/health/live`
  - passed read-only; the already-running host is healthy
- `curl --fail --silent --show-error --max-time 5 http://127.0.0.1:8000/api/v1/settings/readiness`
  - read-only; confirmed the live host is still serving the older loaded readiness copy because it was not restarted during this build-lane task
- temporary isolated current-code host on `http://127.0.0.1:8015`
  - `/health/live` passed
  - `/api/v1/settings/readiness` showed `host_installer_command`, readiness `actions`, `Enable ChatGPT OAuth`, `httpx-toolkit`, `nxc`, empty software `missing_binaries`, and `hardware_blocked: true` for missing WiFi adapter hardware
  - temporary host was stopped and `/tmp/aegispt-backlog215-acceptance.db` was removed

## Remaining Risks

- The live `127.0.0.1:8000` process was not restarted, so it will not show the new Settings/readiness UX until the service is redeployed or restarted.
- This task proves software readiness and UI enablement controls, not a real target scan or a WiFi adapter lab proof.
- WiFi hardware remains blocked on the current host because no wireless adapter is detected; software tooling is verified.
- `testssl.sh --version` timed out during verification but the script detected the binary and continued with an explicit presence note.
- ZAP reported add-ons may be out of date and Semgrep reported a newer version is available; neither blocked the required host verification.
