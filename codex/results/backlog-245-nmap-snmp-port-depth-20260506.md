# backlog-245 evidence: nmap scan depth and SNMP non-standard ports

Date: 2026-05-06

## Scope

Active task: `codex/tasks/backlog-245-nmap-full-port-scan-and-snmp-nonstandard.json`.

Implemented only nmap port-depth defaults/options and SNMP port configuration/discovery behavior.

## Evidence

- Deep internal LAN service-enumeration defaults now set nmap `top_ports` to `10000`.
- Nmap run configuration accepts governed `scan_depth` values:
  - `top-1000`
  - `top-10000`
  - `all-ports`
- Wizard Advanced Configuration > Safety exposes `Nmap Scan Depth` with the same three choices.
- SNMP profile defaults pass `ports: [161]`.
- SNMP runner accepts configured ports and probes nmap-discovered SNMP services on non-standard ports such as `1161`.
- SNMP command preview now includes configured ports.

## Validation

- `python3 scripts/validate_backlog_tasks.py` passed before implementation.
- Focused checks passed:
  - `source .venv/bin/activate && python -m pytest workers/tests/test_snmp_enum_runner.py workers/tests/test_runner_contract.py -q`
  - `source .venv/bin/activate && python -m pytest api/tests/test_assessment_chain.py::test_internal_lan_chain_service_enumeration_uses_discovered_hosts api/tests/test_runs.py::test_snmp_enum_profile_queues_read_only_bounded_default_community_task api/tests/test_runs.py::test_nmap_configuration_scan_depth_maps_to_bounded_runner_params api/tests/test_runs.py::test_snmp_configuration_accepts_nonstandard_ports api/tests/test_wizard_iot_static.py -q`
- Required full API suite passed:
  - `source .venv/bin/activate && python -m pytest api/tests/ -q`
- Current-code browser acceptance on `http://127.0.0.1:8000/app/` passed with `domcontentloaded` plus explicit selectors:
  - evidence JSON: `codex/results/backlog-245-wizard-nmap-scan-depth-8000.json`
  - screenshot: `codex/results/backlog-245-wizard-nmap-scan-depth-8000.png`
- `git diff --check` passed before and after documentation/promotion updates.

## Exceptions

- The first Playwright acceptance attempt used `networkidle` and timed out because the operator console keeps background live requests open. It is not claimed green. The accepted run used `domcontentloaded` and explicit visible selector checks.
- Local generated `codex/tasks/task-2026050610...pack-refinement...json` files appeared during validation/runtime interaction. They were not queue-backed `backlog-*.json` packages and were removed as out-of-scope generated state.
- No live customer, public, or third-party SNMP/nmap target was scanned. Browser acceptance was local UI-only.
