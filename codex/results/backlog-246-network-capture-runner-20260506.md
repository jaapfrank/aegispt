# Backlog 246 Network Capture Runner Evidence

## Scope

- Active task: `Network traffic capture runner: tcpdump passive capture + ARP poisoning detection`
- Approved live validation scope from operator thread: `10.0.20.0/24`
- Local UI validation target: `http://127.0.0.1:8000/app/`

## Implementation Proof

- Added governed `network-capture` runner with bounded passive tcpdump command construction, no pcap/raw payload storage, and credential value redaction.
- Added ARP consistency parsing for inventory, `ip neigh`, and `arping` evidence, including duplicate MAC and gateway MAC mismatch finding generation.
- Added optional ARP spoof proof path that remains fail-closed unless explicit intrusive authorization, single target, gateway, interface, scope, and time bounds are present.
- Registered `passive-lan-network-capture` across run profiles, orchestration, findings, inventory, reports, settings/readiness, install/verify scripts, certification matrix, assessment chains, acceptance harness, and wizard/planning surfaces.

## Live Acceptance Truth

- Evidence: `codex/results/backlog-246-network-capture-live-10-0-20-20260506.json`
- Interface/scope: `eth0` with `10.0.20.46/24`; route to `10.0.20.0/24` is local on `eth0`.
- Safe discovery: `nmap -sn -n 10.0.20.0/24 --host-timeout 10s` found 27 hosts.
- Real ARP table: `ip neigh show dev eth0` produced 28 usable ARP entries for runner parsing.
- Host binary truth: `tcpdump`, `arping`, and `arpspoof` were not installed; `ip` and `nmap` were available.
- Runner live attempt truth: bounded passive capture and gated spoof-proof executions returned `completed_with_gaps`; tcpdump capture status was `failed` due missing binary, and ARP spoof proof was `blocked_capability_unavailable`.

## Browser Acceptance

- Evidence: `codex/results/backlog-246-wizard-network-capture-8000.json`
- Screenshot/evidence: `codex/results/backlog-246-wizard-network-capture-preview-8000.png` and `.json`
- Current `/app/` served `app.js?v=20260506-network-capture-1`.
- Playwright verified Internal LAN and Smart Home / IoT LAN prediction matrix depths include `passive-lan-network-capture`.
- Playwright verified the visible guided Internal LAN preview for `10.0.20.0/24` uses `Full Internal LAN`, shows `2 phases · 11 runners`, includes `CAP Network capture + ARP`, has no `RUNNE` fallback label, and has no page errors.

## Validation

- `python3 scripts/validate_backlog_tasks.py` passed before implementation and before documentation promotion.
- `source .venv/bin/activate && python -m pytest workers/tests/test_network_capture_runner.py workers/tests/test_runner_contract.py workers/tests/test_runner_tool_certification_matrix.py -q` passed.
- `source .venv/bin/activate && python -m pytest api/tests/ -q` passed on the rerun after fixing the CIDR-only chain follow-up regression; only existing Alembic deprecation warnings were printed.
- `node --input-type=module --check < ui/assets/modules/wizard.js` passed.
- `bash -n scripts/install_security_tools.sh scripts/verify_host.sh` passed.
- `git diff --check` passed.

## Boundaries

- No live ARP spoofing was executed because the governed proof route was blocked by missing `arpspoof` on this host.
- No public, customer, third-party, or out-of-scope target was contacted.
- No credential values or raw captured packet payloads were stored.
- No pack-registry, validation, approval, deployment, runtime-binding, scope, ROE, credential, or kill-switch bypass occurred.
