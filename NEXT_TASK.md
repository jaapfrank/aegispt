# Active Task

## Title

Network traffic capture runner: tcpdump passive capture + ARP poisoning detection to cover AutoPenBench NS4/NS5

## Promoted From

`codex/tasks/backlog-246-network-traffic-capture-arp-runner.json`

## Goal

Implement the active backlog package `codex/tasks/backlog-246-network-traffic-capture-arp-runner.json` so AegisPT gains a governed network-capture runner for passive traffic capture and ARP poisoning detection, while keeping intrusive ARP spoof proof explicitly gated.

## Scope

Implement the active backlog package `codex/tasks/backlog-246-network-traffic-capture-arp-runner.json`.

Expected slice:

- add a `network-capture` runner with passive tcpdump capture mode
- detect cleartext credentials or tokens in bounded captured traffic evidence
- add ARP consistency checks that can report possible ARP poisoning / missing Dynamic ARP Inspection
- keep optional ARP spoof proof intrusive-gated, time-bounded, single-target, and restorative
- register `passive-lan-network-capture` and wire it into the specified internal LAN / IoT planning surfaces
- keep capture duration, packet counts, scope, approval, runtime binding, deployment, credential, ROE, and kill-switch behavior intact

## Constraints

- Do not implement until this file is the single active task.
- Keep passive capture time-limited and interface/scope approved.
- ARP spoof proof, if implemented, must remain intrusive-tier only with explicit gate and immediate restoration.
- Do not store captured cleartext credentials beyond governed finding/evidence handling.
- Do not bypass approvals, scope, ROE, deployment, runtime binding, credential gates, or kill switch.
- No runtime self-modification.
- No uncontrolled plugin installation.

## Validation

- `python3 scripts/validate_backlog_tasks.py`
- `source .venv/bin/activate && python -m pytest api/tests/ -q`
- `git diff --check`

## Acceptance

- `network-capture` is in supported tools.
- Passive tcpdump capture mode works in bounded approved-scope form.
- ARP consistency checks can produce the intended finding.
- Any ARP spoof proof remains explicitly gated and bounded.
- `passive-lan-network-capture` is registered and reachable through required planning/wizard surfaces.
- Existing tests do not regress.
