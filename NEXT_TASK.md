# Active Task

## Title

Full port scan by default plus SNMP non-standard port support: cover AutoPenBench NS1 and NS3

## Promoted From

`codex/tasks/backlog-245-nmap-full-port-scan-and-snmp-nonstandard.json`

## Goal

Implement the active backlog package `codex/tasks/backlog-245-nmap-full-port-scan-and-snmp-nonstandard.json` so active-tier nmap scanning catches services on non-standard ports and SNMP probing can use configured or discovered non-standard SNMP ports.

## Scope

Implement the active backlog package `codex/tasks/backlog-245-nmap-full-port-scan-and-snmp-nonstandard.json`.

Expected slice:

- change active-tier nmap default port coverage from top-1000 to top-10000, or the nearest existing bounded implementation required by the package
- expose a governed scan-depth option for top-1000, top-10000, and all 65535 ports where the existing wizard/settings flow supports it
- make SNMP probing accept a configurable port list defaulting to `[161]`
- make SNMP probe ports include nmap-discovered SNMP services on non-standard ports
- keep scope, approval, runtime binding, deployment, credential, ROE, and kill-switch behavior intact

## Constraints

- Do not implement until this file is the single active task.
- Only change nmap port-depth defaults/options and SNMP port configuration/discovery behavior.
- Do not change unrelated scanner behavior.
- Do not bypass approvals, scope, ROE, deployment, runtime binding, credential gates, or kill switch.
- No runtime self-modification.
- No uncontrolled plugin installation.

## Validation

- `python3 scripts/validate_backlog_tasks.py`
- `source .venv/bin/activate && python -m pytest api/tests/ -q`
- `git diff --check`

## Acceptance

- Active-tier nmap scans use top-10000 ports by default instead of top-1000.
- Full port scan is available as a governed wizard/settings option.
- SNMP runner accepts a configurable port list with default `[161]`.
- SNMP runner probes ports identified as SNMP by nmap, including non-standard ports.
- Existing nmap/SNMP tests do not regress.
