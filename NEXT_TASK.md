# Active Task

## Title

RCE detection Nuclei template expansion: cover AutoPenBench WS5/WS6 and real-world CVE RCE tasks

## Promoted From

`codex/tasks/backlog-249-rce-detection-nuclei-templates-expansion.json`

## Goal

Implement the active backlog package `codex/tasks/backlog-249-rce-detection-nuclei-templates-expansion.json` so AegisPT improves detection-only RCE coverage for AutoPenBench WS5/WS6 and real-world CVE RCE classes through governed Nuclei template expansion, OOB callback support where safely configured, and service-aware template selection.

## Scope

Implement the active backlog package `codex/tasks/backlog-249-rce-detection-nuclei-templates-expansion.json`.

Expected slice:

- verify and enable detection-only Nuclei coverage for listed RCE CVEs such as Log4Shell, Spring4Shell, GeoServer, Jenkins CLI RCE, Druid RCE, Grafana path traversal/file read, Bludit RCE, and SambaCry
- add or wire generic detection-only RCE templates for common command-injection parameters, PHP file-inclusion/code-execution signals, SSTI math-expression probes, and safe deserialization callback probes
- support OOB/Interactsh-style blind RCE detection only through governed configuration and detection-only callbacks
- update Nuclei templates before scans where this can be done without bypassing existing tool validation and approval controls
- auto-match Nuclei templates to discovered service evidence from existing inventory/nmap/httpx artifacts to reduce noise
- preserve existing Nuclei safety validation and approval gates

## Constraints

- Do not implement until this file is the single active task.
- Detection templates only; no RCE exploitation, payload delivery, file writes, persistence, webshell upload, or shell execution.
- Nuclei templates must remain detection-only and pass existing safety validation.
- Do not use templates with uncontrolled `attack` behavior or unsafe body payloads.
- Do not bypass pack registry, validation, approval, deployment, runtime binding, scope, ROE, credentials, or kill switch.
- Do not weaken intrusive exploitation gates.
- No runtime self-modification.
- No uncontrolled plugin installation.

## Validation

- `python3 scripts/validate_backlog_tasks.py`
- `source .venv/bin/activate && python -m pytest api/tests/ -q`
- `git diff --check`

## Acceptance

- Listed CVE RCE templates are verified present/enabled or gaps are explicitly documented.
- OOB/Interactsh blind RCE detection is configured or safely blocked with clear operator evidence.
- `nuclei -update-templates` behavior is governed and does not bypass safety validation.
- Template selection can use discovered service evidence to select relevant RCE checks.
- Existing Nuclei tests do not regress.
- No exploitation, payload delivery, file write, or webshell behavior is introduced.
