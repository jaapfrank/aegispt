# Active Task

## Title

Pentest depth expansion: add ffuf/gobuster directory bruteforce, nikto web scan, sqlmap SQLi detection, and Shodan/Censys passive recon

## Promoted From

`codex/tasks/backlog-211-pentest-depth-additional-tools.json`

## Goal

Add the four runner/recon gaps identified by the competitive analysis: directory/endpoint bruteforce, web server configuration scanning, SQL injection confirmation, and passive Shodan/Censys recon.

## Scope

Implement the active backlog package `codex/tasks/backlog-211-pentest-depth-additional-tools.json`.

Expected slice:

- add an `ffuf` or `gobuster` runner for active, rate-limited directory/endpoint bruteforce that produces structured hidden-endpoint findings
- add a `nikto` runner for web server configuration scanning that produces structured web configuration findings
- add a constrained `sqlmap` runner for SQL injection confirmation only on explicit parameters or ZAP-flagged injectable parameters
- add Shodan/Censys passive recon that uses configured API keys and produces structured external-exposure findings
- expose the four new capabilities in the Tool Library
- update the security tool installer for the new tools

## Constraints

- Keep Prompt 1 and Prompt 2 intact.
- Implement the four runners only.
- Use the same runner pattern as existing tools in `workers/orchestration/tasks.py`.
- Do not change core dispatch logic.
- Do not touch existing runners except where integration registration requires additive wiring.
- Respect existing authorization tier gates.
- `sqlmap` must require explicit parameter specification or ZAP-flagged injectable parameters and must never run unscopedly across all pages.
- Do not bypass scope, ROE, validation, approval, deployment, runtime binding, credential gates, or kill switch.
- No runtime self-modification.
- No uncontrolled plugin installation.
- No live target actions outside safe/local/explicitly authorized validation.

## Validation

- `python3 scripts/validate_backlog_tasks.py`
- `source .venv/bin/activate && python -m pytest api/tests/ -q`
- `git diff --check`

## Acceptance

- Four new runners are present in the supported tools list.
- Each runner produces structured findings in the standard format.
- `sqlmap` cannot run without an explicit parameter target or ZAP-flagged injectable parameter.
- Shodan/Censys recon is passive, read-only, and requires API keys.
- All four tools appear in the Tool Library.
- No regression in existing runner tests.
