# Active Task

## Title

Linux privilege escalation enumeration runner: SUID/SGID binaries, sudo misconfigurations, writable cron jobs, and path hijacking

## Promoted From

`codex/tasks/backlog-234-linux-privilege-escalation-enumeration.json`

## Goal

Add the queued Linux privilege escalation enumeration capability described in `codex/tasks/backlog-234-linux-privilege-escalation-enumeration.json`.

## Scope

Implement the active backlog package `codex/tasks/backlog-234-linux-privilege-escalation-enumeration.json`.

Expected slice:

- add a `priv-esc-linux` runner for approved credentialed Linux targets
- enumerate SUID/SGID binaries and match dangerous entries against a GTFOBins-style list
- parse `sudo -l` output for dangerous `NOPASSWD`, broad `ALL=(ALL:ALL) ALL`, and risky command entries
- detect writable cron scripts, weak file permissions, writable early `$PATH` directories, and known kernel local privilege escalation CVE signals
- require the intrusive-credential profile tier, configured SSH/low-privilege access context, approval, scope, ROE, credentials, runtime binding, and kill switch
- add the `intrusive-credential-priv-esc-linux` run profile and required operator surfaces
- wire the profile into Full Internal LAN Phase 3 and wizard surfaces required by the task package
- keep evidence, findings, methodology tags, provenance, reports, approvals, scope, credential materialization, and runtime dispatch paths aligned with existing models and flows

## Constraints

- Keep Prompt 1 and Prompt 2 intact.
- Add only the Linux privilege escalation enumeration capability from the task package.
- Do not bypass local provenance, scope, ROE, validation, approval, deployment, runtime binding, credential gates, or kill switch.
- No runtime self-modification.
- No uncontrolled plugin installation.
- Enumeration only.
- Do not execute found SUID/SGID binaries for exploitation.
- Do not escalate privileges.
- Do not write to the target filesystem.
- Do not change the Metasploit exploitation runner or intrusive-exploitation approval gates.
- No live target actions outside safe/local/expliciet geautoriseerde validatie.

## Validation

- `python3 scripts/validate_backlog_tasks.py`
- `source .venv/bin/activate && python -m pytest api/tests/ -q`
- `git diff --check`

## Acceptance

- `priv-esc-linux` is registered in supported tools.
- SUID/GTFOBins matching produces a deterministic finding.
- `sudo -l` parsing detects dangerous entries.
- Writable cron and weak-permission checks are represented safely.
- Kernel local privilege escalation CVE signal matching is represented without exploitation.
- `intrusive-credential-priv-esc-linux` exists and requires approval plus credential context.
- Runner is reachable through the wizard for Internal LAN / Full Internal full-depth with credential context.
- Existing runner/API tests do not regress.
