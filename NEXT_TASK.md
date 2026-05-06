# Active Task

## Title

SSH/service brute force runner via Hydra: cover AutoPenBench AC0 weak-password task

## Promoted From

`codex/tasks/backlog-244-ssh-hydra-brute-force-runner.json`

## Goal

Implement an approval-gated `ssh-brute` runner using Hydra so AegisPT can cover the AutoPenBench AC0 weak-password task and bounded service brute-force checks for approved SSH, FTP, Telnet, RDP, and related discovered services.

## Scope

Implement the active backlog package `codex/tasks/backlog-244-ssh-hydra-brute-force-runner.json`.

Expected slice:

- add an `ssh-brute` runner using Hydra
- take configured target host(s), discovered services, and port metadata from existing approved scope/run context
- use a tiered wordlist: top-50 common passwords first, then an engagement-configured password list only when provided
- rate-limit attempts to max 5 attempts per second
- stop after 3 consecutive lockout signals
- report successful credential pairs as critical findings with existing provenance/report flows
- support SSH plus FTP, Telnet, RDP basic brute-force coverage within the same safety model
- install/verify Hydra through existing tool-install readiness paths
- wire `active-lan-ssh-brute` into RunProfiles, assessment chains, wizard trigger logic, and acceptance harness mapping as described in the task package

## Constraints

- Do not implement until this file is the single active task.
- Brute force only within approved engagement CIDR/targets.
- Active tier; requires approval.
- Never use `rockyou.txt` or large wordlists unless explicitly operator-configured in a future active task.
- Stop immediately on 3 lockout detections.
- Do not touch existing AD/Kerberos `credential-attacks` behavior except where registration/dispatch references require coexistence.
- Do not bypass approvals, scope, ROE, deployment, runtime binding, credential gates, or kill switch.
- No runtime self-modification.
- No uncontrolled plugin installation.

## Validation

- `python3 scripts/validate_backlog_tasks.py`
- `source .venv/bin/activate && python -m pytest api/tests/ -q`
- `git diff --check`

## Acceptance

- `ssh-brute` appears in supported tools.
- The runner detects a weak credential on a safe approved test container or records an exact blocker.
- Lockout protection works.
- `active-lan-ssh-brute` is reachable through RunProfiles, relevant assessment chains, wizard triggers, and acceptance harness mapping.
- Existing tests do not regress.
