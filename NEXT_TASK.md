# Active Task

## Title

AI Free Bash Execution: let the AI agent run arbitrary shell commands on authorized targets via SSH, with operator-per-command approval

## Promoted From

`codex/tasks/backlog-248-ai-free-bash-execution-runner.json`

## Goal

Implement the active backlog package `codex/tasks/backlog-248-ai-free-bash-execution-runner.json` so AegisPT can support AI-proposed SSH shell commands on approved engagement targets while preserving per-command operator approval, scope enforcement, auditability, kill-switch control, and the existing predefined runner model.

## Scope

Implement the active backlog package `codex/tasks/backlog-248-ai-free-bash-execution-runner.json`.

Expected slice:

- add an `ai-shell` runner that executes a single approved SSH command on an approved engagement target
- allow the AI agent to propose shell-type actions with exact command, target, SSH credential reference, and reasoning
- surface shell proposals in Mission Control with the exact command visible before approval
- execute only after operator approval of that individual command
- cap command output and store durable proposed/approved/rejected/executed audit evidence
- enforce a banned-command list before SSH execution
- enforce approved target scope before SSH execution
- add a per-engagement kill switch or disable control for `ai-shell`
- add the `active-ai-shell` run profile and dispatch mapping required by the package
- keep the existing manual/predefined runners intact

## Constraints

- Do not implement until this file is the single active task.
- Do not execute shell commands on the AegisPT host itself.
- Only execute via SSH on approved engagement targets.
- Every shell command requires individual operator approval; no batch approval and no auto-run shell mode.
- Enforce the banned-command list before execution: destructive disk operations, reboot/shutdown, firewall flush, password/user changes, crontab removal, and external `wget`/`curl` outside scope.
- Do not bypass approvals, scope, ROE, deployment, runtime binding, credential gates, or kill switch.
- Do not weaken intrusive exploitation gates.
- Do not change existing predefined runner behavior except where explicitly required to register `ai-shell`.
- No runtime self-modification.
- No uncontrolled plugin installation.

## Validation

- `python3 scripts/validate_backlog_tasks.py`
- `source .venv/bin/activate && python -m pytest api/tests/ -q`
- `git diff --check`

## Acceptance

- AI can propose shell-type actions with command, target, SSH credential reference, and reasoning.
- Mission Control shows the exact proposed command before approval.
- Approval executes exactly one SSH command on an in-scope target.
- Rejection does not execute.
- Banned commands are blocked before SSH execution.
- Out-of-scope targets are blocked before SSH execution.
- Output is capped and returned for the next AI analysis cycle.
- Audit log records proposed, approved/rejected, executed, output hash, and blocker states.
- Engagement kill switch disables `ai-shell`.
- Existing AI agent, proposal, runner, approval, and dispatch tests do not regress.
