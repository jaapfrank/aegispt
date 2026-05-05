# Active Task

## Title

AI attack chain reasoning: teach the AI agent to chain web vulnerabilities across tools and recognize compound attack paths

## Promoted From

`codex/tasks/backlog-219-ai-attack-chain-reasoning-web-context.json`

## Goal

Implement cross-task web attack-chain reasoning for the AI agent. After web scan tasks, the AI should analyze all findings so far for the current engagement, recognize compound paths such as file upload plus stored XSS or path traversal plus writable filesystem/code execution signals, and propose the next logical review-gated chain test.

## Scope

Implement the active backlog package `codex/tasks/backlog-219-ai-attack-chain-reasoning-web-context.json`.

Expected slice:

- extend the AI agent with an engagement-scoped cross-task context window that reads all in-scope findings, not only the current task output
- add deterministic web-specific chain templates for compound patterns such as stored XSS plus file upload, unrestricted file upload plus uploaded HTML execution checks, and path traversal plus writable filesystem/code execution signals
- create and store a compound attack-chain finding type or equivalent finding record for multi-step paths
- surface generated chain proposals through the existing Mission Control AI Proposals inbox

## Constraints

- Do not implement until this file is the single active task.
- Do not change autonomous dispatch logic.
- Do not bypass intrusive approval gates.
- Do not change finding schema behavior for non-chain findings.
- Do not bypass pack registry, validation, approval, deployment, runtime binding, scope, ROE, credentials, or kill switch.
- No runtime self-modification.
- No uncontrolled plugin installation.
- No autonomous exploit chaining or full attack graph implementation.

## Validation

- `python3 scripts/validate_backlog_tasks.py`
- `source .venv/bin/activate && python -m pytest api/tests/ -q`
- `git diff --check`

## Acceptance

- AI proposes a compound chain when stored XSS and file upload evidence co-exist in the same engagement.
- AI proposes a code-execution chain when path traversal and writable filesystem/code execution signals co-exist in the same engagement.
- A compound attack-chain finding type or equivalent stored chain finding exists.
- Chain proposals appear in the Mission Control AI Proposals inbox.
- Chain reasoning uses only in-scope findings from the current engagement.
- No AI agent test regressions.
