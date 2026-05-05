# Active Task

## Title

AI Proposals Inbox: make AI-generated next-step proposals visible and actionable in Mission Control

## Promoted From

`codex/tasks/backlog-205-ai-proposals-inbox-operator-visibility.json`

## Goal

The AI agent generates AgentProposal records after completed tool runs, but operators cannot see or act on those suggested next steps in Mission Control. Add a visible AI proposals inbox for the active run, with approval and rejection actions grounded in the existing proposal/dispatch mechanisms.

## Scope

Implement the active backlog package `codex/tasks/backlog-205-ai-proposals-inbox-operator-visibility.json`.

Expected slice:

- show a Mission Control panel listing pending AgentProposal records for the active run
- show tool, target, risk tier, confidence, and one-line reasoning for each proposal
- add approve and reject controls for each proposal
- approved proposals dispatch as queued tasks through the existing mechanism
- rejected proposals are marked rejected and removed from the visible pending list
- show a pending proposal badge/count on the Mission Control navigation item
- hide the panel when no proposals exist

## Constraints

- Do not change AI agent proposal generation logic.
- Do not change proposal confidence scoring.
- Do not bypass approval gates for intrusive tools.
- Do not bypass scope, ROE, approval, validation, deployment, runtime binding, credentials, or kill switch.
- No runtime self-modification.
- No uncontrolled plugin installation.

## Validation

- `python3 scripts/validate_backlog_tasks.py`
- `source .venv/bin/activate && python -m pytest api/tests/test_health.py -q`
- `git diff --check`

## Acceptance

- AI proposals panel renders in Mission Control.
- Approve action dispatches proposal as a task.
- Reject action removes proposal from the panel.
- Pending proposal badge/count updates for Mission Control.
- Panel hidden when no proposals exist.
- E2E tests pass.
