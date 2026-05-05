# Active Task

## Title

AI reasoning transparency: restructure post-task analysis into Summary→Thought→Action and show each step to operators

## Promoted From

`codex/tasks/backlog-232-ai-reasoning-transparency-summary-thought-action.json`

## Goal

Implement explicit Summary→Thought→Action post-task AI reasoning transparency. The backend should store separate summary, thought, and action text for each analysis, and Mission Control should show that reasoning to operators before they approve or reject suggested actions.

## Scope

Implement the active backlog package `codex/tasks/backlog-232-ai-reasoning-transparency-summary-thought-action.json`.

Expected slice:

- update post-task AI analysis so `AgentReasoning` records store `summary_text`, `thought_text`, and `action_text` separately, either as model fields or in `metadata_json`
- map the existing observations, hypotheses, and proposals output into Summary, Thought, and Action sections
- update ChatGPT OAuth post-task analysis output handling to preserve the same three-part structure
- show a collapsible `AI Analysis` card in Mission Control under tasks that have AI analysis
- show Summary, Reasoning, Suggested Actions, and each proposal's `reasoning_text`
- hide the card when no AI analysis exists for a task

## Constraints

- Do not implement until this file is the single active task.
- Do not change proposal generation logic beyond reasoning-field structure.
- Do not change proposal approval gates.
- Do not change autonomous dispatch logic.
- Do not introduce a new reasoning model.
- Do not bypass pack registry, validation, approval, deployment, runtime binding, scope, ROE, credentials, or kill switch.
- No runtime self-modification.
- No uncontrolled plugin installation.

## Validation

- `python3 scripts/validate_backlog_tasks.py`
- `source .venv/bin/activate && python -m pytest api/tests/ -q`
- `git diff --check`

## Acceptance

- `AgentReasoning` records store summary, thought, and action text separately.
- Mission Control task list shows a collapsible AI Analysis card per completed task when analysis exists.
- The card shows Summary, Reasoning, Suggested Actions, and approve/reject controls for proposals.
- `AgentProposal.reasoning_text` is shown per proposal.
- The card is hidden when no analysis exists for a task.
- No AI agent or Mission Control E2E test regressions.
