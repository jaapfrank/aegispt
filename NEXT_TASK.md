# Active Task

## Title

Tool capability guide: expose all 33 implemented tools with descriptions, when to use them, and what findings they produce

## Promoted From

`codex/tasks/backlog-209-tool-capability-guide-and-selection-intelligence.json`

## Goal

AegisPT operators must be able to see the implemented tool catalogue inside the product, understand what each tool is for, what authorization tier it requires, and how it fits into assessment modes, without changing runner dispatch logic.

## Scope

Implement the active backlog package `codex/tasks/backlog-209-tool-capability-guide-and-selection-intelligence.json`.

Expected slice:

- add an operator-facing Tool Library view accessible from Pack Forge or Settings
- show all 33 implemented tools with name, category, short description, typical findings, and required authorization tier
- provide a detail view for each tool with example findings, prerequisites, and chain membership
- add a quick-add path that creates a manual task proposal for operator approval
- keep this as transparency/catalogue work only

## Constraints

- Keep Prompt 1 and Prompt 2 intact.
- Display existing tool capabilities only.
- Do not add new tools.
- Do not change tool dispatch logic.
- Do not bypass authorization, approval, scope, ROE, pack validation, deployment, runtime binding, credential gates, or kill-switch controls.
- No runtime self-modification.
- Do not run live target actions.

## Validation

- `python3 scripts/validate_backlog_tasks.py`
- `source .venv/bin/activate && python -m pytest api/tests/test_health.py -q`
- `git diff --check`

## Acceptance

- Tool Library shows all 33 tools.
- Each tool has description and authorization tier.
- Clicking a tool shows detail with findings, prerequisites, and chain membership.
- Add-to-run creates a manual task proposal for approval.
- No runner dispatch or approval behavior is changed.
