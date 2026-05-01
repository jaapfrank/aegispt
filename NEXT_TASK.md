# Active Task

## Title

Fix AutoFix Suggested Fix section absent from findings drawer when ai.autofix_enabled=false

## Promoted From

`codex/tasks/backlog-159-autofix-section-missing-findings-drawer.json`

## Goal

Add an AutoFix section to the findings drawer that: (a) when ai.autofix_enabled=false shows a compact "AutoFix is disabled - enable in Settings > AI Provider" with a direct Settings link; (b) when ai.autofix_enabled=true and ai_fix_suggestion exists renders the suggestion with the advisory review/testing disclaimer from backlog-131; (c) when ai.autofix_enabled=true but no suggestion shows "No suggestion available - re-run with AutoFix enabled". Never auto-apply code. Use existing FindingRemediation.ai_fix_suggestion field - no new API endpoints needed.

## Scope

Implement the active backlog package `codex/tasks/backlog-159-autofix-section-missing-findings-drawer.json`.

Expected slice:

- make the AutoFix section visible in the finding drawer at all times
- when disabled, show an enable-in-Settings hint with a direct Settings action
- when enabled with an existing suggestion, render that suggestion with the advisory review/testing disclaimer
- when enabled without a suggestion, show a truthful no-suggestion-yet message
- do not add new API endpoints
- do not auto-apply code or mutate repositories

## Constraints

- Keep Prompt 1 and Prompt 2 intact.
- Do not bypass approval gates, pack registry, validation, deployment, or runtime binding.
- No runtime self-modification.
- Fix only the specific bug described.
- Do not use this task for broad redesign.
- Do not install new tools.
- Do not run live customer or intrusive targets.
- Do not change unrelated schemas or prompts.

## Validation

- `python3 scripts/validate_backlog_tasks.py`
- `source .venv/bin/activate && python -m pytest api/tests/test_health.py -q`
- `git diff --check`

## Acceptance

- AutoFix section is visible in the finding drawer at all times.
- When disabled: shows "AutoFix disabled - enable in Settings" with a link.
- When enabled with `ai_fix_suggestion`: shows the suggestion with advisory disclaimer.
- When enabled but no suggestion: shows "No suggestion yet" message.
- No new API endpoints are added; the drawer uses existing `FindingRemediation.ai_fix_suggestion`.
