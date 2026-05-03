# Active Task

## Title

Mission Control AI Signal panel: remove developer labels (DETERMINISTIC MODE, BUILD LANE, PROVIDER, SIGNALS, REPAIRS)

## Promoted From

`codex/tasks/backlog-196-mission-control-ai-signal-developer-labels.json`

## Goal

Remove developer-facing AI Signal labels from Mission Control and replace them with operator-appropriate copy and a clean empty state.

## Scope

Implement the active backlog package `codex/tasks/backlog-196-mission-control-ai-signal-developer-labels.json`.

Expected slice:

- remove or replace `DETERMINISTIC MODE` with operator-facing language such as review/supervised context
- remove `BUILD LANE` from the operator-facing Mission Control AI Signal panel
- replace internal headings such as `PROVIDER`, `SIGNALS`, and `REPAIRS` with operator-appropriate copy
- rewrite the review-only AI constraint into clear operator language
- simplify the no-run empty state to one clean message

## Constraints

- Keep Prompt 1 and Prompt 2 intact.
- Do not change AI Signal data fetching, signal rendering logic, backend APIs, approval gates, pack lifecycle, deployment, runtime binding, scope enforcement, credential gates, or kill switch behavior.
- No runtime self-modification.
- Do not install uncontrolled plugins.
- Do not run live target actions.

## Validation

- `python3 scripts/validate_backlog_tasks.py`
- `source .venv/bin/activate && python -m pytest api/tests/test_health.py -q`
- `git diff --check`

## Acceptance

- `DETERMINISTIC MODE` is not visible as an operator-facing Mission Control label.
- `BUILD LANE` is not visible in Mission Control.
- AI Signal empty state shows a single clean message when no run is selected.
- AI panel section headings are operator-appropriate.
- Focused Mission Control/UI validation passes.
