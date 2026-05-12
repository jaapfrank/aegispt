# Active Task

## Title

Mission Control: AI Adaptive Loop Panel showing Iteration Chain and Hypotheses

## Goal

When a run uses run_mode=ai_loop, Mission Control must replace the Phase Chain panel with an AI Loop panel showing: current iteration and status; last AI hypothesis (what and why); chain of findings→actions; what is queued next and why; label 'AI Adaptive Pentest'. Standard/chain runs keep the existing Phase Chain panel.

## Scope

- `ui-v2/src/components/screens/MissionControl.tsx`

## Constraints

- No new backend API endpoints — use existing `/api/v1/runs/{id}/ai-insights`.
- Standard and chain run views must remain unchanged.
- `npm run build` must pass with no TypeScript errors.

## Source Package

`codex/tasks/backlog-338-mission-control-ai-loop-panel.json`

## Validation

- `cd ui-v2 && npm run build`
- `python3 scripts/validate_backlog_tasks.py`
