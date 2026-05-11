# Active Task

## Title

AI Adaptive Pentest: Intake Creates ai_loop Runs + Auto-Dispatch Passive Tasks

## Goal

The Intake wizard must offer a third run mode alongside Manual Wizard and AI Guided chat: 'AI Adaptive Pentest'. This mode creates a run with run_mode=ai_loop in configuration_json, no fixed phase chain. After the run is created, the assessment loop must dispatch passive tasks automatically without requiring operator intervention. Currently advance_assessment_loop() queues passive tasks with dispatch_mode='queued_not_dispatched' — this must be changed to actually dispatch them through the existing task dispatch path so the loop progresses on its own. Active/intrusive candidates continue to require operator approval (proposal flow).

## Scope

- `ui-v2/src/components/Intake.tsx`
- `api/app/services/assessment_loop.py`
- `workers/orchestration/tasks.py`

## Constraints

- Do not bypass scope/ROE, approval gates for active/intrusive runners, credential materialization, runtime gate mutation, or kill-switch behavior.
- Passive tasks only auto-dispatch; active runners stay behind the existing proposal/approval flow.

## Source Package

`codex/tasks/backlog-336-ai-loop-intake-and-auto-dispatch.json`

## Required Reading

- `CURRENT_STATE.md`
- `TASK_QUEUE.md`
- `TESTING_POLICY.md`

## Validation

- `python3 scripts/validate_backlog_tasks.py`
- `.venv/bin/pytest`
- `cd ui-v2 && npm run build`
- `cd ui-v2 && npm run test:e2e`
- `cd ui-v2 && npm run lint`
- `git diff --check`
