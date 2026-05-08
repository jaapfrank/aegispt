# Active Task

## Title

AI Goal-Oriented (CTF) Reasoning Mode

## Promoted From

`codex/tasks/backlog-303-goal-oriented-ctf-reasoning-mode.json`

## Goal

Instead of asking the AI to "find vulnerabilities", allow operators to set an objective: "Access the billing database" or "Gain Domain Admin". The AI reasons backward from the goal, formulating a kill-chain hypothesis. It specifically seeks and chains controlled proof paths designed to reach that explicit objective, mimicking an advanced adversary while remaining inside AegisPT approval, scope, ROE, runner registry, provenance, and kill-switch controls.

## Scope

AI post-exploitation and multi-step reasoning.

## Constraints

- Do not implement until this package is the single active task in NEXT_TASK.md.
- Keep execution behind registered runners or approved flows.
- Do not bypass existing approval gates, scope/ROE boundaries, credential protections, runtime binding, reports, provenance, or kill switch.
- Do not perform runtime self-modification or uncontrolled plugin installation.
- Preserve manual wizard and fixed-chain flows; goal-oriented reasoning applies only to explicitly configured AI/ai_loop runs.

## Validation

- `python3 scripts/validate_backlog_tasks.py`
- `pytest api/tests/`

## Acceptance

- A goal-oriented AI run records an explicit operator objective.
- The planner derives a bounded, evidence-linked hypothesis path toward the objective.
- Proposed/queued actions remain tied to existing runners, approvals, rationale/provenance, and scope/ROE gates.
