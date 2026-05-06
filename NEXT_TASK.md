# Active Task

## Title

Kill chain progress rate tracking: map findings and phase completions to MITRE ATT&CK stages and show progress gauge

## Promoted From

`codex/tasks/backlog-235-kill-chain-progress-rate-tracking.json`

## Goal

Implement kill chain progress tracking so AegisPT can map stored findings and assessment progress to MITRE ATT&CK-style stages and show assessment depth as an operator-facing progress gauge.

## Scope

Implement the active backlog package `codex/tasks/backlog-235-kill-chain-progress-rate-tracking.json`.

Expected slice:

- add static finding-to-ATT&CK tactic mapping without changing finding schema
- compute engagement kill-chain progress and progress percentage from existing findings and phase/completion signals
- render a Mission Control kill-chain progress strip with completed, current, and future stages
- expose MITRE ATT&CK matrix coverage in the engagement dossier / Explorer surface
- keep the mapping deterministic and grounded in stored evidence

## Constraints

- Do not implement until this file is the single active task.
- Do not change finding schema.
- Do not change threat-intel sync behavior.
- Do not change run dispatch logic.
- Do not bypass pack registry, validation, approval, deployment, runtime binding, scope, ROE, credentials, or kill switch.
- No runtime self-modification.
- No uncontrolled plugin installation.

## Validation

- `python3 scripts/validate_backlog_tasks.py`
- `source .venv/bin/activate && python -m pytest api/tests/ -q`
- `git diff --check`

## Acceptance

- Each supported finding type maps to a MITRE ATT&CK tactic/stage.
- Mission Control shows a kill-chain progress strip.
- Completed stages render as complete, current stage renders as in progress/current, and untested stages render as future/untested.
- Explorer/dossier shows MITRE ATT&CK matrix coverage.
- Progress percentage is computed and shown numerically.
- Mission Control and Explorer coverage do not regress.
