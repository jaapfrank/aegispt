# Active Task

## Title

Launch authorization and phase auto-advance contract

## Promoted From

`codex/tasks/backlog-180-launch-authorization-auto-advance-contract.json`

## Goal

Make mission launch authorization carry through the assessment chain so operators are not forced to re-confirm every phase when they already selected and authorized the intended depth at launch.

## Scope

Implement the active backlog package `codex/tasks/backlog-180-launch-authorization-auto-advance-contract.json`.

Expected slice:

- make Full / all-phases launch-time authorization durable and visible in chain state
- auto-advance already-authorized non-exploitation phases when prerequisites are satisfied
- show exact remaining gate reasons and safe next actions for missing credentials, missing evidence prerequisites, missing tools, scope expansion, intrusive exploitation, or failed runner review
- make Wizard preview clear about which phases can auto-advance and which phase types still require manual approval
- make Mission Control phase cards distinguish pre-authorized, auto-advancing, waiting-on-prerequisite, and manual-approval-required states

## Constraints

- Keep Prompt 1 and Prompt 2 intact.
- Do not bypass approval gates, pack registry, validation, deployment, or runtime binding.
- No runtime self-modification.
- Do not install uncontrolled plugins.
- Only fix launch-time authorization carry-through, phase auto-advance clarity, and remaining-gate explanations.
- Do not bypass pack validation, runtime binding, scope enforcement, kill switch, credential prerequisites, or explicit exploitation authorization.
- Do not install or execute new tools.
- Do not run live customer or intrusive targets.
- Do not add uncontrolled autonomous execution.
- Do not weaken explicit exploitation, credential, scope, or kill-switch gates.

## Validation

- `python3 scripts/validate_backlog_tasks.py`
- `source .venv/bin/activate && python -m pytest api/tests/test_assessment_chain.py api/tests/test_runs.py -q`
- `source .venv/bin/activate && python -m pytest ui/tests/test_operator_console_e2e.py ui/tests/test_operator_console_smoke_e2e.py -q`
- `git diff --check`
- Focused authorization/phase-chain coverage for full-depth launch, no-credentials launch, credentialed launch, and exploitation-gated launch behavior
- Browser/safe acceptance where relevant

## Acceptance

- Full Internal LAN with launch-time authorization does not ask for redundant phase confirmations for already-authorized non-exploitation phases.
- No-credentials missions explain credential-dependent gates instead of silently skipping or repeatedly asking for approval.
- Intrusive exploitation remains explicitly gated unless the launch flow recorded specific exploitation authorization that satisfies the existing safety contract.
- Mission Control shows what is authorized, what is next, and why anything is blocked.
