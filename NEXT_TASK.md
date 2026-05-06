# Active Task

## Title

Wire all new runners (214-249) into RunProfiles, assessment chains, and wizard depth triggers

## Promoted From

`codex/tasks/backlog-250-new-runners-wizard-profile-wiring.json`

## Goal

Implement the active backlog package `codex/tasks/backlog-250-new-runners-wizard-profile-wiring.json` so runners added in tasks 214-249 are reachable through RunProfiles, assessment-chain phases, wizard depth triggers, and acceptance harness mapping instead of remaining dead code.

## Scope

Implement the active backlog package `codex/tasks/backlog-250-new-runners-wizard-profile-wiring.json`.

Expected slice:

- add or confirm RunProfile entries for all new web, LAN/network, AI shell, crypto, and RCE runner profiles listed in the task package
- assign each new RunProfile to at least one relevant assessment-chain phase
- update `wizard.js` execution-profile/depth trigger logic so the correct tile and depth combinations select the new profiles while preserving the existing manual wizard path
- add the new profile names to `scripts/acceptance_harness.py` `PROFILE_TOOL_MAP`
- preserve existing profile tool lists and approval gate logic; add wiring only where needed

## Constraints

- Do not implement until this file is the single active task.
- Do not change runner implementations.
- Do not change approval gate thresholds.
- Add to existing profile/chain behavior without removing existing tools.
- Preserve the existing handmatige/wizard path; AI-assisted/adaptive UI work is not part of this task unless the active package explicitly requires it.
- Do not bypass pack registry, validation, approval, deployment, runtime binding, scope, ROE, credentials, or kill switch.
- No runtime self-modification.
- No uncontrolled plugin installation.

## Validation

- `python3 scripts/validate_backlog_tasks.py`
- `source .venv/bin/activate && python -m pytest api/tests/ -q`
- `python3 scripts/acceptance_harness.py --smoke`
- `git diff --check`

## Acceptance

- Every new runner from tasks 214-249 has a corresponding RunProfile entry in `api/app/services/run_profiles.py`.
- Every new RunProfile is assigned to at least one assessment-chain phase in `api/app/services/assessment_chain.py`.
- `ui/assets/modules/wizard.js` includes the required tile and depth trigger rules.
- `scripts/acceptance_harness.py` includes all new profiles in `PROFILE_TOOL_MAP`.
- External Web + Active wizard flow dispatches the expected new web runners, including XXE.
- Internal LAN + Full depth dispatches `ssh-brute`, `network-capture`, and `priv-esc-linux`.
- Existing wizard flow tests do not regress.
