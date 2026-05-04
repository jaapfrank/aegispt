# Active Task

## Title

Tool install and enable control plane: make missing tools repairable and gated features one-click configurable

## Promoted From

`codex/tasks/backlog-215-tool-install-and-enable-control-plane.json`

## Goal

AegisPT must ship with all software-based pentest tool groups installable by the official installer/container image, and Settings must provide concrete repair/install and governed enable/configure actions instead of vague degraded/blocked labels.

## Scope

Implement the active backlog package `codex/tasks/backlog-215-tool-install-and-enable-control-plane.json`.

Expected slice:

- official host installer and Compose image include all tracked software tool groups where packages are available
- readiness detection accepts actual command names used by AegisPT runners, including Impacket `.py` commands and compatibility aliases
- Settings shows each degraded software tool group with a concrete Install/Repair action or copyable privileged command
- Settings distinguishes software-missing from hardware-missing, especially WiFi software versus wireless adapter hardware
- disabled but supported capabilities expose governed Enable/Configure actions that only write settings and do not execute tools
- write post-install verification evidence or exact privilege/hardware blockers

## Constraints

- Keep Prompt 1 and Prompt 2 intact.
- Install/repair and enablement UX only.
- Do not auto-run pentest tools.
- Do not auto-enable intrusive execution.
- Do not bypass authorization, approval, scope, ROE, pack validation, deployment, runtime binding, credential gates, or kill-switch controls.
- No runtime self-modification.
- Do not install uncontrolled plugins.
- Do not run live target actions.

## Validation

- `python3 scripts/validate_backlog_tasks.py`
- `source .venv/bin/activate && python -m pytest api/tests/test_settings.py -q`
- `source .venv/bin/activate && python -m pytest ui/tests/test_operator_console_smoke_e2e.py -q`
- `bash scripts/verify_host.sh` or documented privilege-safe equivalent on a prepared host
- `git diff --check`

## Acceptance

- Readiness reports software tool groups ready on the prepared host or records exact install blockers.
- Settings exposes actionable install/repair/enable controls instead of vague degraded text.
- Hardware-only blockers remain honest and separate from software installation gaps.
- No pentest tool is executed against a live target as part of installation or enablement.
