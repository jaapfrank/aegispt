# Active Task

## Title

Mythos Phase 4 — Non-HTTP Primitives: SMB and LDAP as exec_plan Steps

## Goal

Extend the `exec_plan` grammar to allow SMB (list shares, file read, NTLM auth attempt) and LDAP (bind, search) as step types alongside HTTP. First move toward truly universal cross-protocol attack composition: AI can now write a single exec_plan that proves web → SMB or web → LDAP chains in one continuous narrative.

## Scope

- Extend `workers/runners/exec_plan/runner.py` with two new step kinds:
  - `smb_request` with subcommands `list_shares` / `read_file` / `ntlm_auth_attempt`, wrapping the existing impacket / netexec primitives.
  - `ldap_request` with subcommands `bind` / `search`, wrapping the existing `ldap_enum` primitives.
- Reuse the existing scope check + capture / expect / on_success contract.
- System prompt grammar section gets a BRIEF addendum showing the two new step kinds (no rewrite of existing exec_plan grammar).

## Constraints

- SMB + LDAP ONLY. Do NOT add SSH, RDP, Kerberos, or DNS step kinds in this task — those are follow-up scope.
- Implementation MUST wrap existing `impacket` / `netexec` / `ldap_enum` primitives, not re-implement protocol clients.
- SMB step kinds are intrusive tier by default. LDAP queries can be active tier (read-only).
- System prompt grammar section gets a brief addendum showing the two new step kinds — do NOT rewrite existing exec_plan grammar.
- Must NOT touch: `workers/runners/impacket/` core logic, `workers/runners/netexec/runner.py` core logic, `workers/runners/ldap_enum/runner.py` core logic, `api/app/models/control.py`, `api/app/services/run_credential_vault.py`.

## Source Package

`codex/tasks/backlog-386-non-http-primitives-smb-ldap.json`

## Reference

- `workers/runners/exec_plan/runner.py` — existing HTTP step grammar (the addendum follows the same shape)
- `workers/runners/impacket/runner.py` + `workers/runners/netexec/runner.py` — SMB primitives we consume
- `workers/runners/ldap_enum/runner.py` — LDAP primitives we consume
- `api/app/services/assessment_loop.py` — `_AI_PICKER_SYSTEM_PROMPT`; the grammar addendum lands BELOW line 200 (the protected range carried forward from #330/#331/#332/#334/#343)
- The 3 live-reliability fixes (#336/#337/#338) just merged — a live re-test against Gruyere is now operator-class action; this task continues Phase 4 work in parallel.

## Validation

- `python3 scripts/validate_backlog_tasks.py`
- `.venv/bin/pytest workers/tests/test_exec_plan.py workers/tests/test_exec_plan_smb.py workers/tests/test_exec_plan_ldap.py`
- `python3 -m compileall -q workers api`
- `.venv/bin/ruff check workers/runners/exec_plan/runner.py`
- `git diff --check`
