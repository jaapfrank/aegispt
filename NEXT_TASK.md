# Active Task

## Title

Non-HTTP Primitives: SMB and LDAP as exec_plan Steps (Phase 4 day 3)

## Goal

Extend the exec_plan grammar to allow SMB (list shares, file read, NTLM auth attempt) and LDAP (bind, search) as step types alongside HTTP. First move toward truly universal cross-protocol attack composition: AI can now write a single exec_plan that proves web → SMB or web → LDAP chains in one continuous narrative.

## Scope

- Extend `workers/runners/exec_plan/runner.py` with two new step kinds:
  - `smb_request` (subcommands list / read / auth using existing impacket or netexec primitives)
  - `ldap_request` (using existing ldap_enum primitives)
- Reuse the existing scope check + capture/expect/on_success contract.
- Schema updates documented in system prompt minimally (the prompt body is otherwise must_not_touch; brief note can be appended outside lines 1-200).

## Constraints

- New step kinds only. Do NOT change the existing HTTP step grammar, do NOT add other protocols (FTP, SSH, etc.) in this task, do NOT replace the underlying impacket/netexec/ldap_enum runners.
- Reuse existing scope/ROE/tier governance — no new bypass routes.
- Bounded: per-step timeout + overall plan budget honored (existing exec_plan caps apply).
- Must NOT touch: `_AI_PICKER_SYSTEM_PROMPT` body lines 1-200, finding schema fields, `workers/runners/impacket/`/`workers/runners/netexec/`/`workers/runners/ldap_enum/` runner implementations (consume them, don't modify).

## Source Package

`codex/tasks/backlog-386-non-http-primitives-smb-ldap.json`

## Reference

- `workers/runners/exec_plan/runner.py` (existing HTTP step engine; #334 added captured_value emission)
- `workers/runners/impacket/runner.py` + `workers/runners/netexec/runner.py` + `workers/runners/ldap_enum/runner.py` (underlying primitives)
- `api/app/services/finding_verifier.py` (#335 — verifier strategies could later extend to cover SMB/LDAP findings)
- `docs/AGENT_SYSTEM_MAP.md` §7 (scope/ROE governance) + §3 (exec_plan grammar)

## Validation

- `python3 scripts/validate_backlog_tasks.py`
- `.venv/bin/pytest workers/tests/test_exec_plan_smb_ldap.py workers/tests/test_exec_plan_runner.py`
- `python3 -m compileall -q workers`
- `.venv/bin/ruff check workers/runners/exec_plan/`
- `git diff --check`
