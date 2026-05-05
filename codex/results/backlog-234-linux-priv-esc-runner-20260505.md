# Backlog 234 Evidence - Linux Privilege Escalation Enumeration Runner

## Scope

Completed the active task from `codex/tasks/backlog-234-linux-privilege-escalation-enumeration.json`.

## Runtime and Safety Truth

- Added `priv-esc-linux` as a read-only SSH enumeration runner for approved Linux targets.
- Requires configured SSH auth context, approved target scope, runtime binding, approval, and kill-switch enforcement through existing AegisPT flows.
- Records that no SUID/SGID exploitation, privilege escalation, privileged sudo command, target filesystem write, runtime mutation, or bypass was attempted.
- Password auth uses `sshpass -e` with `SSHPASS` environment binding; secrets are not emitted into command previews, findings, or artifacts.

## Coverage

- SUID/SGID GTFOBins-style dangerous binary matching.
- `sudo -n -l` parsing for `NOPASSWD`, broad `ALL=(ALL:ALL) ALL`, and risky command entries.
- Writable cron paths.
- Weak `/etc/passwd` and `/etc/shadow` permissions.
- Credential-like backup file signals with redaction.
- Writable early PATH directories.
- Conservative kernel local privilege-escalation CVE signals for Dirty Pipe and Baron Samedit.

## UI Acceptance

Read-only local acceptance on `http://127.0.0.1:8000/app/` confirmed:

- `http://127.0.0.1:8000` was relevant because wizard/run-profile/assessment-chain/operator surfaces changed.
- Full Internal full-depth expected chain includes `intrusive-credential-priv-esc-linux`.
- Wizard preview includes Linux local escalation signals in Phase 3.

Evidence files:

- `codex/results/active-task-priv-esc-linux-browser-acceptance-20260505.json`
- `codex/results/active-task-priv-esc-linux-wizard-preview-20260505.png`

## Validation

- `python3 scripts/validate_backlog_tasks.py` passed before implementation.
- `python3 -m py_compile workers/runners/priv_esc_linux/runner.py workers/orchestration/tasks.py workers/orchestration/findings.py api/app/services/runs.py api/app/routers/runs.py api/app/services/run_profiles.py api/app/services/assessment_chain.py` passed.
- `python3 -m pytest workers/tests/test_priv_esc_linux_runner.py -q` passed.
- Focused API/registration/assessment-chain tests passed.
- Required gate passed after final UI change: `source .venv/bin/activate && python -m pytest api/tests/ -q`.
- Final backlog validator and `git diff --check` passed after promoting backlog-236 into `NEXT_TASK.md`.

## Not Claimed

- No live Gruyere, WebGoat, public internet, or LAN SSH host was scanned.
- No privilege escalation or exploitation was attempted.
- Kernel CVE matches are signals requiring human patch/backport review.
