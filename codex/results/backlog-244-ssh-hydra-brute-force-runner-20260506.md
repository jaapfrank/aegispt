# backlog-244 SSH/Service Hydra Brute Force Runner Evidence

Date: 2026-05-06

## Scope

The active task was `backlog-244-ssh-hydra-brute-force-runner`, promoted from `codex/tasks/backlog-244-ssh-hydra-brute-force-runner.json`.

The implementation stayed inside the approved build lane and added a bounded `ssh-brute` runner for SSH, FTP, Telnet, and RDP weak-credential validation. It did not change the existing AD/Kerberos `credential-attacks` runner except for coexistence through run/profile registration.

`http://127.0.0.1:8000` was relevant because the task changed wizard/profile browser wiring and served asset cache keys.

## Implementation Evidence

- `ssh-brute` was added to `SUPPORTED_TOOLS` and dispatches to `workers.runners.ssh_brute.runner.execute_ssh_brute_force`.
- `ssh-brute-results.json` is recognized by the existing normalized finding extraction path.
- `active-lan-ssh-brute` was added as an active RunProfile with `required_approvals: 1`, `approval_step_id: active-lan-ssh-brute`, max 5 attempts/second, top-50 passwords first, max 200 attempts/service, max 50 custom passwords, and stop after 3 lockout signals.
- `active-lan-ssh-brute` is reachable through FULL-INTERNAL-LAN, FULL-LAN-IOT, FULL-AD-ASSESSMENT, host follow-up profiles, wizard prediction matrix, tool catalog, plan fallbacks, and acceptance harness mapping.
- Hydra installation/readiness was wired through `scripts/install_security_tools.sh`, `scripts/verify_host.sh`, Settings tool readiness, and the runner/tool certification matrix.

## Safe Live Lab

A local-only Docker lab was used:

- Hydra image: temporary `aegispt-ssh-brute-hydra-244`, built from `ubuntu:24.04` with the Ubuntu `hydra` package.
- Target image: temporary `aegispt-ssh-brute-target-244`, built from `ubuntu:24.04` with OpenSSH enabled for user `ac0`.
- Target binding: `127.0.0.1:2222 -> container:22`.
- Runner scope allowlist: `{"hosts": ["127.0.0.1"]}`.
- Runner target/service: `127.0.0.1:2222` / SSH.
- Result: accepted weak credential finding `Weak Credential: SSH ac0:password on 127.0.0.1:2222`.
- Evidence JSON: `codex/results/backlog-244-ssh-hydra-live-lab-20260506.json`.
- The target container and temporary validation images were removed after the proof.

Host truth: `hydra` is not installed on this build host, but `apt-cache policy hydra` showed candidate `9.5-1build3`. The certification matrix records host binary readiness as missing while installation wiring is present.

## Browser Acceptance

The local current-code host was restarted with `AEGISPT_LOCAL_ENSURE_ZAP=0`:

- URL: `http://127.0.0.1:8000/app/`
- Health: `http://127.0.0.1:8000/health/live`
- Served app asset: `./assets/app.js?v=20260506-ssh-brute-1`

Browser acceptance imported the current wizard module and verified that `active-lan-ssh-brute` appears in active/full chain profiles for:

- `internal-lan`
- `active-directory`
- `full-internal`
- `smart-home-lan`

No browser page errors or console errors were recorded.

Evidence:

- `codex/results/backlog-244-wizard-ssh-brute-8000.json`
- `codex/results/backlog-244-wizard-ssh-brute-8000.png`

## Validation

Passed:

- `python3 scripts/validate_backlog_tasks.py`
- `python3 -m compileall workers/runners/ssh_brute workers/orchestration/tasks.py workers/orchestration/findings.py api/app/services/runs.py api/app/services/run_profiles.py api/app/services/assessment_chain.py api/app/routers/runs.py api/app/services/settings.py scripts/build_runner_tool_certification_matrix.py scripts/acceptance_harness.py`
- `node --input-type=module --check < ui/assets/modules/wizard.js`
- `node --input-type=module --check < ui/assets/modules/shared.js`
- `node --input-type=module --check < ui/assets/modules/packs.js`
- `node --input-type=module --check < ui/assets/app.js`
- `bash -n scripts/install_security_tools.sh scripts/verify_host.sh`
- `source .venv/bin/activate && python -m pytest workers/tests/test_ssh_brute_runner.py workers/tests/test_runner_tool_certification_matrix.py -q`
- `source .venv/bin/activate && python -m pytest api/tests/ -q`
- `source .venv/bin/activate && python -m pytest ui/tests/test_wizard_input_prediction_matrix_e2e.py -q`
- safe local Docker Hydra runner acceptance against `127.0.0.1:2222`
- current-code browser acceptance on `http://127.0.0.1:8000`
- `python3 scripts/build_runner_tool_certification_matrix.py --output-json codex/results/backlog-244-runner-tool-certification-matrix-20260506.json --output-md codex/results/backlog-244-runner-tool-certification-matrix-20260506.md`
- post-promotion `python3 scripts/validate_backlog_tasks.py`
- post-promotion `git diff --check`

Not claimed:

- `source .venv/bin/activate && python -m pytest scripts/tests/test_runner_tool_certification_matrix.py -q` was a wrong-path attempt and exited with code 4 before being rerun correctly as `workers/tests/test_runner_tool_certification_matrix.py`.

## Boundaries

- No public, customer, or third-party target was brute-forced.
- No rockyou or large wordlist was used.
- No mass credential stuffing was implemented.
- No pack registry, validation, approval, deployment, runtime binding, scope, ROE, credential gate, or kill-switch path was bypassed.
- No runtime self-modification or uncontrolled plugin installation occurred.
