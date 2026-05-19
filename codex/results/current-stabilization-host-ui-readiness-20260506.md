# Current Stabilization Host/UI Readiness Evidence

Date: 2026-05-06

Scope:
- Correct current host/readiness/product-truth problems before continuing with the active backlog task.
- Do not execute backlog-247 implementation.
- Keep existing pack registry, validation, approval, deployment, runtime binding, scope, ROE, credentials, and kill-switch boundaries intact.

Repairs:
- Installed and verified host binaries previously recorded as missing or blocked: `tcpdump`, `arping`, `arpspoof`, `gobuster`, `nikto`, `sqlmap`, and `hydra`.
- Updated `scripts/verify_host.sh` so Hydra help output is accepted even though this Hydra build exits non-zero for `-h`.
- Wired the already-registered new web security profiles into the Full External Web active chain and Wizard mission preview.
- Regenerated runner/tool certification evidence after host install; software readiness now has no missing software groups.
- Reclassified runner/tool certification readiness as `ready_with_hardware_limitation` when the only blocked certification item is hardware-specific WiFi lab proof.
- Added explicit Settings guidance that WiFi assessment requires an authorized monitor-mode capable USB WiFi adapter such as Alfa AWUS036ACH.
- Removed temporary generated backlog-252/backlog-253 queue entries after the reported issues were fixed in this stabilization pass.
- Removed generated non-queue pack-refinement task state from `codex/tasks/` so the queue remains the single source for task promotion.
- Closed stale local development run metadata through existing governed runtime endpoints; diagnostics now reports no queued/running tasks and no stuck active-like runs.
- Hid stale-running Mission Control guidance for cancelled/non-running selected tasks.

Validation evidence:
- `bash scripts/verify_host.sh` completed successfully.
- `python3 scripts/build_runner_tool_certification_matrix.py --output-json codex/results/runner-tool-certification-matrix.json --output-md codex/results/runner-tool-certification-matrix.md` completed successfully.
- `python3 scripts/run_enterprise_release_readiness.py --output-json codex/results/enterprise-release-readiness.json --output-md codex/results/enterprise-release-readiness.md` completed successfully and kept release readiness `blocked` because validation accuracy and FP/FN posture remain unresolved.
- Playwright acceptance against `http://127.0.0.1:8000/app/` proved External Web + Active preview shows `23 runners` and includes XXE, JWT, SSRF, GraphQL, SSTI, HTTP smuggling, IDOR, and Headers security.
- Playwright/API readiness acceptance proved `runner_tool_certification.status=ready_with_hardware_limitation`, `wireless_readiness.status=blocked`, and WiFi hardware guidance is visible.
- Playwright/API runtime acceptance proved `queue_state.status=ready`, `run_stuck.status=ready`, no queued-task badge, and no stale-running callout on the selected cancelled task.

Evidence artifacts:
- `codex/results/stabilization-stale-run-recovery-20260506.json`
- `codex/results/stabilization-run-cancel-cleanup-20260506.json`
- `codex/results/stabilization-ui-acceptance-20260506.json`
- `codex/results/stabilization-web-chain-preview-20260506.png`
- `codex/results/stabilization-settings-readiness-20260506.png`
- `codex/results/stabilization-mission-control-20260506.png`

Remaining risks:
- `wifi-survey` remains hardware-limited until authorized monitor-mode WiFi hardware and lab proof are available.
- Enterprise release readiness remains `blocked` for known-vulnerability detection accuracy and false-positive/false-negative posture, not for software tool installation.
- The active task remains backlog-247 `sqlmap blind and advanced SQLi`; this stabilization pass did not implement that task.
