# Backlog 240 Runner/Tool Certification Matrix Evidence

## Scope

Certification evidence only. No runner, detection capability, approval flow, pack validation, runtime binding, scope, ROE, credential, deployment, or kill-switch behavior was bypassed or weakened.

## Artifacts

- `codex/results/runner-tool-certification-matrix.json`
- `codex/results/runner-tool-certification-matrix.md`
- `scripts/build_runner_tool_certification_matrix.py`

## Matrix Summary

- tracked supported runners/tools: `54`
- certified by deterministic evidence plus output/report mapping: `53`
- supported-with-gap: `0`
- blocked: `1`
- hardware-only blocker: `wifi-survey`
- software readiness states on this build host: `15 ready`, `2 missing`, `37 not-required`

`wifi-survey` is blocked by missing deterministic wireless hardware lab / adapter proof while its installable software readiness remains separate. `nikto` and `sqlmap` are certified by deterministic evidence and mapping, but their host binaries were not detected on this build host.

## Runtime and Release-Readiness Consumption

- `/api/v1/settings/readiness` now exposes `runner_tool_certification` capability metadata.
- `/api/v1/diagnostics` now exposes a `runner_tool_certification` subsystem through the existing readiness flow.
- `scripts/run_enterprise_release_readiness.py` now reads `codex/results/runner-tool-certification-matrix.json` for the `runner_tool_readiness` support claim.

Release-readiness was regenerated locally and remains fail-closed:

- release status: `blocked`
- go/no-go: `no-go`
- `runner_tool_readiness`: `supported-with-gap`
- runner/tool claim metrics: `54` tools, `53` certified, `1` blocked

## Validation

- `python3 scripts/validate_backlog_tasks.py` passed before implementation with exactly one active task.
- `source .venv/bin/activate && python -m pytest workers/tests/test_runner_tool_certification_matrix.py -q` passed.
- `source .venv/bin/activate && python -m pytest api/tests/test_settings.py::test_settings_readiness_reports_tools_runtime_and_export_artifact api/tests/test_diagnostics.py::test_diagnostics_surfaces_subsystems_and_actionable_failures api/tests/test_release_readiness.py -q` passed.
- `python3 scripts/build_runner_tool_certification_matrix.py` generated the machine-readable and human-readable matrix artifacts.
- `python3 scripts/run_enterprise_release_readiness.py` regenerated release-readiness outputs and kept the gate `blocked`/`no-go`.
- `python3 scripts/validate_backlog_tasks.py` passed.
- `source .venv/bin/activate && python -m pytest workers/tests -q` passed.
- `source .venv/bin/activate && python -m pytest api/tests/test_settings.py -q` passed.
- `git diff --check` passed.

## Safe Acceptance

`http://127.0.0.1:8000` was relevant because this task affects Settings/Diagnostics operator readiness. The already-running process answered health checks but served old code: `/api/v1/settings/readiness` and `/api/v1/diagnostics` did not include `runner_tool_certification`.

Current-code acceptance used a temporary local Uvicorn host on `http://127.0.0.1:8017` with a local SQLite database:

- `/health/live`: `200`, `status=ok`, `runtime_state=healthy`
- `/api/v1/settings/readiness`: `200`, `runner_tool_certification.status=blocked`, `tool_count=54`, matrix path `codex/results/runner-tool-certification-matrix.json`
- `/api/v1/diagnostics`: `200`, `runner_tool_certification.status=blocked`, `tool_count=54`, matrix path `codex/results/runner-tool-certification-matrix.json`

## Remaining Risks

- The existing `http://127.0.0.1:8000` process needs restart before operators see the new readiness/diagnostics metadata there.
- Host binary readiness is environment-dependent; the matrix records this but does not install or repair tools.
- Wireless support remains blocked until a future explicit authorized hardware lab proves adapter/monitor-mode behavior safely.
- Enterprise release-readiness remains `blocked` because the broader accuracy evidence closure is the next queued task.
