# Active Task

## Title

Runner and tool certification matrix: prove each supported assessment family has install, fixture, output, and report evidence

## Promoted From

`codex/tasks/backlog-240-runner-tool-certification-matrix.json`

## Goal

Make the supported-tool and supported-runner surface enterprise-verifiable by certifying every tracked assessment family against installation readiness, safe fixture/lab proof, normalized output contracts, evidence artifacts, report mapping, and known limitations.

## Scope

Implement the active backlog package `codex/tasks/backlog-240-runner-tool-certification-matrix.json`.

Expected slice:

- create a machine-readable runner/tool certification matrix for tracked tool groups and custom runners
- record installed/ready state, required authorization tier, safe fixture or benchmark proof, expected artifact schema, finding/report mapping, false-positive guardrails, and unsupported/hardware blockers
- separate software readiness from hardware-only blockers such as wireless adapters
- link each supported runner claim to deterministic tests, fixture/lab evidence, or an honest supported-with-gap/blocked reason
- feed or reference the matrix from Settings/Diagnostics and enterprise release-readiness outputs where the task package requires it
- keep this slice to certification evidence only; do not add new runners or new detection capabilities

## Constraints

- Keep Prompt 1 and Prompt 2 intact.
- Do not bypass local provenance, scope, ROE, validation, approval, deployment, runtime binding, credential gates, or kill switch.
- No runtime self-modification.
- No uncontrolled plugin installation.
- Certification and evidence matrix only.
- Do not implement new detection capabilities.
- Do not run against live external targets.
- Do not change runner target execution safety boundaries.
- Do not remove finding schema fields.

## Validation

- `python3 scripts/validate_backlog_tasks.py`
- `source .venv/bin/activate && python -m pytest workers/tests -q`
- `source .venv/bin/activate && python -m pytest api/tests/test_settings.py -q`
- `git diff --check`

## Acceptance

- Every supported runner/tool claim is backed by test or fixture evidence, or marked supported-with-gap/blocked honestly.
- The certification matrix can be consumed by release-readiness and operator diagnostics.
