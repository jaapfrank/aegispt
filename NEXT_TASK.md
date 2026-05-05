# Active Task

## Title

Enterprise release blocker closure: execute accuracy evidence and close or keep blocked release claims honestly

## Promoted From

`codex/tasks/backlog-237-enterprise-release-blocker-closure.json`

## Goal

Turn the current enterprise release-readiness no-go into current, evidence-backed truth by executing the validation matrix and updating the support-claim ledger without lowering gates or inventing proof.

## Scope

Implement the active backlog package `codex/tasks/backlog-237-enterprise-release-blocker-closure.json`.

Expected slice:

- run and repair only the existing release-readiness evidence path
- execute the known-vulnerability validation matrix against safe/local benchmark targets, or record exact blockers and safest next steps for any blocked scenario
- refresh enterprise release-readiness outputs from current evidence
- keep the release gate fail-closed when critical evidence is missing
- produce operator-readable blocker and reliability truth for detection accuracy, false-positive posture, skipped scenarios, and unsupported claims
- do not add unrelated runners or new detection capability in this task

## Constraints

- Keep Prompt 1 and Prompt 2 intact.
- Do not bypass local provenance, scope, ROE, validation, approval, deployment, runtime binding, credential gates, or kill switch.
- No runtime self-modification.
- No uncontrolled plugin installation.
- Evidence closure only.
- Do not fake results.
- Do not relax thresholds to get a green release gate.
- Do not mark unsupported capabilities as supported without evidence.
- Do not run against live external/customer targets.
- Do not remove finding schema fields.

## Validation

- `python3 scripts/validate_backlog_tasks.py`
- `source .venv/bin/activate && python -m pytest api/tests/test_release_readiness.py -q`
- `python3 scripts/run_validation_matrix.py`
- `python3 scripts/run_enterprise_release_readiness.py --output-json codex/results/enterprise-release-readiness.json --output-md codex/results/enterprise-release-readiness.md`
- `git diff --check`

## Acceptance

- Accuracy evidence is current and machine-readable, or blockers are explicit and fail closed.
- The enterprise-ready claim is allowed only when the gate has current evidence for required claims.
