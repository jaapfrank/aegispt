# Backlog 237 - Enterprise Release Blocker Closure

Date: 2026-05-05

## Scope

Active task: `codex/tasks/backlog-237-enterprise-release-blocker-closure.json`.

This slice repaired and executed the existing release-readiness evidence path only. It did not add runners, lower thresholds, bypass approval/runtime gates, pull Docker images by default, or scan live external/customer targets.

## Implementation

- `scripts/run_validation_matrix.py` now records blocked validation scenarios as first-class machine-readable evidence with an `execution_blocker` object.
- Default no-argument validation matrix execution attempts safe local execution only when the configured local AegisPT API is reachable; otherwise it writes blocked preflight evidence instead of silent catalog-only `not_run` output.
- Missing Docker fixture images are blocked before `docker run` when `--allow-image-pull` is not explicitly supplied.
- `scripts/run_enterprise_release_readiness.py` now carries validation scenario blockers into the support-claim ledger and keeps accuracy and FP/FN posture claims blocked until the matrix passes.
- Markdown release-readiness gaps are rendered one per line for operator readability.
- Focused tests cover blocked validation preflight output and release-readiness blocker propagation.

## Current Evidence Truth

`http://127.0.0.1:8000` was relevant for validation because the default validation matrix path uses it as the local API base URL. `/health/live` returned healthy during acceptance.

`python3 scripts/run_validation_matrix.py` wrote `codex/results/validation-matrix-latest.json` with:

- matrix status: `blocked`
- mode: `auto-execute`
- summary: `3` scenarios, `3` blocked, `0` passed, `0` failed, `0` not_run
- blocked scenarios:
  - `webgoat-active-web-safe`: `docker_image_missing` for `webgoat/webgoat:2023.8`
  - `dvwa-active-web-safe`: `docker_image_missing` for `vulnerables/web-dvwa:latest`
  - `clean-nginx-passive-web`: `docker_image_missing` for `nginx:1.25-alpine`

The safest next step recorded for each blocker is to pre-pull the approved fixture image on a validation host, update the catalog if the tag is obsolete, or rerun with `--allow-image-pull` after explicitly accepting external registry access.

`python3 scripts/run_enterprise_release_readiness.py --output-json codex/results/enterprise-release-readiness.json --output-md codex/results/enterprise-release-readiness.md` wrote:

- release status: `blocked`
- go/no-go: `no-go`
- enterprise-ready claim allowed: `false`
- blocked critical claims:
  - `known_vulnerability_detection_accuracy`
  - `false_positive_false_negative_posture`

## Validation

- `python3 scripts/validate_backlog_tasks.py` passed before implementation and during final task validation.
- `source .venv/bin/activate && python -m pytest api/tests/test_release_readiness.py -q` passed.
- `source .venv/bin/activate && python -m pytest scripts/tests/test_validation_runner.py -q` passed as focused extra coverage for the repaired matrix runner.
- `python3 scripts/run_validation_matrix.py` passed and produced blocked evidence, not green accuracy claims.
- `python3 scripts/run_enterprise_release_readiness.py --output-json codex/results/enterprise-release-readiness.json --output-md codex/results/enterprise-release-readiness.md` passed and kept the release no-go.
- `curl -fsS http://127.0.0.1:8000/health/live` passed for safe local API acceptance.
- `git diff --check` passed.

## Remaining Risk

- No benchmark scenario executed because the required Docker fixture images were not present locally and the safe default path does not pull from registries.
- Known-vulnerability detection accuracy and false-positive/false-negative posture remain unproven and release-blocking.
- The already-running local API is healthy, but this task did not restart or mutate the live runtime process.
- The operator-reported Gruyere wizard/all-tools issue is not part of this active task and remains queued separately under backlog-250.
