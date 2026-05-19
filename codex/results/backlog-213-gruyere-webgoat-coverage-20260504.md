# backlog-213 Gruyere + WebGoat benchmark coverage

## Scope

Completed the active benchmark gap-analysis task without adding new detection capabilities or changing core dispatch. The slice adds local benchmark fixtures, runs existing passive and active AegisPT web checks against local Gruyere and WebGoat targets, and records expected-versus-actual detection evidence.

## Implementation

- Added a safe local Gruyere Docker runtime fixture to `scripts/acceptance_harness.py`, matching the existing WebGoat fixture pattern and cleaning up containers after validation.
- Added profile-gated local benchmark services to `docker-compose.yml` for Gruyere and WebGoat.
- Added `google-gruyere-local` and `gruyere-benchmark-coverage` to `codex/tasks/target_lab_matrix.json`.
- Added `scripts/validation/benchmark_coverage_expected.json` with 52 expected benchmark vulnerabilities:
  - 20 Google Gruyere local expectations
  - 32 OWASP WebGoat local expectations
- Added `scripts/run_benchmark_coverage.py` to run the existing AegisPT validation path and produce coverage artifacts.
- Added focused test coverage for the catalog, coverage evaluator, and Gruyere runtime fixture.

## Benchmark Evidence

Generated artifacts:

- `codex/results/coverage_report.json`
- `codex/results/benchmark-coverage-latest.json`

Execution mode: `execute`

Overall coverage:

- Expected vulnerabilities: 52
- Detected by existing tools: 12
- Missed by existing tools: 40
- Overall coverage: 23.08%

Gruyere local:

- Expected: 20
- Detected: 7
- Missed: 13
- Coverage: 35.0%
- Passive run: `81da7b61-e4c1-44e6-8518-f3b456dbb0d9`, profile `passive-web-nuclei-audit`, completed, 0 findings
- Active run: `0ff8b685-45be-4ca1-aa4c-762ca5e4eb8c`, profile `active-web-zap-active`, completed, 52 findings

WebGoat local:

- Expected: 32
- Detected: 5
- Missed: 27
- Coverage: 15.62%
- Passive run: `f70551b2-60b4-4fd6-9091-0d93d03f6f3b`, profile `passive-web-nuclei-audit`, completed, 0 findings
- Active run: `dfd51a71-8744-444a-9381-497231cf6e40`, profile `active-web-zap-active`, completed, 36 findings

The detected benchmark rows were produced by the existing ZAP active path. The passive Nuclei audit path completed for both benchmarks but did not produce matching benchmark findings in this run.

## Validation

- `python3 scripts/validate_backlog_tasks.py` passed before implementation with exactly one active task.
- `python3 -m json.tool scripts/validation/benchmark_coverage_expected.json` passed.
- `python3 -m json.tool codex/tasks/target_lab_matrix.json` passed.
- `docker-compose config` passed for the benchmark profile services.
- `source .venv/bin/activate && python -m pytest scripts/tests/test_benchmark_coverage.py api/tests/test_acceptance_harness.py::test_default_target_catalog_expands_benchmark_truth_safely api/tests/test_acceptance_harness.py::test_activate_runtime_target_materializes_gruyere_fixture api/tests/test_acceptance_harness.py::test_activate_runtime_target_materializes_webgoat_fixture -q` passed.
- `source .venv/bin/activate && python -m pytest api/tests/test_health.py -q` passed.
- `python3 scripts/validate_backlog_tasks.py` passed after implementation.
- `git diff --check` passed.
- Local benchmark execution completed against loopback Docker fixtures only; no external live target actions were run.

## Remaining Risks

- Existing AegisPT tools detected only 12 of 52 expected benchmark vulnerabilities, so the benchmark report proves substantial remaining detection gaps.
- Path traversal, denial-of-service, and buffer-overflow-style benchmark gaps have no precise existing queued task reference in the report and should be handled by a later gap-triage task if they are still not covered by the queued runner slices.
- Docker Compose v2 is not installed on this host, but `docker-compose` v1.29.2 validated the benchmark services and the runtime harness used direct Docker lifecycle management successfully.
- An unrelated older stuck run remains visible in diagnostics; this task did not mutate stale run state because stale recovery was outside scope.
