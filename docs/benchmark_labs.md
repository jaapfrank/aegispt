# Lab Benchmark Orchestrator

The lab benchmark orchestrator records expected-vs-actual benchmark evidence for local or explicitly authorized vulnerable labs. It is designed for release confidence without making public-target validation the default path.

## Boundaries

- Dry-run mode is the default.
- The orchestrator does not launch Docker containers.
- The orchestrator does not dispatch AegisPT runners.
- The orchestrator does not mutate scope, approvals, credentials, runtime binding, or runner profiles.
- Public internet targets are not allowed by default.
- Live lab checks require separate operator setup on loopback or another explicitly authorized lab target.
- Missed or unexecuted checks are recorded as gap records, not hidden green claims.

## Catalog

Benchmark definitions live in `scripts/validation/benchmark_coverage_expected.json` under `lab_orchestrator.benchmarks`.

Each benchmark declares:

- target metadata with loopback defaults and `public_target_allowed=false`
- safe allowed proof types
- required evidence IDs such as run, task output, finding, coverage truth, runner decision, and report references
- expected issue families and title patterns
- unsupported gaps that remain live-lab or evidence-collection dependent

The legacy `benchmarks` list in the same JSON remains unchanged for the existing Gruyere/WebGoat coverage runner.

## Dry Run

Run:

```bash
python3 scripts/run_lab_benchmark_orchestrator.py --dry-run
```

This validates the catalog and writes:

- `codex/results/lab-benchmark-orchestrator-latest.json`
- `codex/results/lab-benchmark-orchestrator-latest.md`

Dry-run output marks every live-required issue as `not_evaluated` with a `live_lab_not_executed` gap record.

## Collected Evidence

After an operator runs a local lab fixture separately and exports evidence, rerun with:

```bash
python3 scripts/run_lab_benchmark_orchestrator.py --actual-results path/to/benchmark-evidence.json
```

The evidence file can contain either a single benchmark object with `benchmark_id` or a top-level `benchmarks` list. Supported evidence sections include:

- `run_id`
- `tasks`
- `findings`
- `coverage_truth`
- `reports`
- `runner_decisions`

The orchestrator compares supplied findings to expected issue patterns and verifies that required evidence IDs are present. Missing findings become `missed` gaps. Matching findings with incomplete evidence become `evidence_incomplete` gaps.

## Support Claims

A dry run proves the benchmark contract and reporting shape only. Product support claims still require collected evidence from a legal local or explicitly authorized lab target, plus review of any unsupported gaps.
