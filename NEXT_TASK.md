# Active Task

## Title

Gruyere + WebGoat gap analysis: add local benchmark targets, run existing tools against both, and produce expected-vs-actual coverage reports before adding new detection capability tasks

## Promoted From

`codex/tasks/backlog-213-gruyere-webgoat-benchmark-coverage-gap.json`

## Goal

Add Google Gruyere and OWASP WebGoat as official local benchmark targets, run the existing AegisPT tooling against both, and produce expected-vs-actual coverage evidence before adding new detection capability tasks.

## Scope

Implement the active backlog package `codex/tasks/backlog-213-gruyere-webgoat-benchmark-coverage-gap.json`.

Expected slice:

- add local Gruyere and WebGoat benchmark targets to the test lab
- run existing passive and active AegisPT tools against both local lab targets
- record which expected benchmark vulnerabilities are detected versus missed
- produce a coverage report with vulnerability id, expected detection, actual detection, tool used, severity, and notes
- use the benchmark gap report to inform later queued detection tasks without implementing new detection capabilities in this task

## Constraints

- Keep Prompt 1 and Prompt 2 intact.
- Do not implement new detection capabilities in this task.
- Do not silently reprioritize later gap tasks.
- Do not mutate production databases.
- Do not change existing assessment packs unless the active task package explicitly requires a safe local benchmark fixture.
- Do not change core dispatch logic.
- Do not bypass scope, ROE, validation, approval, deployment, runtime binding, credential gates, or kill switch.
- No runtime self-modification.
- Do not run external live target actions; benchmark actions must stay local/safe lab only.

## Validation

- `python3 scripts/validate_backlog_tasks.py`
- `source .venv/bin/activate && python -m pytest api/tests/test_health.py -q`
- `git diff --check`

## Acceptance

- Local Gruyere instance runs in the test lab.
- Local WebGoat instance runs in the test lab.
- AegisPT runs existing passive and active checks against both local lab targets.
- `coverage_report.json` documents expected-versus-actual detection per benchmark vulnerability.
- Gruyere and WebGoat coverage percentages are documented.
- Missed benchmark vulnerabilities are listed as gaps for later tasking.
