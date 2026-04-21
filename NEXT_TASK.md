# Active Task

## Title

Remediation Tracking and Single-Finding Retest Foundation

## Promoted From

`codex/tasks/backlog-02-remediation-status-and-single-finding-retest.json`

## Goal

Add a first-class remediation loop without redefining the existing finding schema by introducing additive remediation tracking, linked retest runs, and proof-of-resolution output.

## Scope

Implement the first remediation slice by adding an additive remediation tracking model tied to findings, a single-finding retest launch path linked back to the original finding, and a proof-of-resolution report variant that reuses the existing evidence, reporting, and provenance structures.

## Constraints

- work only inside this remediation closure slice
- do not silently reprioritize `TASK_QUEUE.md`
- do not add untracked future work
- keep the slice to additive remediation tracking, one finding-scoped retest path, and proof-of-resolution output
- defer batch retest orchestration, ticketing integrations, and broader workflow automation
- do not expand the existing `FindingUpdate.status` literal
- use an additive remediation record or equivalent additive metadata layer instead of redefining finding schema fields
- keep Prompt 1, Prompt 2, Prompt 3, the deterministic run model, and runtime safety controls authoritative

## Success Criteria

- operators can record remediation state and notes for a finding without changing the existing finding status contract
- a single-finding retest run can be launched and linked back to its source finding and source run
- proof-of-resolution output shows the original finding, remediation notes, retest evidence, and verification timestamp in one report path
- Findings Theater and report surfaces expose the remediation and retest linkage truthfully
- API, report, and browser tests cover the additive remediation path

## Likely Touched Files

- `api/app/models/control.py`
- `api/app/routers/findings.py`
- `api/app/services/reports.py`
- `api/app/services/finding_views.py`
- `ui/assets/modules/findings.js`
- `api/tests/test_reports.py`
- `ui/tests/test_operator_console_e2e.py`
- `CURRENT_STATE.md`
- `DONE_LOG.md`
- `NEXT_TASK.md`

## Must Not Touch

- `api/app/methodology.py`
- `api/app/schemas/findings.py`
- `api/app/services/packs.py`
- `workers/orchestration/findings.py`
- `workers/orchestration/tasks.py`
- Prompt 1 / Prompt 2 methodology and adaptive-pack foundations
- runtime self-modification
- arbitrary public-target expansion

## Out Of Scope

- batch retest or retest-all orchestration
- Jira, ServiceNow, Slack, or Teams integration
- automatic SLA enforcement
- changes to the existing `FindingUpdate.status` enum
- remediation SLA dashboards or enterprise workflow automation

## Validation

- `python3 scripts/validate_backlog_tasks.py`
- `source .venv/bin/activate && python -m pytest --capture=no api/tests/test_reports.py api/tests/test_runs.py`
- `source .venv/bin/activate && PLAYWRIGHT_BROWSERS_PATH="$PWD/.playwright-browsers" python -m pytest --capture=no ui/tests/test_operator_console_e2e.py`
- `git diff --check`
