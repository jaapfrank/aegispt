# Backlog 179 Problems Center Zero-State Cleanup Evidence

Date: 2026-05-02

## Scope

Implemented `codex/tasks/backlog-179-problems-center-zero-state-cleanup.json`.

The change is limited to Problems Center empty/zero-state display logic and focused UI coverage:

- zero findings show `No open problems — findings from completed runs appear here.` with a `Go to Mission Control` action
- all-resolved lifecycle shows `All problems resolved. Start a new run to re-validate.`
- active problem states show a status summary only for non-zero actual problem statuses

No backend findings API, finding status model, Findings Theater behavior, pack registry, approval gate, deployment, or runtime binding behavior was changed.

## Status Mapping Truth

The task package mentioned `confirmed`, `suspected`, and `discounted` as finding statuses. Repo truth shows Problems Center uses `problem_status` from `api/app/schemas/problems.py`:

- `open`
- `in_progress`
- `resolved`
- `verified`
- `reoccurred`

The implementation therefore renders non-zero summaries for those actual statuses and does not invent unsupported `confirmed`, `suspected`, or `discounted` labels.

## Files

- `ui/assets/modules/problems.js`
- `ui/tests/test_problems_center_e2e.py`
- `DONE_LOG.md`
- `CURRENT_STATE.md`
- `NEXT_TASK.md`

## Validation

- `python3 scripts/validate_backlog_tasks.py`
  - passed before implementation
  - result: `193 queued task packages mapped one-to-one, and NEXT_TASK.md contains exactly one active task`
- `node --input-type=module --check < ui/assets/modules/problems.js`
  - passed
- `python3 -m py_compile ui/tests/test_problems_center_e2e.py`
  - passed
- `source .venv/bin/activate && python -m pytest ui/tests/test_problems_center_e2e.py::test_problems_center_empty_resolved_and_status_summary_states_are_guided -q`
  - not green; hit the known local `_pytest/capture.py FileNotFoundError`
- `source .venv/bin/activate && python -m pytest ui/tests/test_problems_center_e2e.py::test_problems_center_empty_resolved_and_status_summary_states_are_guided -s -q`
  - passed
- `source .venv/bin/activate && python -m pytest ui/tests/test_problems_center_e2e.py -s -q`
  - passed
- `curl -fsS http://127.0.0.1:8000/health/live`
  - passed
  - result: healthy JSON
- live Playwright browser acceptance against `http://127.0.0.1:8000/app/`
  - passed
  - proof line: `live_problems_acceptance=ok`
- `python3 scripts/validate_backlog_tasks.py`
  - passed after implementation
- `source .venv/bin/activate && python -m pytest api/tests/test_health.py -q`
  - not green; hit the known local `_pytest/capture.py FileNotFoundError`
- `source .venv/bin/activate && python -m pytest api/tests/test_health.py -s -q`
  - passed
- `git diff --check`
  - passed before promotion
- `python3 scripts/validate_backlog_tasks.py`
  - passed after promoting backlog-180
  - result: `193 queued task packages mapped one-to-one, and NEXT_TASK.md contains exactly one active task`
- `git diff --check`
  - passed after promoting backlog-180

## Live Acceptance Proof

The live browser check injected safe local UI state only and verified:

- zero findings: empty state sentence, visible Mission Control action, no stats block, no status summary
- all resolved: resolved guidance, `1 Resolved`, `1 Verified`, no stats block
- active problems: `1 Open`, `1 In Progress`, `1 Resolved`, visible open-critical stats, visible problem row, and no `confirmed`, `suspected`, or `discounted` labels

## Residual Risk

- The exact no-`-s` pytest commands still fail in the local host capture layer; equivalent checks pass with capture disabled.
- This task does not change backend problem-status derivation, false-positive semantics, finding lifecycle models, Findings Theater, or broader Problems Center layout.
