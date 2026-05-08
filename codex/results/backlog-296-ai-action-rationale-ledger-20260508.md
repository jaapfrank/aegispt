# backlog-296 AI Action Rationale Ledger

Date: 2026-05-08

## Scope

Implemented the active task from `NEXT_TASK.md`: make ai_loop tool decisions provable through a Rationale Ledger entry that links the observed `TargetContextDocument` to the chosen tool, target, parameters, and guarded dispatch path.

No UI was changed. `http://127.0.0.1:8000` browser validation was not required for this backend/API/report slice.

## Implementation Proof

- `api/app/services/ai_planner.py`
  - `record_rationale` now writes explicit statements in the form `I observed ... in Context Document ..., therefore I am dispatching Tool ... with parameters ...`.
  - Ledger entries include structured `observed_context`, `dispatch_contract`, and `rationale_contract` fields in `decision_source_json`.
  - Dispatch contract preserves registered-runner execution, scope/ROE enforcement, approval gates, and kill-switch authority.
- `api/app/services/assessment_loop.py`
  - Assessment-loop API state now exposes ordered `rationale_ledger` entries for operator review.
- `api/app/schemas/runs.py`
  - `AssessmentLoopRead` includes `rationale_ledger`.
- `api/app/services/reports.py`
  - Technical report output now includes an `AI Action Rationale Ledger` section backed by stored ledger rows.
- `api/tests/test_ai_planner.py`
  - Tests prove passive queued actions and active review-only proposals receive provable ledger statements, structured contracts, API exposure, and report inclusion.

## Safety Boundaries

- No runner registry bypass.
- No approval-gate bypass.
- No scope or ROE bypass.
- No credential handling changes.
- No runtime self-modification.
- No uncontrolled plugin/tool installation.
- Active actions remain review-only until the existing approval flow permits execution.

## Validation

- `python3 scripts/validate_backlog_tasks.py` passed before implementation.
- `python3 -m py_compile api/app/services/ai_planner.py api/app/services/assessment_loop.py api/app/services/reports.py api/app/schemas/runs.py` passed.
- `.venv/bin/python -m pytest api/tests/test_ai_planner.py api/tests/test_assessment_loop.py -q` passed.
- `.venv/bin/python -m pytest api/tests/` passed: 521 passed, 4 warnings.
- Final `python3 scripts/validate_backlog_tasks.py` passed.
- Final `git diff --check` passed.

Note: an initial full-suite attempt with system `python3` failed during test collection because that interpreter lacked `pypdf`; the repository `.venv` contains `pypdf` and the required full API suite passed there.

## Remaining Evidence Gap

No live worker dispatch was run for a full artifact-fed ai_loop. That is not a new runner or option gap from this task; the existing live-dispatch coverage gap remains tracked in:

- `extra_tests.md` XT-019
- `extra_tests.md` XT-026
- `extra_tests.md` XT-027
