# Codex Acceptance Workflow

## Purpose

Codex should validate the product through the repo-defined matrix instead of improvising its own target choices or acceptance logic.

## Inputs

Codex acceptance work uses:

- `codex/tasks/product_acceptance_matrix.json`
- `codex/tasks/ui_acceptance_matrix.json`
- `codex/tasks/target_lab_matrix.json`
- `scripts/run_acceptance_matrix.py`
- the existing pytest suites

## Default order

1. UI browser validation
2. API regression
3. real-run safe acceptance

This keeps the cheaper deterministic checks ahead of live lab activity.

## Scenario-selection rules

For real-run scenarios, Codex should:

1. read prior result files under `codex/results/`
2. prefer the next enabled scenario that does not already have a passing result
3. refuse any target outside the safe catalog
4. stop and report if the desired target is disabled or unauthorized

## Result recording

Every acceptance execution should leave behind:

- test command output
- any Playwright trace/screenshot artifacts from failures
- acceptance result JSON for real-run scenarios

## Repo truth updates

When a meaningful acceptance milestone changes the project state, update:

- `DONE_LOG.md`
- `CURRENT_STATE.md`

Update `NEXT_TASK.md` only when the acceptance work actually changes what the next highest-priority task should be.

## UI visibility

The operator UI is not turned into a QA dashboard, but acceptance-created runs still surface:

- acceptance scenario id
- safe target label and class
- expected outputs
- links into evidence, reports, and history

This keeps validation visible without polluting the main product flow.
