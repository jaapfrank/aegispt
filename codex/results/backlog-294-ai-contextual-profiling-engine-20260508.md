# backlog-294 AI Contextual Profiling Engine Evidence

Date: 2026-05-08

## Scope

Backend-only AI planning and assessment-loop work. No `ui-v2/` files were changed, and browser validation against `http://127.0.0.1:8000` was not required for this slice.

## Implemented Behavior

- `TargetContextDocument` stores approved targets, detected technologies, endpoint candidates, recommended registered runners, micro-plan steps, evidence references, context summary, and provenance.
- `RationaleLedgerEntry` links each ai_loop next action to a run, context document, proposed/queued tool, target, parameters, decision source, task ID, and/or proposal ID.
- `ai_planner.py` builds context documents from run data only: approved scope targets, inventory snapshots, signal profiles, tech stack hints, completed task evidence, and findings.
- `generate_sub_plan` creates child context documents for newly discovered layers/endpoints without invoking tools.
- `advance_assessment_loop` creates the context document before candidate selection and creates the rationale ledger entry before passive task queueing or active proposal review.
- URL targets prefer `httpx`, host/CIDR targets prefer `nmap`, and domain targets prefer `easm-discover`, so URL-only website runs are not pulled into broad EASM-first behavior.
- Assessment-loop API responses include `context_document_id`, `rationale_ledger_entry_id`, and `target_context`.

## Safety Boundaries

- No runner registry bypass.
- No approval gate bypass.
- No runtime self-modification.
- No live target actions during context document creation.
- No UI changes.
- Existing manual/wizard/fixed-chain paths are unchanged.

## Validation

- `python3 scripts/validate_backlog_tasks.py` passed before implementation.
- `source .venv/bin/activate && python -m pytest api/tests/test_ai_planner.py api/tests/test_assessment_loop.py -q` passed.
- `source .venv/bin/activate && python -m pytest api/tests/` passed: 520 passed, 4 warnings.
- Final `python3 scripts/validate_backlog_tasks.py` passed.
- Final `git diff --check` passed.

## Evidence Notes

The focused tests prove:

- a context document is created before a passive `httpx` task is queued;
- the rationale ledger entry is linked to the context document, queued task, and approved passive proposal;
- recursive sub-plan generation records a parent context document and endpoint-specific micro-plan;
- active `auth-flow` decisions create reviewable proposals and rationale entries without queueing tasks.

## Remaining Proof

Live worker-dispatch proof for multiple artifact-fed ai_loop iterations remains tracked in `extra_tests.md` as XT-026.
