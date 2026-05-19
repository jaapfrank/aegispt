# backlog-295 AI Recursive Surface Mapping Evidence

Date: 2026-05-08

## Scope

Backend-only AI planning and assessment-loop work. No UI files were changed, and browser validation against `http://127.0.0.1:8000` was not required.

## Implemented Behavior

- Stored inventory evidence is inspected for newly discovered deeper surfaces:
  - `tech_stack_profile.graphql_endpoints`
  - `tech_stack_profile.api_endpoints`
  - `tech_stack_profile.api_base_urls`
  - `tech_stack_profile.login_forms`
  - `tech_stack_profile.file_upload_endpoints`
  - matching `signal_profile` endpoint records
  - normalized `discovered_layers` records
- `ensure_recursive_surface_context` creates one child `TargetContextDocument` per new layer under the phase-0 parent.
- `generate_sub_plan` now targets the discovered endpoint itself instead of only inheriting the root target.
- Recursive contexts prefer endpoint-specific registered runners:
  - GraphQL: `graphql-probe`
  - API surfaces: `api-assessment`, `content-discovery`
  - Auth surfaces: `auth-flow`
  - Upload surfaces: `content-discovery`, `xss-extended`
- `advance_assessment_loop` checks a recursive context micro-plan before falling back to the generic root-target plan.
- Active recursive actions remain review-only proposals and keep existing approval gates.
- Passive recursive actions, if selected, still queue only through registered runner tasks.
- Every selected recursive action receives context and rationale ledger links.

## Acceptance Proof

The focused regression creates an ai_loop URL run, queues the initial `httpx` action, marks it completed, attaches stored GraphQL endpoint evidence, advances the loop again, and proves:

- a child `TargetContextDocument` is created under the phase-0 parent;
- the child context is `recursive_surface_micro_plan`;
- the child micro-plan contains `graphql-probe`;
- the next action targets `https://loop.example.test/api/graphql`;
- the action becomes a review-only `AgentProposal` because `graphql-probe` is active;
- the `RationaleLedgerEntry` links to the child context and proposal.

## Validation

- `python3 scripts/validate_backlog_tasks.py` passed before implementation.
- `source .venv/bin/activate && python -m pytest api/tests/test_ai_planner.py api/tests/test_assessment_loop.py -q` passed.
- `source .venv/bin/activate && python -m pytest api/tests/` passed: 521 passed, 4 warnings.
- Final `python3 scripts/validate_backlog_tasks.py` passed.
- Final `git diff --check` passed.

## Remaining Proof

Live worker-dispatch proof for artifact-fed recursive ai_loop behavior remains tracked in `extra_tests.md` as XT-027.
