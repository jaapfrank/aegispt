# Operator Console Phase 7 Checklist

## Purpose

This document tracks the seventh stabilization slice for the operator console.

Phase 7 focuses on turning the calmer shell into a better-proven product surface:

- broaden the operator acceptance matrix beyond representative happy paths
- keep browser, API, and safe-run coverage aligned
- make remaining unsupported or unverified paths explicit instead of implied

## Validation status

- prepared on 2026-04-17
- in progress on 2026-04-17
- completed on 2026-04-17
- current automation focus:
  - `scripts/run_product_e2e_matrix.py --lane all`
  - `ui/tests/test_product_feature_matrix_e2e.py`
  - `api/tests/test_acceptance_harness.py`
  - `api/tests/test_nmap_dispatch.py`

## Current slice completed

The first Phase 7 slice is now covered:

- browser-level access-mode matrix:
  - unauthenticated
  - credential reference
  - API key reference
  - bearer token reference
  - session reference
  - manual-auth-only notes
- browser-level safety-cluster matrix:
  - passive light
  - guarded standard
  - deep guarded
  - active approved
- the composite API lane now includes:
  - acceptance harness regression
  - inline `nmap` dispatch regression

The second Phase 7 slice is now covered:

- browser-level multi-role authenticated context:
  - dual-role authenticated webapp intake
  - summary synchronization into Mission Control and Explorer dossier views
- browser-level execution-outcome truth:
  - `pending_approval` blocked missions
  - `completed_with_errors` failed-task missions
- the composite API lane now also includes:
  - dispatch outcome regression from `api/tests/test_task_dispatch.py`

The third Phase 7 slice is now covered:

- browser-level adaptive-pack visibility:
  - deployed pack status remains visible in Mission Control
  - Pack Forge registry and deployment context stay aligned with the selected run
  - Report Center previews carry adaptive pack runtime/deployment context
  - Explorer dossier and History cards both surface the bound pack version
- the repo-owned UI matrix now treats adaptive pack visibility as an explicit supported-path contract instead of leaving it as an implied browser expectation

## Control checklist

| Area | Expected behavior | Current status |
| --- | --- | --- |
| Access-mode browser matrix | all supported access entry styles stay synchronized into the existing deterministic run summary | covered |
| Safety-cluster browser matrix | operator-visible guardrails remain aligned with coverage summary and execution-lane expectations | covered |
| Composite matrix runner | the repo-owned product matrix includes the acceptance harness and `nmap` regression tests instead of only narrower API slices | covered |
| Assessment/profile matrix breadth | assessment-type and profile preset coverage stays green alongside the new access/safety expansions | covered |
| Multi-role authenticated context | multiple account/role entries stay visible from intake through mission and dossier views | covered |
| Blocked/failed execution truth | pending approval and failed-task runs surface honest mission activity and status-board copy | covered |
| Adaptive-pack cross-surface visibility | deployed pack state, runtime binding, and adaptive report context stay synchronized across mission, pack, dossier, history, and report views | covered |
| Safe real-run catalog alignment | real-run scenarios stay catalog-backed and authorization-bounded | covered |
| Remaining unsupported paths are explicit | the repo truth should call out what the matrix still does not exhaustively cover | covered |
| Full supported-path signoff | every meaningful product path has an explicit pass/fail result or a documented gap | covered |

## Commands used for the current Phase 7 slice

```bash
./.venv/bin/pytest -q -s ui/tests/test_product_feature_matrix_e2e.py
./.venv/bin/python scripts/run_product_e2e_matrix.py --lane all
```

## Exit criteria

Phase 7 can only be treated as complete when:

1. every meaningful supported operator path is either validated or explicitly listed as a known gap
2. the composite runner reflects the real acceptance contract instead of a narrower subset
3. browser/API/safe-run docs all point at the same matrix story
4. repo truth files make the remaining coverage limits explicit

## Remaining follow-up inside Phase 7

Phase 7 is now complete for the repo-owned supported-path contract.

The remaining non-blocking follow-up is environment-dependent rather than a missing repo matrix slice:

- real-run lab scenarios still depend on the actual training stacks being present where the harness is executed
- broader auth-family permutations, blocked/failed-family permutations, and deeper adaptive permutations are now future expansion opportunities instead of hidden signoff gaps
