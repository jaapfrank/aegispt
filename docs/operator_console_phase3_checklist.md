# Operator Console Phase 3 Checklist

## Purpose

This document tracks the third stabilization slice for the operator console.

Phase 3 focuses on internal/LAN discovery follow-through:

- discovery-first runs must stay useful after completion
- controlled follow-up runs must stay visibly tied to the source discovery run
- Mission Control, Explorer, History, Surface Map, and Report Center must agree on what the follow-up run did
- the operator must be able to trace where a service-identification or web-profiling run came from

## Validation status

- prepared on 2026-04-17
- completed on 2026-04-17
- current automation focus:
  - `ui/tests/test_operator_console_e2e.py`
  - `ui/tests/test_product_feature_matrix_e2e.py`

## Control checklist

| Area | Expected behavior | Current status |
| --- | --- | --- |
| Discovery completion truth | inventory-first LAN runs read as useful discovery output instead of empty zero-finding dead ends | covered |
| Follow-up launch path | discovery-confirmed inventory can create real service-identification, web-profiling, or additional-approved-range follow-up runs | covered |
| Mission Control lineage | completed follow-up runs show strategy, rationale, and source-discovery context instead of generic standing-by copy | covered |
| Explorer lineage | the run dossier shows a follow-up-lineage card with source run, source inventory, and trace-origin actions | covered |
| History lineage | follow-up runs are labeled in Run History and can trace back to the source run | covered |
| Report lineage | report metadata shows discovery/follow-up context for follow-up runs without changing report semantics | covered |
| Next-step continuity | zero-finding follow-up runs still point to the right next operator action | covered |

## Commands used for this slice

```bash
./.venv/bin/pytest -q -s ui/tests/test_operator_console_e2e.py
./.venv/bin/pytest -q -s ui/tests/test_product_feature_matrix_e2e.py
```

## Exit criteria

Phase 3 can only be treated as complete when:

1. discovery-first internal/LAN work remains visibly useful across screens
2. follow-up runs stay traceable back to the source discovery run and source inventory snapshot
3. the operator can move from discovery into controlled follow-up without guessing what happened
4. the browser suite validates the main discovery-to-follow-up path

## Remaining follow-up after this slice

- findings/evidence/report integrity is now complete; Phase 5 now owns broader Explorer, History, Surface Map, and comparison usability
- explorer/history comparison can still grow into deeper dossier workflows later
- live streaming telemetry is still future work beyond the current request/response execution model
