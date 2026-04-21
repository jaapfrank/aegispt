# Operator Console Phase 5 Checklist

## Purpose

This document tracks the fifth stabilization slice for the operator console.

Phase 5 focuses on making Surface Map, Explorer, History, and Comparison more practical for real post-run review:

- large inventories should stay searchable and understandable
- Explorer should read like a dossier instead of a loose data dump
- History should stay filterable and clickable as runs accumulate
- Comparison should explain not only finding delta, but also inventory delta

## Validation status

- prepared on 2026-04-17
- completed on 2026-04-17
- current automation focus:
  - `ui/tests/test_operator_console_e2e.py`
  - `ui/tests/test_product_feature_matrix_e2e.py`

## Control checklist

| Area | Expected behavior | Current status |
| --- | --- | --- |
| Surface Map browser | operators can search and filter larger inventories without losing asset detail or follow-up actions | covered |
| Surface Map summary | the browser explains how many asset records exist, what is visible, and what is currently selected | covered |
| Explorer dossier summary | the selected run opens with a compact dossier summary for inventory, evidence, reports, pack state, and next review | covered |
| History search | run history can be narrowed by profile, target, status, or follow-up lineage | covered |
| Comparison clarity | comparison speaks about findings and inventory deltas instead of findings only | covered |
| Clickability / next action | history cards and dossier summaries expose an obvious next operator action | covered |
| Browser validation | surface search, dossier summary, and comparison delta behavior are exercised in the operator console browser suite | covered |

## Commands used for this slice

```bash
./.venv/bin/pytest -q -s ui/tests/test_operator_console_e2e.py
./.venv/bin/pytest -q -s ui/tests/test_product_feature_matrix_e2e.py
./.venv/bin/pytest -q -s api/tests/test_reports.py
git diff --check
```

## Exit criteria

Phase 5 can only be treated as complete when:

1. large inventories can be narrowed and reviewed without hunting blindly through the list
2. Explorer gives a human operator a practical dossier summary before the deeper detail blocks
3. History and Comparison explain what changed in both findings and inventory terms
4. browser validation and repo truth both reflect the finished slice

## Remaining follow-up after this slice

- Phase 6 remains responsible for broader calmness, hierarchy, and readability work across the full console
- richer per-task live telemetry is still future work beyond the current request/response execution model
- larger-history pagination and heavier comparison analytics can still be added later if explicitly prioritized
