# Operator Console Phase 4 Checklist

## Purpose

This document tracks the fourth stabilization slice for the operator console.

Phase 4 focuses on findings, evidence, and report integrity:

- findings should only appear when a run truly produced finding-level output
- zero-finding discovery and follow-up runs should still expose useful evidence and report context
- Evidence Replay, Report Center, Explorer, and History should agree on run lineage and executed output
- report variants should stay readable and truthful for discovery-only, follow-up, and finding-bearing runs

## Validation status

- prepared on 2026-04-17
- completed on 2026-04-17
- current automation focus:
  - `api/tests/test_reports.py`
  - `ui/tests/test_operator_console_e2e.py`

## Control checklist

| Area | Expected behavior | Current status |
| --- | --- | --- |
| Discovery no-finding honesty | discovery runs with inventory but no findings do not collapse into empty or misleading evidence/report states | covered |
| Follow-up no-finding honesty | follow-up runs such as service identification show useful evidence/report context without inventing vulnerabilities | covered |
| Findings Theater integrity | no-finding states explain discovery/follow-up output instead of implying the run failed silently | covered |
| Evidence Replay integrity | Evidence Replay shows run-level evidence posture when no finding exists, including task, artifact, inventory, and lineage context | covered |
| Report integrity | technical/evidence variants keep discovery and follow-up inventory context visible while findings remain zero | covered |
| Browser validation | discovery and follow-up evidence/report behavior is exercised in the operator console browser suite | covered |
| API validation | report exports for finding-bearing, discovery-only, and follow-up runs stay readable and truthful | covered |

## Commands used for this slice

```bash
./.venv/bin/pytest -q -s api/tests/test_reports.py
./.venv/bin/pytest -q -s ui/tests/test_operator_console_e2e.py
```

## Exit criteria

Phase 4 can only be treated as complete when:

1. zero-finding discovery and follow-up runs still produce reviewable evidence/report context
2. findings, evidence, and report views stop contradicting one another
3. browser and API validation both cover the critical discovery/follow-up integrity paths
4. repo truth files reflect the finished slice

## Remaining follow-up after this slice

- Phase 5 remains responsible for broader Explorer, History, Surface Map, and comparison usability
- true live telemetry is still future work beyond the current request/response runner model
- the inventory aggregation model can still be refined later if tighter exact-count semantics become a priority
