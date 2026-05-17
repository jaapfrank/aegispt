# Active Task

## Title

Cross-Runner Verifier: Independent Confirmation for Critical Findings (Phase 4 day 2)

## Goal

Before any critical or high finding is committed to the run report, a second independent runner or primitive sequence verifies the impact claim. Eliminates the false-positive class where a single runner's heuristic match is treated as proof (e.g. "I saw 'Manage this server' in the body" without an actual admin-only action succeeding).

## Scope

- Add `api/app/services/finding_verifier.py` with `verify_finding(finding, run, scope) -> VerifierVerdict`.
- Picker (or finding-persistence path) routes critical/high findings through the verifier before persistence.
- Verifier chooses an independent check (different primitive sequence from the original runner) and runs it.
- Findings that fail verification get severity downgraded with a `verifier_note` field.

## Constraints

- Verifier is a separate service that READS run state + can request a small independent HTTP check. Do NOT change the finding schema fields (existing) — only add a `verifier_note` attribute via the existing extensible attributes mechanism.
- Verifier MUST NOT call the same runner that produced the finding (no self-verification).
- Verifier is bounded: max 1 independent HTTP request + 5s timeout per verification. No unbounded loops.
- Scope/ROE enforced as for any other HTTP call (`web_target_value_is_allowed_with_path`).

## Source Package

`codex/tasks/backlog-385-cross-runner-verifier-system.json`

## Reference

- `api/app/services/evidence_ingest.py` (#322 + #334 — observation shape, captured_value entities now available for verifier to consume)
- `api/app/services/assessment_graph.py` (`project_graph_for_picker` from #323 + #334 RECENT_CAPTURES section)
- `workers/runners/exec_plan/runner.py` (the exec-plan engine; verifier can compose a verification step similarly)
- `docs/AGENT_SYSTEM_MAP.md` §4 (Evidence model) + §7 (scope/ROE governance)

## Validation

- `python3 scripts/validate_backlog_tasks.py`
- `.venv/bin/pytest api/tests/test_finding_verifier.py`
- `python3 -m compileall -q api`
- `.venv/bin/ruff check api/app/services/finding_verifier.py`
- `git diff --check`
