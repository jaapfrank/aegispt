# Active Task

## Title

Review Checkpoint: Universal Auth Probes Working Across Stacks (Phase 2 close-out)

## Goal

After #325-#328, verify the 5 migrated probes actually find vulnerabilities on at least 2 non-Gruyere targets, Gruyere parity is preserved, the cache is working, and no Gruyere-specific patterns remain in production code. Decide go/no-go for Phase 3.

## Scope

- Operator + agent review of work from backlog-375 (#325), backlog-376 (#326), backlog-377 (#327), backlog-378 (#328).
- Live run of `scripts/test_probe_generality.py` across Gruyere + juice-shop + demo.testfire.net + testasp.vulnweb.com.
- Written checkpoint report at `docs/checkpoints/2026-mythos-phase2-review.md` with go/no-go on Phase 3.

## REVIEW CHECKPOINT — AGENT MUST STOP

**This is a review checkpoint (#329 in the Mythos plan; #324 was Phase 1's equivalent).** Per the universal prompt rule, the agent **STOPS** here and asks operator for explicit go/no-go before executing the checkpoint's body (live runs + report generation + Phase 3 promotion).

When operator approves: agent proceeds to (1) run the generality script against all 4 targets (operator may want to spin up a local Gruyere first since the previous run found it unreachable in this WSL env), (2) write `docs/checkpoints/2026-mythos-phase2-review.md` citing real findings_count numbers from the matrix (no aspirational claims), (3) confirm cache hit rate via second-run replay, (4) reconfirm AGENT_SYSTEM_MAP section 3 reflects the migration, (5) emit explicit GO or NO-GO with justification, (6) on GO: promote backlog-380 (#330 Picker Structured Outputs) into NEXT_TASK; on NO-GO: name + queue a corrective task.

## Constraints

- Review only. NO production code changes. Output is a checkpoint report and a yes/no decision on Phase 3 promotion.
- Evidence requirement: report must cite real findings_count numbers, not aspirational claims.
- Must NOT touch: `api/app/services/`, `workers/runners/`, `workers/orchestration/`, `ui-v2/` — review-only task.

## Source Package

`codex/tasks/backlog-379-review-checkpoint-universal-probes.json`

## Reference

- `DONE_LOG.md` (entries for #325, #326, #327, #328a foundation, #328 completion)
- `docs/AGENT_SYSTEM_MAP.md` section 3 (post-migration runner inventory)
- `scripts/test_probe_generality.py` (the generality test harness)
- `api/app/services/auth_discoverer.py` (~1500 lines: fetch_auth_pages, fingerprint_application, build_recipe, lookup/store/verify/mark_stale, acquire_session)
- `workers/runners/{info_disclosure,stored_xss,file_upload,param_pollution,cookie_tamper}_probe/runner.py` (the 5 migrated probes)
- `docs/checkpoints/2026-mythos-phase1-review.md` (template format for the Phase 2 checkpoint report)

## Validation

- `python3 scripts/validate_backlog_tasks.py`
- `test -f docs/checkpoints/2026-mythos-phase2-review.md`
- `python3 scripts/test_probe_generality.py`
