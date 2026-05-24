# Session follow-ups — 2026-05-24

Persistent record of items raised in chat during this session that are not yet executed and are not already tracked in:

- [beat-shannon-pro-roadmap-2026-05-23.md](beat-shannon-pro-roadmap-2026-05-23.md) — M-roadmap (capability work, M1–M9)
- [continual-harness-roadmap-2026-05-24.md](continual-harness-roadmap-2026-05-24.md) — H-roadmap (planned but not active)
- [../research/repo-hygiene-and-open-tasks-audit-2026-05-24.md](../research/repo-hygiene-and-open-tasks-audit-2026-05-24.md) — repo hygiene priorities P1–P5

Anything captured here either updates one of those docs or is operational engineering work that doesn't belong in any of them.

## M-roadmap status delta (changes since 2026-05-23 roadmap version)

| M-item | Was (2026-05-23) | Now (after this session) |
|---|---|---|
| M1 critic | SHIPPED + LIVE | unchanged |
| M2 verdict gate | SUBSTRATE SHIPPED, drop-path not exercised | unchanged |
| M3 CPG | SHIPPED + LIVE | unchanged |
| M4 multi-trajectory | v1 substrate, no live measurement | unchanged |
| M5 episodic memory | pending (never wired) | **PARTIAL — recall hooked into `_claude_select_next_action` (fallback path only) via commit 34ed7b2; NOT in primary specialists path** |
| M6 cross-model critic | v1 substrate, no live measurement | unchanged |
| M7 two-phase agents | pending | unchanged |
| M8 pad-1 reliability | PARTIAL (classify only) | unchanged |
| M9 deep reads | pending | unchanged |
| **Smoke baseline (XBOW)** | 0/10 on 10-XBEN subset | **2/5 (smoke 24, 40%)** + 0/10 (smoke 25; 3 infra-crash on docker layer corruption + 7 AI-misses, source-aware was broken because harness only looked at `app/` not `src/` — fixed in commit 240a269) |
| **Smoke baseline (single-target XBEN-002)** | 0/1 | **1/1 (smoke 23, 390s, end-to-end clean)** |

## Capability items raised in chat that should land before H-roadmap activates

### S1 — M5 recall in primary specialists path (not just fallback)

Commit 34ed7b2 added `prior_episodes_block` to `_claude_select_next_action` (regel ~2985–3043). But `PICKER_MODE=specialists` is set in the systemd unit, so the primary picker path is `_specialists_select_next_action` → `picker_specialists/orchestrator.py`. The Claude path is the fallback. In ~90% of advances the recall block is never seen by the LLM that actually chooses the next action.

- **Move**: push the recall block into `picker_specialists/orchestrator.py`'s `_build_user_content_for_specialist` (regel ~61–79). Each of the 5 specialist prompts gets the same `prior_findings_summary` envelope — extend it with `prior_episodes_block` derived from the same `recall_similar()` call.
- **Risk**: low. Add-only block in user content. Specialists currently accept any user content as input.
- **Acceptance**: smoke 27 picker logs show the block present in at least 3 of the 5 specialists' input on first advance of run 2.

### S2 — XBEN-010 (phantomjs XSS) triage methodology

Smoke 24 + 25 showed XBEN-010 misses every time. It's a stored-XSS challenge where the server pipes user input through `phantomjs check.js` and only returns the flag if `alert('XSS')` fires inside the headless browser. Pure HTTP probes can't solve it.

This is a vuln-class capability gap, not a single bug. We don't have a written process for triaging a specific XBEN miss and turning it into a generic capability addition.

- **Move**: write `docs/triage-method.md` with the steps: (1) collect ALL exec_plan + CEA stdout for that run; (2) classify the miss reason (no-callback-detection, no-form-target-discovery, payload-class-missing, runner-missing); (3) decide if it's a one-off (skill addition) or a class (new runner / picker prompt update); (4) propose the change as a queue item.
- **Risk**: zero (doc only).
- **Acceptance**: doc exists, applied once to XBEN-010 with a written diagnosis.

## Operational / engineering items

### O1 — Auto-finalize zombie runs

`scripts/finalize_zombie_runs.py` exists and works (we ran it twice today, finalized 18 runs across two invocations). It only triggers on operator/script call. Result: 16 zombies accumulated since 2026-05-19 before we ran it.

- **Move**: schedule via APScheduler (already wired for `scheduled_runs`) on a 5-min interval. Reuse the existing job-registration pattern.
- **Risk**: low — the script is idempotent and only finalizes runs older than 5 min.
- **Acceptance**: a smoke that fails mid-way leaves no `queued`/`running` row 10 min later.

### O2 — Bulk endpoint for Mission Control engagement fan-out

Mission Control today fans out ~20 sequential `GET /api/v1/engagements/<id>` calls per polling refresh (one per engagement). User flagged this on 2026-05-24 as "what is this every time". Adds latency + DB load + log noise.

- **Move**: add `GET /api/v1/engagements?include=latest_run` (or similar) that returns the bulk projection Mission Control actually needs in one query. Drop the fan-out from the frontend.
- **Risk**: low — new endpoint, no removal of old. Frontend swap in a second PR.
- **Acceptance**: Mission Control refresh issues ≤ 2 API calls, not 20.

### O3 — Delete genuine dead functions in `assessment_loop.py`

Audit found 2 functions with zero in-file callers and zero external callers:

- `_compute_depth_level` (assessment_loop.py)
- `_record_loop_rejection` (assessment_loop.py)

`record_assessment_loop_goal` (NO leading underscore) has 2 external callers in `api/app/routers/runs.py` — keep.

- **Move**: delete the two functions. Single commit, no behavior change.
- **Risk**: zero.
- **Acceptance**: file shrinks ~150 lines; import-ok; one smoke run still passes.

### O4 — Split oversized service modules

Audit listed (P5 in repo-hygiene doc) but without a concrete plan. The 6 largest:

- `api/app/services/reports.py` — 7681 lines
- `api/app/services/assessment_loop.py` — 6680 lines
- `api/app/services/runs.py` — 5946 lines
- `workers/orchestration/tasks.py` — 5524 lines
- `workers/orchestration/findings.py` — 2538 lines
- `api/app/services/auth_discoverer.py` — 2405 lines

Proposed split for `assessment_loop.py` (the file where we've found 3 bugs this session because it's too big to keep in working memory):

- `assessment_loop/__init__.py` — re-exports the public surface
- `assessment_loop/state.py` — `_loop_state`, `_store_loop_state`, `_as_dict`, `_run_uses_ai_loop`, `_targets_for_loop`
- `assessment_loop/picker_claude.py` — `_claude_select_next_action`, `_claude_candidate_to_loop_candidate`, prompt strings
- `assessment_loop/picker_chatgpt.py` — `_chatgpt_oauth_select_next_action`
- `assessment_loop/specialists_dispatch.py` — `_specialists_select_next_action`, `_maybe_dispatch_script_critic`, `_maybe_dispatch_cpg_seeded_cea`
- `assessment_loop/guards.py` — early-stop, target-unreachable, idempotent-terminal, fingerprint, max-iter (the work added this session)
- `assessment_loop/recall.py` — M5 prior-episodes assembly
- `assessment_loop/candidates.py` — `_goal_oriented_candidate`, `_seed_candidate`, `_plan_candidate`, `_selector_candidate`, `_ai_proposal_candidate`, `_auth_signal_candidate`, `_context_micro_plan_candidate`, `_exec_plan_fallback_candidate`
- `assessment_loop/advance.py` — `advance_assessment_loop` (the main entry — ideally < 300 lines after extraction)

- **Move**: one commit per submodule. Each commit moves code, updates imports, runs `pytest` + a smoke. No behavior change in any single commit.
- **Risk**: medium — many call sites need updating; long-running smokes may catch regressions.
- **Acceptance**: smoke 23 (single XBEN-002) still SOLVED 1/1 after the refactor; no public-API signature change.

### O5 — Investigate untracked modules imported by tracked files (P1 from audit)

Audit identified:
- `api/app/services/m2_verdict_gate.py` — untracked, imported indirectly via assessment_loop integration
- `api/app/services/picker_specialists/` — untracked, imported by `assessment_loop._specialists_select_next_action`
- `workers/runners/code_exec_attack/` — untracked, dispatched by orchestrator
- `workers/runners/pre_recon_cpg/` — untracked, dispatched by orchestrator
- `workers/runners/pre_recon_source/` — untracked, dispatched by orchestrator
- `workers/runners/recon_deliverable/` — untracked, dispatched by orchestrator

If any of my recent commits ship without these directories, a clean checkout breaks at import time.

- **Move**: for each module, decide promote-vs-remove. Likely all need to be promoted (they're load-bearing for M1/M3/M5 + specialists path). Create proper backlog task packages for each so they ship with tests + evidence.
- **Risk**: high if skipped (clean checkout breaks). Low if executed.
- **Acceptance**: `git status --short` no longer shows `??` lines for these modules; clean checkout + `pytest` + import-check all pass.

## Decision rules

1. **No new feature commit until O5 is resolved.** Otherwise a clean checkout is broken.
2. **Order under "S" + "O" items**: O5 (unblocks) → O1 (small, hygiene) → O3 (small, hygiene) → S1 (lifts solve rate) → O2 (UI ergonomics) → S2 (process doc) → O4 (refactor).
3. **H-roadmap stays gated** behind the M-roadmap activation criteria (see `continual-harness-roadmap-2026-05-24.md`).

## Already executed this session (for the record)

- ✅ Audit caught + fixed codex_tasks.py write-back bug (commit 72b4713)
- ✅ 390 task JSON files restored from HEAD
- ✅ TASK_QUEUE.md items 389/390 moved to Discussion section
- ✅ `python3 scripts/validate_backlog_tasks.py` passes
- ✅ M5 recall + success_marker writeback (commit 34ed7b2, fallback path only — S1 above is the follow-up to make this hit the primary path)
- ✅ Early-stop + target-health + idempotent guards (commit 102497c)
- ✅ flag_modified for SQLAlchemy mutation tracking (commit ab82f78)
- ✅ XBEN compose port-strip (commit 1e89e0d)
- ✅ Source-aware app/src/code/Dockerfile-bearing discovery (commit 240a269)
- ✅ DB cleanup: 194 engagements + 227 runs + 3964 tasks + 4136 evidence + 4207 findings + 2275 engagement_memory + 1257 agent_episodic_memory all truncated cascade
- ✅ `/home/administrator/.aegispt/memories/` archived to `memories.archive-2026-05-24/`
- ✅ `/tmp/aegispt-api.log` rotated (90MB → fresh)
- ✅ Smoke 23 = SOLVED 1/1 100% (XBEN-002 end-to-end clean)
- ✅ Smoke 24 = 2/5 (40%) — XBEN-002 + XBEN-005 SOLVED; 2 infra crash, 1 genuine miss (XBEN-010 phantomjs XSS)
- ✅ Smoke 25 = 0/10 — exposed source-aware `app/` hardcode + docker mysql layer corruption + port conflict on :8000
