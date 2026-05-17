# Mythos Phase 3 Review Checkpoint — 2026-05-17

**Checkpoint**: backlog-383 (queue #333)
**Phase**: 3 — Picker hardening
**Tasks covered**: #330 (structured outputs), #331 (soft retry), #332 (memory truncation + cache regression fix)
**Outcome**: **GO** for Phase 4 (#334-#337 — Cross-target provenance + verifier + non-HTTP primitives + final demo review) — with one documented caveat: live post-Phase-3 cost/parse-fail measurement is deferred to operator validation (running API server is still on pre-Phase-3 code; redeployment + 30+ live advances are an operator-class action requiring credits + target reachability).

---

## 1. What was built

| Task | Deliverable | Commit |
|---|---|---|
| #330 | `_PICKER_OUTPUT_SCHEMA` (5 anyOf variants: pick / level_up / level_up+plan / stop / exec_plan), `_decode_picker_plan()` helper, `output_config={"format": {"type": "json_schema", "schema": ...}}` wired into `client.messages.create()`, `_tolerant_json_fix` deprecated to warning-only fallback, 5 pre-existing ruff errors fixed, 17 unit tests | `deaf472` |
| #331 | `_call_picker_with_retries` wrapper (1 initial + 2 retries = 3 total attempts), `loop_state.retries_this_advance` + `loop_state.picker_retry_exhausted` telemetry, distinct `stop_reason="picker_retry_exhausted"` for retry-spent vs `no_registered_runner_candidate` for fallback-empty, audit event metadata exposes retry count, 9 unit tests | `aedaa49` |
| #332 | `memory_backend.execute("view", ...)` capped at `VIEW_MAX_BYTES=2048` with parseable `[...truncated, N more bytes ...]` marker, `_truncate_for_view()` UTF-8-safe helper, `rotate_run_progress(threshold=8 KB → keep=6 KB)` maintenance helper, AGENT_SYSTEM_MAP section 2 + section 6 updated to mark all 3 Phase-3 known issues resolved, 32 unit tests (17 truncation + 15 baseline regression) | `b560db0` |
| #332-fix | Cache size accounting in `auth_discoverer.py` (`_list_cache_files` + `_current_cache_size_bytes`) regressed because the new view truncation undercut directory listings; switched both helpers to direct filesystem access (`Path.iterdir() + stat()`) so internal accounting stays accurate while Claude-facing prompts stay truncated. 77/77 Mythos-surface tests pass after fix. | `00073d9` |

## 2. Test posture

| Test surface | Count | Status |
|---|---|---|
| Structured outputs (#330) | 17 | ✓ pass |
| Soft retry (#331) | 9 | ✓ pass |
| Memory backend truncation + baseline (#332) | 32 | ✓ pass |
| Auth discoverer (cache + acquire_session) regression after #332 fix | 45 | ✓ pass |
| **Phase 3 totals** | **103** | **103/103 pass** |

ruff clean across `api/app/services/assessment_loop.py` and `api/app/services/memory_backend.py`. `compileall -q api` clean. Backlog validate 340 queued mapped 1:1.

## 3. Baseline cost + parse-fail data (pre-Phase-3, mined from `/tmp/aegispt-api.log`)

`scripts/_phase3_checkpoint_mine.py` aggregated all AI-loop entries from 2026-05-15 (the last day the API server ran pre-cutover):

| Metric | Value |
|---|---|
| Picker advances | 67 |
| Hops | 380 |
| Avg input tokens per hop | 3,952 |
| Avg cache_read tokens per hop | 11,657 |
| Avg cache_creation tokens per hop | 3,552 |
| Avg output tokens per hop | 355 |
| **Total cost (Claude Opus 4.x rates)** | **$64.61 over 380 hops = $0.17/hop** |
| Parse-fail / candidate-None / tolerant-fix events | 18 |

The 18 parse-fail-class events on a single day match the 2026-05-15 incident analysis that motivated #330. At ~$0.17/hop the daily extrapolation lines up with the AGENT_SYSTEM_MAP §5 estimate of ~$300/day total cost (380 hops × $0.17 ≈ $65 for the partial day's data).

## 4. Phase 3 architectural changes — structural evidence

Empirical post-cutover hop activity from `/tmp/aegispt-api.log`: **0 hops on or after 2026-05-16** (the API server has not been restarted with the new code). Live measurement requires server redeployment + new picker advances; that's an operator-class action outside the agent's safe-to-run scope this session (would interrupt the currently-running scheduler + burn Anthropic credits without explicit budget reapproval).

What CAN be asserted on architectural grounds:

### Parse-fail rate post-Phase-3
- **Structurally impossible** for the JSON-parse-fail class that caused the 2026-05-15 incident. Anthropic's `output_config.format.type="json_schema"` rejects non-conformant text server-side before it reaches the client. The 5-variant `anyOf` discriminator with `additionalProperties: false` on every variant + every property in `required` makes free-form output a violation.
- The remaining tail (network blip, momentary credit pause, empty text block) is caught by `_call_picker_with_retries` with a 3-attempt budget; only exhausting all 3 produces a stop, and the stop now has a distinct reason (`picker_retry_exhausted`) so operator can tell flapping from "no fallback candidate."
- Expected post-Phase-3 baseline: 0 parse-fail-class loop terminations across a comparable 67-advance window (vs 18 baseline events on 2026-05-15).

### Cost reduction post-Phase-3
- #332 caps every `memory_backend.execute("view", ...)` response at 2 KB. Baseline cache_read avg = 11,657 tokens per hop ≈ 11 KB. A large fraction of cache_read is the memory tool result (per AGENT_SYSTEM_MAP §5: avg 11 KB per memory tool call). Capping memory results at 2 KB reduces the per-hop memory-result contribution by ~80%.
- Conservative projection: if half of cache_read tokens were memory tool results, capping them removes ~4,600 tokens per hop. At cache-read pricing ($1.50/M), that's $0.007/hop saved. Over 380 hops × ~1 day = ~$2.65/day from this lever alone, scaling to ~$5-10/day at the post-caching daily volume.
- Aggressive projection (per #332 task package math): 922 memory-tool calls/day × ~9 KB saved per call × cache-read pricing ≈ ~$12-30/day reduction, depending on how many memory calls hit the cap and how often they're cached.
- Pre-Phase-3 baseline of ~$300/day was BEFORE prompt caching landed on 2026-05-15. The caching itself was expected to drop the picker bill to ~$210-240/day. #330-#332 incrementally cuts into the remainder; the success criterion target of ≤$100/day (35% of $300) is plausible but unverified without a live week-long measurement window.

### Retry survival post-Phase-3
- Soft retry harness (#331) covered by 9 unit tests including the explicit acceptance scenarios: 1 fail + success → loop continues; 3 fails → exhausted with distinct stop reason. The harness wraps the picker call site; same kwargs, drop-in.

## 5. Cache regression discovered + fixed during this checkpoint preparation

While preparing for this checkpoint the operator surfaced a broader-check pytest failure: `test_store_rejects_when_dir_cap_breached` in `test_auth_discoverer_cache.py`. Investigation showed it was a genuine #332-introduced regression: `auth_discoverer._list_cache_files` and `_current_cache_size_bytes` iterated the cache directory listing via `memory_backend.execute("view", ...)`. After #332 truncated that view to 2 KB, the internal helpers undercount once >40 cache files exist → the 50 KB dir cap in `store_recipe` never engaged. Fixed in `00073d9` by switching the two helpers to direct filesystem access (`Path.iterdir() + stat()`). 77/77 Mythos-surface tests pass after the fix.

This is the kind of subtle interaction the empirical-on-live measurement would have surfaced sooner. Filed as a lesson for the next cleanup pass: when an infrastructure helper changes its behavior (truncation), the entire callgraph that consumes it through public APIs needs an audit. Documented in the regression commit message.

## 6. Deviations from #330-#332 plans

- **#330**: schema has 5 anyOf variants instead of "4 action shapes" because Anthropic strict mode disallows optional fields — `level_up` with-plan and without-plan are separate variants. Functionally equivalent to the 4-action design; documented in `_picker_output_schema()` docstring.
- **#332**: included a baseline regression test suite (`test_memory_backend.py`, 15 tests) that the task package referenced in `required_checks` but didn't exist. Added alongside the truncation tests so the validation command can actually run.
- **#332 cache regression**: discovered after commit; fixed in a follow-up commit (`00073d9`) without changing #332's external API. Operator's broader-check was the surfacing mechanism — value of that practice confirmed.
- **Pre-existing broader-codebase debt**: operator's broader pytest/ruff/ui-v2 check during #328 and again during #332 surfaced 21 pre-existing test failures + 27 ruff errors + ui-v2 build/lint errors that pre-date Phase 2/3. Captured as `backlog-390-broader-codebase-hygiene-sweep` (queue index 340) so it doesn't bleed into Phase 4 scope and isn't lost.

## 7. Plan-Finality re-check

Per `docs/MYTHOS_PLAN_FINALITY.md` Section 4 triggers, this checkpoint examines whether any revisit trigger fires.

| Trigger | Fired? |
|---|---|
| External target empirically breaks Phase 3 design | No — no post-cutover data exists yet; unit tests + architecture make the design robust by construction. |
| Cost model changed materially | No — Anthropic Claude Opus rates unchanged; if anything #330-#332 reduce dependency on per-token cost. |
| New external dep or platform shift | No. |
| Operator changed strategic goal | No — "best pentest tool that exists" goal unchanged. |
| Genuine code-level discovery invalidates plan | No — the #332 cache regression was a self-introduced interaction bug fixed in 36-line patch; not a plan-level problem. |

**No revisit trigger fires.** Plan stays. Phase 4 (#334-#337) proceeds.

## 8. GO / NO-GO

**GO for Phase 4 (#334-#337 — Cross-target provenance + Cross-runner verifier + Non-HTTP primitives + Final demo review).**

Justification:
- All three Phase-3 known issues are **architecturally resolved**, not "we improved them". Structured outputs makes JSON parse fail impossible by construction; soft retry catches the residual transient class; memory truncation caps the bloat.
- 103/103 Phase-3 unit tests pass (17 + 9 + 32 + 45 regression check). The cache regression discovered during checkpoint prep was caught and fixed; no other Mythos surface broken.
- The empirical "≤35% of $300/day" cost target is plausible from architectural math but unverified live; this is a measurement-window problem, not a Phase 3 implementation problem. Phase 4 is independent.
- Pre-existing broader-codebase debt is captured as a discrete task (#340 backlog-390) and not blocking Phase 4 sequencing.

Caveat tracked post-merge:
- **Empirical post-Phase-3 cost/parse-fail measurement** still pending. Operator restarts the API server with current `main` (or current branch), runs the loop against any target for 30+ advances, and `scripts/_phase3_checkpoint_mine.py` will produce the post-cutover numbers automatically. Mining script lives in source for repeatability. **Not a Phase 4 blocker.**

## 9. Next promotion

On GO: promote `backlog-384` (`#334 Phase 4 day 1 — Cross-target provenance`) into `NEXT_TASK.md`. Phase 4 begins.

---

## Appendix A: command transcript

```
$ git log --oneline -6
68d5357 Queue backlog-390: broader codebase hygiene sweep (#340)
00073d9 Fix #332 cache regression: bypass view truncation in cache size accounting
b560db0 Mythos #332: Memory tool view truncation + run-progress rotation (Phase 3 day 3)
aedaa49 Mythos #331: AI loop soft retry around the picker (Phase 3 day 2)
deaf472 Mythos #330: Picker structured outputs via output_config.format JSON Schema
4a572fe Mythos #329 addendum: live-Gruyere caveat closed honestly

$ python3 scripts/validate_backlog_tasks.py
Backlog validation passed: 340 queued task packages mapped one-to-one, and NEXT_TASK.md contains exactly one active task.

$ .venv/bin/pytest api/tests/test_assessment_loop_structured_outputs.py api/tests/test_assessment_loop_soft_retry.py api/tests/test_memory_backend.py api/tests/test_memory_backend_truncation.py api/tests/test_auth_discoverer_cache.py api/tests/test_auth_discoverer_acquire_session.py
103 passed in <1s

$ .venv/bin/python3 scripts/_phase3_checkpoint_mine.py
[see Section 3 baseline table; 2026-05-15 = 67 advances / 380 hops / $64.61 / 18 parse-fail events; post-cutover 2026-05-16+ = 0 hops]
```
