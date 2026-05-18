# Active Task

## Title

Empirical Phase-3 live validation: restart API + 30+ picker advances + mine post-cutover cost / parse-fail / retry / capture-usage data (backfill 6 of 6 — FINAL)

## Goal

Three back-to-back tasks (\#330 structured outputs, \#332 memory truncation, \#333 review checkpoint) each DEFERRED live validation to the operator. The result: the \$300/day → ≤\$100/day cost-reduction target is plausible from math but unverified; the structured-outputs zero-parse-fail claim is unverified live; and the rotation saving from backlog-392 (now wired) is also unverified. This task is the explicit agent-runnable validation step: restart the API server with current code, run the assessment loop against any reachable target for ≥30 advances, then run `scripts/_phase3_checkpoint_mine.py` on the post-cutover log and append results to the Phase-3 checkpoint report. Also: \#334 RECENT_CAPTURES capture-usage validation — mine logs for evidence that the picker actually references captured values in its reasoning text (verifies \#343's prompt addendum effectiveness).

## Scope

- Pure validation task — no production code changes.
- Restart the API server (systemd via `scripts/restart_local_inline_host_systemd.sh` if available, otherwise direct uvicorn).
- Verify the running process matches current-HEAD commit (`git rev-parse HEAD` matches the worker's import-time log line).
- Trigger a 30+-advance run against juice-shop or demo.testfire.net (reachable per \#329 checkpoint).
- Wait for completion or natural stop (`stuck_no_new_signals` / `picker_retry_exhausted` / `exhausted` etc.).
- Run `scripts/_phase3_checkpoint_mine.py` on `/tmp/aegispt-api.log`.
- Append a section 10 to `docs/checkpoints/2026-mythos-phase3-review.md` with: total advances, avg input/cache_read/cache_creation/output tokens per hop, total cost, parse-fail count, picker_retry_exhausted count, picker_recovered count, RECENT_CAPTURES citation count in reasoning text.
- Close section 10 with explicit GO/NO-GO on the ≤\$100/day claim.
- If data refutes the claim, file a follow-up tuning task in the same commit (do NOT paper over).

## Constraints

- Validation + report append only. Do NOT modify `api/app/services/`, do NOT modify `workers/`, do NOT tune the picker (tuning belongs in a separate follow-up if data refutes the claim).
- Per `feedback_constraint_recap_noise`: load-bearing failures get documented load-bearing; near-misses are flagged for tuning.
- Per `feedback_self_validation`: this is exactly the kind of agent-runnable validation the operator has explicitly told me to run rather than defer.
- backlog-392 (rotate wiring) was merged in `f018434` so the post-cutover data reflects the FULL Phase-3 saving stack.
- Must NOT touch: `api/app/services/assessment_loop.py`, `api/app/services/memory_backend.py`, `_AI_PICKER_SYSTEM_PROMPT`, `_PICKER_OUTPUT_SCHEMA`, `workers/`, `scripts/_phase3_checkpoint_mine.py` (consume only).

## Source Package

`codex/tasks/backlog-397-empirical-phase3-live-validation.json`

## Reference

- `scripts/_phase3_checkpoint_mine.py` — the log-mining script (consume only)
- `scripts/restart_local_inline_host_systemd.sh` — API restart helper
- `docs/checkpoints/2026-mythos-phase3-review.md` — checkpoint report; section 10 to be appended
- DONE_LOG entries for \#330, \#332, \#333, \#342, \#343 — the deferred claims this task validates
- AGENT_SYSTEM_MAP.md §5 — Phase-3 empirical cost data (the pre-cutover baseline)

## Validation

- `python3 scripts/validate_backlog_tasks.py`
- `test -f docs/checkpoints/2026-mythos-phase3-review.md && grep -q '## 10\.' docs/checkpoints/2026-mythos-phase3-review.md`
- `python3 scripts/_phase3_checkpoint_mine.py /tmp/aegispt-api.log`
- `git diff --check`
