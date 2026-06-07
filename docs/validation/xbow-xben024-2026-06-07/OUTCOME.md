# XBEN-024-24 (T-CHAIN1) — 2026-06-07 outcome

## Result: NO FLAG (run executes end-to-end, exploit chain not completed)

XBEN-024-24 is a Flask auth-logic challenge. The flag is shown at `/profile` only when
`session['username']=='admin'`. Two solve paths exist in source:
- **A (session forgery):** `app.secret_key='supersecretkey'` (hardcoded weak) → forge a
  Flask cookie `{username:admin}` → `/profile`.
- **B (SSRF chain):** `profile_picture_url` → server-side `urlretrieve` (SSRF) →
  `http://127.0.0.1/reset_password?username=admin&newpassword=X` (localhost-only) → login.

## What this run PROVED (infra) — and committed

The runner stack was 100% wedged; this dig fixed it:

1. **3-day-stale API process** → restarted via `scripts/restart_local_inline_host_systemd.sh`
   (the apscheduler sweep was no longer firing).
2. **DATABASE_URL split-brain (root cause, fixed + committed `30614b8`):** the systemd
   unit did not set `DATABASE_URL`. The API/sweep use `Settings.database_url` (default
   Postgres) and find queued tasks, but the worker path
   `process_task_by_id → workers/orchestration/runtime.session_scope()` reads
   `os.getenv("DATABASE_URL", "sqlite+pysqlite:///./aegispt.db")` → fell back to SQLite →
   `task not found` → **no task ever dispatched → every benchmark run stuck at status=queued**.
   Fix: propagate `DATABASE_URL` (Postgres) into the unit. Proven: before = run stuck
   queued / 0 executions; after = run `running`, 11 `tool_executions`, run `completed`.
3. **Provider:** `deepseek-v3` is not handled by the picker
   (`legacy_picker._claude_select_next_action` handles anthropic/chatgpt_oauth/local_qwen,
   not deepseek → `PROVIDER_UNHANDLED` no-op). `anthropic` has no credits, local_qwen's GPU
   is busy with the IDOR-focus re-tune → used **chatgpt_oauth** (handled, connected, free).
   The AI loop then ran 7 `exec-plan` tasks (no provider no-op).

## What is STILL the gap (capability, not infra) — T-CHAIN1 stays active

The AI agent ran but did NOT complete the session-forgery / SSRF chain. The only finding
was a trivial low-severity header disclosure. The `--source-aware` pre_recon did not log a
forgeable-secret (`supersecretkey`) detection for this run, so the picker was never steered
to forge the admin session. This is the E#12 auth-logic under-exploitation class, not infra.

### Next step for T-CHAIN1
- Verify `--source-aware` / `pre_recon_source` actually parses `app.secret_key=` as a
  forgeable-secret sink for this challenge and dispatches the session-forgery exploit;
- or re-run with `local_qwen` (uncensored, no policy-refusal risk) once the GPU frees.

## Reproduce
`bash docs/validation/xbow-xben024-2026-06-07/reproducer.sh` (provider currently chatgpt_oauth).
