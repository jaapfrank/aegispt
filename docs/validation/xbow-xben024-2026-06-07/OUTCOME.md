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

### Update 2026-06-07 (cont.) — 3 infra bugs found + fixed (all committed)

The source-aware pipeline was broken in three independent places, each blocking the whole
auth-logic/source-aware class (not just XBEN-024):

1. **DATABASE_URL split-brain** (`30614b8`) — worker `session_scope()` defaulted to SQLite
   while the API used Postgres → `task not found` → every run wedged at `queued`. FIXED +
   validated (runs now execute, 11 tool_executions).
2. **AEGISPT_INTERACTIVE_EXPLOIT unset** (`1140027`) — the focused per-source-objective
   interactive-exploit dispatch is env-gated; the unit never set it. FIXED (pre-recon-source
   now gets queued in source-aware runs).
3. **source_dir not in pre-recon-source task params** (`cf3e53b`) — the AI picker built the
   pre-recon-source candidate without `source_dir` → runner skips `no_source_dir` → picker
   stays black-box. Empirically confirmed (run fd002662 params had no source_dir). FIXED in
   `_queue_passive_loop_task`. Direct proof the detection works: running pre_recon_source on
   the XBEN-024 source surfaces `forgeable-session-secret: supersecretkey` + `ssrf-urlretrieve`.

4. **pre-recon-source not dispatched on non-specialists providers** (`3639e43`) — the
   source-aware bootstrap (dispatch pre-recon-source FIRST) lived ONLY in the specialists
   picker; chatgpt_oauth/local_qwen/anthropic never ran the white-box scan. Hoisted to the
   top of `_claude_select_next_action` (provider-agnostic). PROVEN: XBEN-024 with
   chatgpt_oauth now runs pre-recon-source as the 2nd task, status=completed, source_dir in
   params (marker `picker: ... provider-agnostic bootstrap`). The source scan now surfaces
   `forgeable-session-secret: supersecretkey` + the SSRF chain to the picker.

### Remaining blockers (the actual XBEN-024 solve)

- **5th gap — focused-exploit dispatch is specialists-only:** the per-source-objective
  interactive-exploit dispatch lives in `_maybe_dispatch_cpg_seeded_cea`, called ONLY from
  `_specialists_select_next_action` (3049). So even though the secret now surfaces for
  chatgpt_oauth, the actual exploit is never dispatched on non-specialists providers. Fix:
  hoist the focused-exploit dispatch provider-agnostically (same pattern as `3639e43`), OR
  run with `PICKER_MODE=specialists`.
- **Provider policy-refusal:** even once the exploit dispatches, chatgpt_oauth may refuse
  the session-forgery. Cleanest path: `local_qwen` (uncensored) once the GPU frees from the
  IDOR-focus re-tune.
- **Net:** the source-aware *pipeline* is now fixed end-to-end (secret surfaces for all
  providers); the *exploit dispatch* + a *non-refusing provider* are the last two steps,
  both best closed together once the GPU frees (local_qwen + hoisted focused-exploit).

## Reproduce
`bash docs/validation/xbow-xben024-2026-06-07/reproducer.sh` (provider currently chatgpt_oauth).
