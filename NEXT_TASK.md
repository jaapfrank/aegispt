# Active Task

## Title

Memory Tool Result Truncation and Bloat Containment (Phase 3 day 3)

## Goal

Cap `memory_backend.execute` response size at 2 KB per call and refactor `/memories/run-progress.md` from an unbounded log into a bounded structured summary. Reduces the ~9 KB per memory-tool call wasted on the picker prompt (~922 calls/day observed = ~$30/day saving at current pricing). Closes the third known-issue bullet in `AGENT_SYSTEM_MAP.md` section 2: "Memory file `/memories/run-progress.md` grows unbounded".

## Scope

- Modify `api/app/services/memory_backend.py` to truncate `view` command results to 2 KB with a trailing `[...truncated, N more bytes]` marker.
- Add a separate maintenance helper that periodically rotates `/memories/run-progress.md` when it exceeds 8 KB, keeping only the most recent 6 KB of content.

## Constraints

- Truncation + rotation only. Do NOT change the memory tool schema, the system prompt directives about /memories paths, or any storage backend.
- Writes are NOT capped. Only reads are truncated for prompt-injection bounds. The full file remains on disk.
- Truncation must include a clear marker that prompts Claude to view sub-paths or read further if needed. Do not silently drop content.
- Must NOT touch: `_AI_PICKER_SYSTEM_PROMPT`, `workers/runners/`, `workers/orchestration/`, `api/app/services/assessment_loop.py` (only log-message lines that show truncation activity may change there if needed).

## Source Package

`codex/tasks/backlog-382-memory-tool-result-truncation.json`

## Reference

- `api/app/services/memory_backend.py` (`execute("view", ...)` is the read path that needs truncation)
- `docs/AGENT_SYSTEM_MAP.md` section 2 ("Memory file `/memories/run-progress.md` grows unbounded") and section 6 (memory tool integration)
- Cost data: ~922 memory-tool calls/day × ~11 KB avg result = ~10 MB/day injected into the picker prompt; truncation to 2 KB saves ~80% per call.

## Validation

- `python3 scripts/validate_backlog_tasks.py`
- `.venv/bin/pytest api/tests/test_memory_backend_truncation.py api/tests/test_memory_backend.py`
- `python3 -m compileall -q api`
- `.venv/bin/ruff check api/app/services/memory_backend.py`
- `git diff --check`
- Acceptance: `memory_backend.execute view` capped at 2 KB with truncation marker; rotation helper keeps `/memories/run-progress.md` under 8 KB; logged `cache_read_input_tokens` per picker hop drops measurably (deferred to operator validation on live runs).
