# Active Task

> **Read FIRST:** [`ANTI_DRIFT.md`](ANTI_DRIFT.md) (repo root) — 5 hard rules + pre-commit checklist + strenger DONE-definitie. Overschrijft SESSION_PROMPT §5.
>
> **Read SECOND:** [`SESSION_PROMPT.md`](SESSION_PROMPT.md) — kickoff discipline voor AegisPT sessies.

## Title

Episodic memory layer — PostgreSQL + pgvector ADDITIVE (memory_backend stays as short-term scratchpad) — **Sprint mythos-exploitation-foundation, task 4 of 15**

## Goal

Add an episodic memory layer for (action, context, outcome, success_marker) tuples queryable via vector similarity. Per Codex refinement: ADDITIVE, NOT a replacement of `api/app/services/memory_backend.py`. File-backed memory_backend stays as short-term scratchpad; pgvector layer is for cross-advance and cross-run retrieval. Memory remains skeptical per Claude Code lessons — every retrieval is a HINT, evidence must still be verified.

## Sprint context

Task 4 van 15 in sprint `mythos-exploitation-foundation`. backlog-409 (Layer 0 Governance Control Plane + sandbox_runner) DONE in 4 slices — 3 dispatch-authorization call sites now route through `GovernanceControlPlane`, sandbox_runner module ready voor wire-in door 414. Met Layer 0 in place is het veilig om aan de memory layer te bouwen omdat episodic recalls nu via één authorize-pad lopen.

## Delta-doelstelling (verplicht per SESSION_PROMPT §1)

> Deze task levert `api/app/services/episodic_memory.py` met `write_episode(action, context, outcome)` + `recall_similar(query, k=5)` + `skeptical_recall_with_verify_hint()`. Database table `agent_episodic_memory` via Alembic migratie. Embeddings via configurable provider. Per Codex contamination guard: benchmark writes tagged `is_benchmark=True`, NEVER teruggegeven aan non-benchmark recalls. `memory_backend.py` blijft ongewijzigd — file-memory als short-term scratchpad behouden.

## Scope

(1) Alembic migration `migrations/versions/{date}_agent_episodic_memory.py` — new table:
- `id` UUID, `run_id` UUID, `engagement_id` UUID
- `action_type` str (e.g. "exec_plan", "runner_dispatch")
- `action_context_jsonb` JSONB, `outcome_jsonb` JSONB
- `success_marker` str (e.g. "flag_captured", "finding_critical", "no_progress")
- `embedding vector(1536)` (pgvector)
- `created_at` timestamptz, `is_benchmark` bool

(2) New `api/app/services/episodic_memory.py`:
- `write_episode(session, *, run, action_type, context, outcome, success_marker)` — embeds context+outcome, persists row, tags `is_benchmark` based on engagement config.
- `recall_similar(session, *, query, k=5, filter_run_id=None, include_benchmark=False)` — vector similarity query, default excludes benchmark rows.
- `skeptical_recall_with_verify_hint(session, *, query, k=5)` — wraps recall_similar and prepends `[HINT, VERIFY BEFORE USE]` marker on every result.

(3) Embeddings provider abstraction: `_embed(text)` reads `EPISODIC_EMBED_PROVIDER` env (default `openai`, fallback `local_hash` for tests). LiteLLM-based provider lands when backlog-417 unifies LLM access — keep the abstraction so the swap is one line.

(4) `memory_backend.py` UNTOUCHED — file-memory blijft als short-term scratchpad per Codex refinement #3.

(5) Unit tests `api/tests/test_episodic_memory.py`: write+read round-trip, is_benchmark isolation (benchmark write NOT returned in production recall), skeptical-hint marker present, fallback to local_hash when no provider configured.

## Constraints (per ANTI_DRIFT.md)

- Per Rule 1: capability task. Delta-metric = "≥1 recall_similar call from a live picker.advance returns ≥1 episode written by a previous advance in the same run (verified via OTEL trace + DB query)".
- Per Rule 2: `episodic_memory.write_episode` MOET aangeroepen worden vanuit `advance_assessment_loop` per advance; geen dead code.
- Per Rule 3 (geen backward-compat creep): `memory_backend.py` stays — additive layer. Mark this explicitly in commit message ("memory_backend untouched; new layer is queryable + cross-run").
- Per Rule 4 (geen mocked-live): live verification via XBOW harness — `recall_similar` returns ≥1 row after 3+ advances on the same run.
- Per Rule 5: contamination guard — write_episode during benchmark engagements tagged `is_benchmark=True`; recall_similar default excludes those rows.

## Source Package

`codex/tasks/backlog-410-episodic-memory-pgvector-additive.json`

## Validation (ANTI_DRIFT.md pre-commit checklist)

```
- [ ] Code INVOKED in production path: episodic_memory.write_episode called from advance_assessment_loop on every advance
- [ ] Delta-metric bewoog: recall_similar returns >=1 episode after 3+ advances on same run (cite OTEL trace ids)
- [ ] Removed code I replaced: N/A (additive; memory_backend untouched — confirm in commit)
- [ ] Geen scope creep: episodic_memory module + migration + tests + 1 advance_assessment_loop call site only
- [ ] Follow-ups gefiled: <refs OR "none">
- [ ] Live test geslaagd: <link to live trace OR DB query of agent_episodic_memory rows>
```

Plus required checks:
- `python3 scripts/validate_backlog_tasks.py`
- `.venv/bin/pytest api/tests/test_episodic_memory.py`
- `python3 -m compileall -q api`
- `.venv/bin/ruff check api/app/services/episodic_memory.py`
- `alembic upgrade head && alembic downgrade -1 && alembic upgrade head`
- `git diff --check`
- Live: ≥1 XBOW challenge run produces ≥3 agent_episodic_memory rows + recall_similar returns prior episode hint to the next advance.
