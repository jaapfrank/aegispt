# Active Task

> **Read FIRST:** [`ANTI_DRIFT.md`](ANTI_DRIFT.md) (repo root) — 5 hard rules + pre-commit checklist + strenger DONE-definitie. Overschrijft SESSION_PROMPT §5.
>
> **Read SECOND:** [`SESSION_PROMPT.md`](SESSION_PROMPT.md) — kickoff discipline voor AegisPT sessies.

## Title

Context curation (Claude Code autoCompact-style) — evidence-preserving summarization at budget thresholds — **Sprint mythos-exploitation-foundation, task 5 of 15**

## Goal

Implement context-window curation per Claude Code's autoCompact pattern. At 60% / 80% budget thresholds, summarize older conversational turns into dense representations, DROP verbose raw tool outputs (large nuclei JSON, full HTML bodies), PRESERVE outcomes + captured_value entities + finding records. Prevents context starvation during long-running advance loops where the picker currently degrades around iteration 10.

## Sprint context

Task 5 van 15 in sprint `mythos-exploitation-foundation`. backlog-410 (episodic memory) DONE — `agent_episodic_memory` populates per advance. Context curation now closes the loop: at compact time the picker consults `skeptical_recall_with_verify_hint(...)` for cross-run hints and the curator drops verbose raw outputs but PRESERVES the structured outcome records that produced those episodes.

## Delta-doelstelling (verplicht per SESSION_PROMPT §1)

> Deze task levert `api/app/services/context_curation.py` met `curate_for_picker(messages, budget_pct, *, preserve_findings, preserve_captured_values)` die de berichtenlijst inkort bij 60% / 80% budget triggers. Hook in `_claude_select_next_action`. OTEL trace per curation event met before/after token count. Delta-metric: picker advance ≥15 succeeds without context-window error on a single XBOW run (currently degrades ~10 advances).

## Scope

(1) New `api/app/services/context_curation.py`:
- `estimate_tokens(messages) -> int` (heuristic, ~4 chars/token)
- `curate_for_picker(messages, *, max_tokens, preserve_finding_ids, preserve_captured_value_ids)` — returns a new (curated_messages, curation_event) tuple.
- Preserve rules: structured `finding` records ALWAYS preserved; `captured_value` entities NEVER dropped; raw tool stdouts >2 KB get summarized into one-line `[curated: tool=X status=Y size_dropped=N bytes]` envelopes.
- Older conversational turns (older than the last 6) get summarized via a dedicated small Claude call OR via a deterministic structural extractor (default — keep the curator deterministic so it doesn't itself need a budget).

(2) Hook into `_claude_select_next_action` (`api/app/services/assessment_loop.py`): right before `client.messages.create(...)`, call `curate_for_picker(messages, max_tokens=120_000)` and emit an OTEL span `picker.context_curation` with attributes `before_tokens`, `after_tokens`, `dropped_count`, `preserved_finding_count`.

(3) Optional integration with episodic_memory: after curation, append a single synthetic message holding `skeptical_recall_with_verify_hint(query=summary_of_current_phase, k=3)` so the picker has a HINT panel of similar past episodes. The hint envelope already has the verify-before-use marker.

(4) Unit tests: `api/tests/test_context_curation.py` — preserve-rules respected (findings + captured_values survive), large raw stdouts summarized, token estimate roughly matches expected.

## Constraints (per ANTI_DRIFT.md)

- Per Rule 1: capability task. Delta-metric = "picker successfully completes ≥15 advances on a single XBOW run without context-window errors (currently degrades ~10)".
- Per Rule 2: `curate_for_picker` MOET aangeroepen worden vanuit `_claude_select_next_action` in dezelfde commit als de module — geen dead code.
- Per Rule 3 (geen backward-compat creep): when the curator runs, the OLD message list is REPLACED, not parallel-kept. Verify via picker prompt size delta after a 15-advance run.
- Per Rule 4 (geen mocked-live): live verification via 15+ advances on XBEN-002 — pre-curation context size + post-curation context size both logged.
- Per Rule 5: preserve-rules can't be sluipweg used to keep XBOW-specific hints in non-benchmark runs (episodic_memory already isolates benchmark/production; the curator just respects the recall result it gets).

## Source Package

`codex/tasks/backlog-411-context-curation-autocompact.json`

## Validation (ANTI_DRIFT.md pre-commit checklist)

- [ ] Code INVOKED in production path: `curate_for_picker` called from `_claude_select_next_action` before every Anthropic API call
- [ ] Delta-metric bewoog: picker advance ≥15 succeeds without context-window error (cite trace id)
- [ ] Removed code I replaced: none (additive) OR cite specific old context-truncation code that's superseded
- [ ] Geen scope creep: context_curation module + 1 hook in `_claude_select_next_action` + tests
- [ ] Follow-ups gefiled: <refs OR "none">
- [ ] Live test geslaagd: <link to OTEL trace OR token-count log from 15-advance run>

Plus required checks:
- `python3 scripts/validate_backlog_tasks.py`
- `.venv/bin/pytest api/tests/test_context_curation.py`
- `python3 -m compileall -q api`
- `.venv/bin/ruff check api/app/services/context_curation.py`
- `git diff --check`
- Live: an XBOW challenge run produces ≥1 OTEL `picker.context_curation` span with before>after token counts.
