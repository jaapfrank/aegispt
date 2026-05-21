# Active Task

> **Read FIRST:** [`ANTI_DRIFT.md`](ANTI_DRIFT.md) (repo root) — 5 hard rules + pre-commit checklist + strenger DONE-definitie. Overschrijft SESSION_PROMPT §5.
>
> **Read SECOND:** [`SESSION_PROMPT.md`](SESSION_PROMPT.md) — kickoff discipline voor AegisPT sessies.

## Title

External knowledge — ExploitDB + NVD + CISA KEV read-only, provenance-scored — **Sprint mythos-exploitation-foundation, task 10 of 15**

## Goal

Layer 2 van architectuur: read-only lookup tegen ExploitDB (MCP server), NIST NVD, CISA KEV. Per Codex: 'nooit als onbewezen waarheid'. Elke reference draagt provenance score (source + freshness + applicability). Agents gebruiken als HINT voor hypothesis generation, NEVER als direct proof.

## Sprint context

Task 10 van 15 in sprint `mythos-exploitation-foundation`. backlog-415 slice 1 DONE — MetaCoordinator + 6 specialists + per-agent ACL + versioned prompt proposals. Recon-specialist en Hypothesis-specialist hebben nu een external-knowledge bron nodig: bij een gevonden technology stack/version, query ExploitDB+NVD+CISA-KEV voor relevante CVEs als HINT.

## Delta-doelstelling

> Deze task levert `api/app/services/external_knowledge.py` met `lookup_exploits(cve_id|product|version)` + `lookup_cve_details(cve_id)` + provenance scoring + `marked_as_hint_only=True` envelope. Delta-metric: ≥1 lookup return van ExploitDB met provenance, gebruikt als HINT voor exploit-developer-agent zonder als bewezen impact te claimen.

## Scope

(1) `api/app/services/external_knowledge.py`:
- `lookup_exploits(cve_id=None, product=None, version=None)` returns list of `ExternalKnowledgeHint` records.
- `lookup_cve_details(cve_id)` returns NVD CVE detail.
- `ExternalKnowledgeHint`: {source, source_url, title, fetched_at, applicability_score (0-1), marked_as_hint_only=True, body_excerpt}.
- Providers: ExploitDB MCP (pulsemcp) when configured; NVD API direct; CISA KEV daily JSON fetch + cache.
- Read-only — no write back to external systems.

(2) Per-provider rate limits + caching:
- 24h cache for KEV; 1h cache for NVD; per-query for ExploitDB.
- Cache dir configurable via `AEGISPT_KNOWLEDGE_CACHE` env (default `/tmp/aegispt-knowledge-cache`).

(3) Wire into Recon/Hypothesis specialists: when target-intel emits a CVE candidate or version fingerprint, the specialist calls `lookup_exploits(...)` and surfaces the hint envelope to the coordinator. Picker prompt section explains: lookups are HINTS only; never use as proof.

(4) Tests `api/tests/test_external_knowledge.py`: stub the HTTP providers; verify schema, applicability scoring, `marked_as_hint_only=True`, cache hit/miss, read-only contract (no write methods exposed).

## Constraints (per ANTI_DRIFT.md)

- Per Rule 1: capability task. Delta-metric = ≥1 ExternalKnowledgeHint surfaced to a live picker advance.
- Per Rule 2: lookup_exploits called from at least one specialist; no dead code.
- Per Rule 4 + 'never as proof': every result envelope has `marked_as_hint_only=True`; agents prompts forbidden from claiming impact based solely on KB results.
- Per `feedback_no_prescriptive_recipes`: KB hints emergently inform hypothesis, do NOT pre-seed step-by-step exploits.
- Read-only: providers exposed via lookup_* only; no write methods.

## Source Package

`codex/tasks/backlog-416-external-knowledge-exploitdb-readonly-provenance.json`

## Validation (ANTI_DRIFT.md pre-commit checklist)

- [ ] Code INVOKED: lookup_exploits called from at least one specialist path
- [ ] Delta-metric: ≥1 hint surfaced live with marked_as_hint_only=True
- [ ] Removed code: N/A (additive)
- [ ] Geen scope creep: external_knowledge module + 1 specialist wire-in + tests
- [ ] Follow-ups gefiled: <refs OR "none">
- [ ] Live test geslaagd: trace/log evidence

Plus required checks:
- `python3 scripts/validate_backlog_tasks.py`
- `.venv/bin/pytest api/tests/test_external_knowledge.py`
- `python3 -m compileall -q api`
- `.venv/bin/ruff check api/app/services/external_knowledge.py`
- `git diff --check`
- Live: ≥1 lookup_exploits trace in batch run.
