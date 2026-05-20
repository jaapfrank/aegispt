# Active Task

> **Read FIRST:** [`ANTI_DRIFT.md`](ANTI_DRIFT.md) (repo root) — 5 hard rules + pre-commit checklist + strenger DONE-definitie. Overschrijft SESSION_PROMPT §5.
>
> **Read SECOND:** [`SESSION_PROMPT.md`](SESSION_PROMPT.md) — kickoff discipline voor AegisPT sessies.

## Title

XBOW benchmark baseline harness — 104 challenges Docker isolated + anti-contamination guard — **Sprint mythos-exploitation-foundation, task 2 of 15**

## Goal

Establish empirical baseline for AegisPT against XBOW's 104 real-world web vulnerability scenarios (industry gold standard). Per Codex refinement: includes explicit anti-contamination guard — XBOW solutions MUST NOT leak into reusable memory or prompts. Provides the measurement instrument all subsequent capability tasks (409-419 + 422-423) will be evaluated against.

## Sprint context

Task 2 van 15 in sprint `mythos-exploitation-foundation`. backlog-407 (observability) DONE met 100% picker.advance trace coverage op live /iterate test. Per Codex: "XBOW baseline vroeg — anders bouwen we op gevoel".

## Delta-doelstelling (verplicht per SESSION_PROMPT §1)

> Deze task levert **scripts/xbow_benchmark.py** dat ≥20 XBOW challenges end-to-end runt zonder harness crash, met baseline XBOW score X/104 (initial mag laag zijn — baseline is meting, niet target). Contamination guard test passt: **0 XBOW challenge paths/flags in production source** + memory writes tijdens benchmark runs allemaal tagged `is_benchmark=True`.

## Scope

(1) New scripts/xbow_benchmark.py: clone/wrap https://github.com/KeygraphHQ/xbow-validation-benchmarks (of upstream); per challenge: Docker up → register engagement+scope in AegisPT → kick autonomous-intrusive run → poll → check CTF flag captured.
(2) Per-challenge metrics: solved_yes_no, time_to_solve, exec_plan_dispatches, exec_plan_successful, refinement_attempts.
(3) Aggregate report `docs/validation/xbow-{date}-baseline.md` + per-OWASP-Top-10 breakdown.
(4) Anti-contamination guard: benchmark-mode memory_backend writes tagged `is_benchmark=True`; greppable test scans production source for XBOW-specific strings.

## Constraints (per ANTI_DRIFT.md)

- Per ANTI_DRIFT Rule 1: meet-instrument, geen capability task. Delta-metric is "benchmark draait + baseline score gedocumenteerd".
- Per Rule 2: harness wordt actief gebruikt via CLI (`python3 scripts/xbow_benchmark.py --target ... --phase baseline`). Niet dead code.
- Per Rule 5: contamination guard NIET sluipweg gebruiken om benchmark-solutions in production prompts te lekken.
- Active task gate: ANTI_DRIFT.md + SESSION_PROMPT.md geladen.

## Source Package

`codex/tasks/backlog-408-xbow-benchmark-baseline-harness.json`

## Validation (ANTI_DRIFT.md pre-commit checklist)

```
- [ ] Mijn code is INVOKED in production path (script callable via CLI; not auto-imported by API)
- [ ] Delta-metric bewoog: baseline score X/104 documented at docs/validation/xbow-...-baseline.md
- [ ] Removed code I replaced: N/A (pure additive — new script + new tests)
- [ ] Geen scope creep: alle changes binnen scope (harness + grep-guard test + docs/validation/)
- [ ] Follow-ups gefiled: <refs OR "none">
- [ ] Live test geslaagd: <link to baseline report OR explicit "≥20 challenges ran" evidence>
```

Plus required checks:
- `python3 scripts/validate_backlog_tasks.py`
- `.venv/bin/pytest tests/test_xbow_contamination_guard.py tests/test_multi_target_validation_grep_guard.py`
- `python3 -m compileall -q scripts`
- `.venv/bin/ruff check scripts/xbow_benchmark.py`
- `git diff --check`
- `git grep -inE 'XBOW.*flag|xbow_challenge_solution' -- api/ workers/` → empty
- Live: `python3 scripts/xbow_benchmark.py --target all --phase baseline` produces report at `docs/validation/xbow-{date}-baseline.md` met ≥20 challenges run end-to-end.
