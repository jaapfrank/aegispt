# Rework 4 Codex Worklist

Date: 2026-06-08
Owner: Codex
Pairs with:

- `docs/strategy/rework4-execution-plan-2026-06-08.md`
- `docs/strategy/rework4-shannon-research-reset-2026-06-08.md`
- `docs/strategy/rework4-claude-worklist-2026-06-08.md`
- `docs/strategy/rework4-coordination-board-2026-06-08.md`

## Purpose

Codex owns the data, ledger, candidate-contract, registry, and reproducibility
lane for the Rework 4 reset. Codex does not own live benchmark execution or
runner exploit wiring unless a future task explicitly transfers that work.

The goal is to make Claude's runner/score-lane work measurable and
reproducible, without creating a second source of truth.

## Hard boundaries

- Do not mark T-CHAIN1 done. `NEXT_TASK.md` remains active until a live
  XBEN-024 validation artifact exists.
- Do not promote model-training output as capability progress unless the
  canonical evidence ledger shows held-out/live movement.
- Do not edit live runner/orchestration behavior while Claude is actively
  proving the scaffold, except for additive schema/adapter work agreed in the
  coordination board.
- Do not create new score docs with independent solve counts.
- Do not touch capability registry, approval flow, deployment flow, or runtime
  binding flow for this reset.

## Active tasks

| ID | Phase | Task | Output | Done when |
|---|---|---|---|---|
| X0 | coordination | Maintain Codex lane state | this worklist + coordination board | Claude and Codex have separate worklists and one shared board |
| X1 | 0.3 | Formalize canonical evidence ledger contract | ledger schema, JSONL path, summary rules, validation command | historical 17 solves and new Gruyere/XBEN runs can be represented without contradictory counts |
| X2 | 0.3 | Reconcile generated score artifacts into the ledger | importer or documented mapping from `docs/validation/` and XBEN matrix artifacts | generated artifacts win over narrative docs |
| X3 | 0.4 | Scope-freeze record | source-aware web/API + XBEN lab scope entry | broad LAN/WAN/IoT/AD/Cloud/UI work is explicitly paused for this reset |
| X4 | 1.1 | Source-to-exploit candidate schema | versioned candidate schema and fixture examples | Claude can wire runner dispatch from candidates instead of generic scanner output |
| X5 | 1.1 | Candidate fixtures from existing source triage | fixture rows for auth, SSRF, XSS/headless, injection, file/path/upload | every fixture has candidate id, source/runtime cue, state, and expected evidence class |
| X6 | 1.1/1.4 | Candidate state taxonomy | allowed states and transition rules | untested, blocked, exploited, false-positive, and no-signal states are unambiguous |
| X7 | 2.1 | Benchmark ledger ingestion | XBOW-104 result ingestion path | Claude can run benchmarks and append outcomes without hand-maintained summaries |
| X8 | 3.2 | Ranker/policy training gate | data contract for candidate ranking | local model work resumes only against ledger-backed candidate decisions |

## Backlog, not active

| ID | Task | Why parked |
|---|---|---|
| X9 | More V4-Pro teacher data | existing mix is enough until live ledger proves a policy gap |
| X10 | New RL env families | useful later, but runner proof-loop comes first |
| X11 | Full Shannon result import | wait until Claude decides whether to run Shannon baseline |

## Handoff format to Claude

When Codex produces a schema, fixture, or ledger change, append a short entry to
`docs/strategy/rework4-coordination-board-2026-06-08.md`:

```text
YYYY-MM-DD HH:MM - Codex handoff
Artifact:
What changed:
Claude needs to:
Validation:
Blockers:
```

## First Codex action

Start with X1 and X2: formalize the canonical evidence ledger so Gruyere and
XBEN proof runs land in one place from the beginning of Phase 0.
