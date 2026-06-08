# Rework 4 Coordination Board

Date: 2026-06-08
Owners: Codex + Claude + Operator

## Purpose

This is the shared coordination file for the Rework 4 reset. Codex and Claude
keep separate worklists, but decisions that affect both lanes land here.

Separate worklists:

- Codex: `docs/strategy/rework4-codex-worklist-2026-06-08.md`
- Claude: `docs/strategy/rework4-claude-worklist-2026-06-08.md`

Primary plan:

- `docs/strategy/rework4-execution-plan-2026-06-08.md`
- `docs/strategy/rework4-shannon-research-reset-2026-06-08.md`

## Shared decision record

1. The architecture is decided: Shannon-style proof-loop, not another rebuild.
2. Evidence wins over model opinion and narrative summaries.
3. The local model is not the primary lever during Phase 0/1; it is measured
   later as a local comparison, ranker, or refusal-specialist.
4. Gruyere scaffold proof should run first with a frontier/strong provider,
   then with the local model as a separate comparison.
5. `NEXT_TASK.md` remains T-CHAIN1 until a live XBEN-024 artifact exists.
6. Generated validation artifacts and the canonical ledger outrank older
   strategy docs when solve counts disagree.
7. No new broad Web/LAN/WAN/IoT/AD/Cloud expansion during the reset.

## File ownership

| Area | Primary owner | Shared rules |
|---|---|---|
| Live runner/orchestration/proof-loop | Claude | Codex reads and proposes schema changes; Claude owns live wiring |
| Canonical evidence ledger | Codex | Claude appends run facts only through agreed schema or handoff |
| Candidate schema and fixtures | Codex | Claude consumes schema and requests missing fields here |
| Benchmark execution | Claude | Codex records/imports outcomes into ledger |
| Teacher data and training mix | Codex | Counts as data only until the ledger moves |
| Scope and budget | Operator | Agents record recommendations, operator decides |
| `CURRENT_STATE.md` and `DONE_LOG.md` | whoever completes a committed slice | Update only with factual completed work |

## Coordination protocol

Before starting a lane task:

- read `CURRENT_STATE.md`, `NEXT_TASK.md`, `DECISIONS.md`
- read this coordination board
- read your own worklist
- check `git status --short`
- add a short "starting" note here if the task touches shared assumptions

After finishing or blocking:

- update your own worklist if task status changed
- append a handoff note here
- update `CURRENT_STATE.md` and `DONE_LOG.md`
- run the relevant validation command
- commit the completed slice

## Handoff templates

Codex to Claude:

```text
YYYY-MM-DD HH:MM - Codex handoff
Artifact:
What changed:
Claude needs to:
Validation:
Blockers:
```

Claude to Codex:

```text
YYYY-MM-DD HH:MM - Claude handoff
Run:
Provider/model:
Outcome:
Evidence artifact:
Ledger impact:
Codex needs to:
Blockers:
```

Operator decision:

```text
YYYY-MM-DD HH:MM - Operator decision
Decision:
Reason:
Applies to:
Expires/revisit:
```

## Conflict rules

- If a live result and a narrative doc disagree, the live result wins.
- If a generated ledger and a hand-written count disagree, the generated
  ledger wins once committed.
- If Claude needs a ledger field that does not exist, request it here before
  writing an ad-hoc score file.
- If Codex needs runner facts that are not emitted, request them here before
  inferring them from logs.
- If a task would cross lane ownership, stop and record the proposed handoff
  here before editing.

## Current shared blockers

| Blocker | Owner | Status |
|---|---|---|
| Canonical ledger is not yet formalized/committed | Codex | next Codex task |
| Gruyere scaffold proof after infra fixes is not yet archived | Claude | next Claude task |
| T-CHAIN1/XBEN-024 has no live solve artifact | Claude | active score-lane task |
| Existing docs disagree on solve-count narratives | Codex | resolved by ledger reconciliation |

## Log

2026-06-08 - Codex setup

- Created separate Codex and Claude Rework 4 worklists.
- Created this coordination board.
- Confirmed the first clean split:
  - Codex starts with evidence-ledger formalization and candidate contracts.
  - Claude starts with Gruyere frontier/strong-provider scaffold proof, then
    local-model comparison.
- Detected an untracked `docs/validation/EVIDENCE_LEDGER.md` skeleton in the
  worktree. Codex should review/formalize it before committing or replacing it.
