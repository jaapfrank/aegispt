# Rework 4 Claude Worklist

Date: 2026-06-08
Owner: Claude
Pairs with:

- `docs/strategy/rework4-execution-plan-2026-06-08.md`
- `docs/strategy/rework4-shannon-research-reset-2026-06-08.md`
- `docs/strategy/rework4-codex-worklist-2026-06-08.md`
- `docs/strategy/rework4-coordination-board-2026-06-08.md`

## Purpose

Claude owns the live runner, orchestration, proof-loop, verification, and
benchmark execution lane for the Rework 4 reset. Claude should prove the
scaffold with a strong frontier brain first, then compare local model behavior
as a separate measurement.

The goal is to restore and harden the existing scaffold, not rebuild it.

## Hard boundaries

- Do not mark T-CHAIN1 done until live XBEN-024 evidence exists under
  `docs/validation/` with byte-equal proof and invariant pass.
- Do not treat a local-model failure as scaffold failure unless the same path
  also fails with the selected frontier/strong provider.
- Do not create new score summaries outside the canonical evidence ledger.
- Do not run parallel XBEN challenges when the repo guidance says sequential
  benchmark runs only.
- Do not change Codex-owned data/ledger schemas without recording the proposal
  in the coordination board first.

## Active tasks

| ID | Phase | Task | Output | Done when |
|---|---|---|---|---|
| C0 | coordination | Read and follow the shared coordination board | board entries before/after live work | Codex can see live-run assumptions and blockers |
| C1 | 0.2 | Gruyere scaffold regression re-run with frontier/strong brain | validation artifact + ledger row | admin/secret proof restored or exact blocker recorded |
| C2 | 0.2 | Gruyere local-model comparison | separate validation artifact + ledger row | local model result is classified as model gap or success, not scaffold proof |
| C3 | 0.1 | One XBEN live proof-loop reproduction | validation artifact + ledger row | at least one XBEN solve reproduced with evidence |
| C4 | T-CHAIN1 | XBEN-024 honest closure | `docs/validation/xbow-xben024-<date>/` | solved with byte-equal proof or explicitly not done with blocker |
| C5 | 1.2 | No Exploit, No Report gate | runner/reporting gate | unproven hypotheses cannot become findings |
| C6 | 1.3 | Hard runner state | persisted auth/session/token/blocker state | login, cookies, revealed creds, and blockers survive across the exploit loop |
| C7 | 1.4 | Coverage/coordinator | tested/untested/blocked boundary records | redundant redispatch is reduced and no-finding has coverage evidence |
| C8 | 1.5 | Provider pluggability proof | same loop across at least two brains | provider is a run setting, not hidden runner default |
| C9 | 2.1 | XBOW-104 benchmark run | canonical ledger rows | one real solve-rate exists, not a narrative estimate |
| C10 | 2.2 | Optional Shannon baseline | side-by-side notes | used only after AegisPT's own baseline is measured |

## Recommended execution order

1. C0: add a coordination-board entry before starting live runs.
2. C1: run Gruyere with the strongest available provider first.
3. C2: compare the local model on the same Gruyere path.
4. C3/C4: reproduce one XBEN solve, prioritizing T-CHAIN1/XBEN-024 if the
   scaffold is stable.
5. C5-C8: harden the proof-loop based on measured failures.
6. C9: run XBOW-104 only after ledger ingestion is ready.

## Handoff format to Codex

When Claude completes or blocks a live run, append a short entry to
`docs/strategy/rework4-coordination-board-2026-06-08.md`:

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

## First Claude action

Start with C1, not a local-only run: Gruyere with a frontier/strong provider is
the cleanest proof that the scaffold fixes restored the baseline.
