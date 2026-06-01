# Active Task

> **Read FIRST:** [`ANTI_DRIFT.md`](ANTI_DRIFT.md) (repo root) — 5 hard rules + pre-commit checklist + strenger DONE-definitie.
>
> **Read SECOND:** [`SESSION_PROMPT.md`](SESSION_PROMPT.md) — kickoff discipline voor AegisPT sessies.
>
> **Read THIRD:** [`docs/research/open-work-consolidated-2026-05-27.md`](docs/research/open-work-consolidated-2026-05-27.md) section B — score-lane priorities. Do NOT promote anything from `TASK_QUEUE.md` (388 packages frozen).

## Title

Daily-5 score-lane: solve XBEN-005-24 (then XBEN-020-24) — daily-5 3/5 → 4/5, byte-equal-verified, committed on metric delta.

## Goal

Solve the next unsolved daily-5 member, **XBEN-005-24**, via the proven recon→exploit lever
(`scripts/xbow_benchmark.py`, `chatgpt_oauth` = €0). Diagnose the prior no-flag first (it
"reached code-exec-attack" per the 2026-05-27 baseline), fix the binding recon/exploit gap if
one exists (as PHP-sink detection unblocked XBEN-014), then prove a canonical SOLVE. Acceptance =
`docs/validation/xbow-daily5-005-<date>/` with byte-equal CAPTURED == `flag_injected`, persisted
critical finding, transcript + scope provenance, `check_finding_persistence_invariant.py` PASS.
Commit ONLY on the real metric delta (ANTI_DRIFT Rule 3).

## Why not B.1/B.2 (drift-check, 2026-06-01 — still applies)

- **B.1 (skill-pack A/B) — FORECLOSED.** Memory `feedback-skill-pack-duplicates-cpg-cea`: smoke
  63 ($7.57) empirically showed picker-prompt skill injection (B.1's mechanism) does NOT move
  SOLVE. Don't burn budget on a known null result.
- **B.2 (M2 verdict-gate DROP-PATH) — DONE.** Drop-path exercised in prod (10 FALSE_POSITIVE
  drops); the over-drop bug (raw-TCP flag captures dropped) was fixed by Track B `7cb6650`
  (0 flag-drops after; `DETERMINISTIC_PROOF` 26×; `test_m2_verdict_gate.py` 7/7).

The north-star is XBOW solve-rate (ANTI_DRIFT Rule 1); the proven lever is RECON completeness.
Keep marching the daily-5, not the foreclosed A/B.

## Notes

### Baseline (canonical truth — 2026-06-01)

- Daily-5 solved = **3/5**: XBEN-002-24, XBEN-014-24
  (`docs/validation/xbow-daily5-2026-06-01/`), XBEN-009-24
  (`docs/validation/xbow-daily5-009-2026-06-01/`, run `584542d3`, byte-equal, invariant PASS).
- Remaining unsolved: **XBEN-005-24** (no-flag, reached code-exec-attack) and **XBEN-020-24**
  (no-flag, wrapper deadline). Per open-work section A, the bottleneck on the unsolved is
  exploit-craft sophistication (Phase B), NOT infrastructure — but verify per challenge (XBEN-014
  proved the real blocker was recon detection, not exploit-craft).
- Known tool-quality gap seen in the 009 solve: `nmap` runs host-discovery only (0.00s, no port
  lines) on port-scoped targets — surfaces no open port. Non-blocking but a recon-quality
  follow-up (cf `feedback-audit-toolcall-quality`).

### Method

- `chatgpt_oauth` = €0 Anthropic credits. Hard wall-clock budget per challenge (ANTI_DRIFT
  Rule 4). Source-aware allowed (white-box near-term lever). Diagnose-before-rerun: read the
  challenge source + the prior no-flag run's tool-call trace before spending a fresh run.
- Verify every claimed SOLVE: byte-equal CAPTURED vs `flag_injected`, persisted finding,
  transcript, scope; audit the individual tool calls (not just solve-status).

### Hard rules (operator-set)

1. No 4th overhaul. Discipline, not architecture.
2. No idle waiting — finish inline OR hand a concrete next-action.
3. `substrate-shipped` ≠ `live-proven`. No DONE on substrate-only.
4. Hard wall-clock budget on every cloud-LLM run.
5. Commit after a task is done (operator 2026-06-01).
6. Lane separation: do NOT touch the concurrent Codex UI/reporting lane's files
   (`ui-v2/*`, `CURRENT_STATE.md`/`DECISIONS.md`/`DONE_LOG.md` while it holds them,
   `docs/validation/codex-ui-reporting-*`). Score-lane commits exclude codex work.

## When does this active task end?

When `docs/validation/xbow-daily5-005-<date>/` exists with a byte-equal-verified XBEN-005 SOLVE
(invariant PASS), daily-5 at 4/5, committed score-lane-only. Next active task = XBEN-020-24
(the last unsolved daily-5 member).

## Carry-over (deferred, blocked by concurrent codex lane)

The XBEN-014 + XBEN-009 DONE_LOG.md entries are pending: DONE_LOG.md / CURRENT_STATE.md remain
held by the live Codex UI lane. Content is preserved in the score-lane commit messages
(`496656c` for 014, this commit for 009) + the artifact READMEs; land them into DONE_LOG.md once
the codex lane releases the file.
