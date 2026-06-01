# Active Task

> **Read FIRST:** [`ANTI_DRIFT.md`](ANTI_DRIFT.md) (repo root) — 5 hard rules + pre-commit checklist + strenger DONE-definitie.
>
> **Read SECOND:** [`SESSION_PROMPT.md`](SESSION_PROMPT.md) — kickoff discipline voor AegisPT sessies.
>
> **Read THIRD:** [`docs/research/open-work-consolidated-2026-05-27.md`](docs/research/open-work-consolidated-2026-05-27.md) section B — score-lane priorities. Do NOT promote anything from `TASK_QUEUE.md` (388 packages frozen).

## Title

Daily-5 scorelane: move the metric beyond 1/5 — solve ≥1 of XBEN-005 / 009 / 014 / 020 (byte-equal-verified), commit only on metric delta.

## Goal

Re-run the fixed daily-5 subset (XBEN-002, 005, 009, 014, 020) on one provider via `scripts/xbow_benchmark.py`, and improve the score-lane metric over the `xbow-daily5-baseline-2026-05-27.md` baseline (`1/5`). Acceptance = a new `docs/validation/xbow-daily5-<date>/` artifact showing EITHER (a) ≥1 NEW byte-equal-verified SOLVE among {005, 009, 014, 020}, OR (b) a documented, measured delta on exec_plan dispatch rate / crash-or-stuck rate / time-to-first-proof for a named challenge. Commit ONLY on a real metric delta (ANTI_DRIFT Rule 3: `substrate-shipped` ≠ `live-proven`).

## Notes

### Baseline to beat (canonical truth)
- XBEN-002-24 is SOLVED + STABLE (3/3 on 2026-05-27 commit `806beb4`, + a 4th reproduction `c70383f1` on 2026-06-01 / commit `c479063`). Score-lane = `1/25`. Do NOT re-spend budget re-confirming XBEN-002 beyond the occasional regression check.
- The 4 unsolved daily-5 (per `xbow-daily5-baseline-2026-05-27.md`): XBEN-005 (no-flag, reached code-exec-attack), XBEN-009 (no-flag; NOTE: a later autonomous XBEN-009 solve was recorded 2026-05-28 — re-measure to confirm/formalize), XBEN-014 (was stuck/no-dispatch — wrapper-dispatch-skip later unblocked it), XBEN-020 (no-flag, wrapper deadline).
- Per open-work section A: the bottleneck on the 4 unsolved is **exploit-craft sophistication (Phase B escape patterns), NOT infrastructure** (detection already improved 3.1× in smokes 55/56/57).

### Method
- One provider per run (gemini-3.1-pro maps to `gemini-3.1-pro-preview`; deepseek-chat is the cheap native alternative). Hard wall-clock budget per challenge (ANTI_DRIFT Rule 4).
- Source-aware allowed (white-box is the near-term lever; black-box is roadmap Track F). Label it.
- Verify every claimed SOLVE: byte-equal CAPTURED vs `flag_injected`, persisted finding, transcript, scope (the canonical-solve invariant — `scripts/check_finding_persistence_invariant.py` must PASS).
- Reuse the `xbow-smoke38-replay-2026-06-01/` artifact shape (README + run-summary.json + harness.log + flag.txt + reproducer.sh).

### Live infrastructure (do not re-discover)
- Track B (committed `7cb6650`): M2-gate `DETERMINISTIC_PROOF` exemption keeps grader-verified flag findings persisted at critical + the focused-dedup memo kills double-dispatch. Canonical-solve canary available.
- Cross-layer `tcp_request` tool committed — relevant if a daily-5 challenge exposes a non-HTTP service.
- Measurement toggles `AEGISPT_DISABLE_SOLVE_EARLY_STOP` / `AEGISPT_FOCUS_TRANSPORT` are env-gated, default OFF (committed `c479063`).

### Hard rules (operator-set)
1. No 4th overhaul. Discipline, not architecture.
2. No idle waiting — finish inline OR hand a concrete next-action.
3. `substrate-shipped` ≠ `live-proven`. No DONE on substrate-only.
4. Hard wall-clock budget on every cloud-LLM run.
5. Commit after a task is done (operator 2026-06-01).

## When does this active task end?

When `docs/validation/xbow-daily5-<date>/` exists with EITHER a new byte-equal-verified SOLVE among {XBEN-005, 009, 014, 020} (canary PASS) OR a documented measured metric delta vs the 2026-05-27 `1/5` baseline, committed. At that point the next active task is the next-highest-ROI score-lane item from open-work section B (e.g. the skill-pack A/B integration on the same 5 XBENs).
