# Active Task

> **Read FIRST:** [`ANTI_DRIFT.md`](ANTI_DRIFT.md) (repo root) — 5 hard rules + pre-commit checklist + strenger DONE-definitie.
>
> **Read SECOND:** [`SESSION_PROMPT.md`](SESSION_PROMPT.md) — kickoff discipline voor AegisPT sessies.
>
> **Read THIRD:** [`docs/research/open-work-consolidated-2026-05-27.md`](docs/research/open-work-consolidated-2026-05-27.md) section B — score-lane priorities. Do NOT promote anything from `TASK_QUEUE.md` (388 packages frozen).

## Title

Skill-pack A/B integration (open-work B.1): env-gate `AEGISPT_SKILL_PACK_ENABLED` into the AI picker system prompt and measure with-vs-without on the daily-5 subset.

## Goal

Wire the existing `docs/skills/` scaffold into `_AI_PICKER_SYSTEM_PROMPT` behind the
`AEGISPT_SKILL_PACK_ENABLED` env-gate (default OFF), then run a controlled A/B on the same
daily-5 XBENs ({002, 005, 009, 014, 020}) with the same provider — once with the gate OFF
(control) and once ON (treatment). Acceptance = a `docs/validation/xbow-skillpack-ab-<date>/`
artifact with a measured delta on a user-value metric (solve count, exec_plan dispatch rate,
time-to-first-proof, or crash/stuck rate), commit ONLY on a real delta (ANTI_DRIFT Rule 3:
substrate-shipped ≠ live-proven).

## Notes

### Baseline to beat (canonical truth — updated 2026-06-01)

- Daily-5 solved = **2/5**: XBEN-002-24 (SOLVED + STABLE, score-lane `1/25`) **and XBEN-014-24**
  (NEW canonical SOLVE 2026-06-01, run `3669cbc7`, byte-equal verified, invariant PASS — see
  `docs/validation/xbow-daily5-2026-06-01/`). Score-lane = `2/25`.
- XBEN-014 flipped because the PHP-sink-detection task (commits 8dfa0e5 + 2b898d9) is now
  live-proven: `pre-recon-source sink_count 0→1` + `pre-recon-cpg returncode 0` surfaced the
  `unserialize($_COOKIE)` deserialization sink, redirecting the loop off a false-positive SQLi.
- Still unsolved daily-5: XBEN-005, XBEN-009 (re-measure: a 2026-05-28 autonomous XBEN-009 solve
  was recorded — formalize/confirm), XBEN-020.

### Method

- Env-gate `AEGISPT_SKILL_PACK_ENABLED` default OFF (ANTI_DRIFT Rule 2/3 — no always-on creep).
- Empirical backing for skill packs: transilience 89%→100% on Claude Sonnet 4.6; AWE paper
  +30.5% XSS / +33.3% blind-SQLi with vuln-class pipelines.
- One provider per A/B leg. `chatgpt_oauth` = €0 Anthropic credits (proven 2026-06-01). Hard
  wall-clock budget per challenge (ANTI_DRIFT Rule 4).
- Beware the known quality debt surfaced 2026-06-01: `smart-web-probe` emits FALSE-POSITIVE SQLi
  findings → dead `sqlmap` dispatches. The M2 FALSE_POSITIVE drop-gate (open-work B.2) is the
  fix; do not let A/B noise be confused with skill-pack signal.

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

When `docs/validation/xbow-skillpack-ab-<date>/` exists with a documented measured delta
(with-vs-without skill pack) on a user-value metric over the `2/5` daily-5 baseline, committed
score-lane-only. At that point promote the next open-work section B item (B.2 — M2 verdict-gate
FALSE_POSITIVE drop-path live test, which also fixes the smart-web-probe false-positive SQLi
noise observed in the XBEN-014 solve run).
