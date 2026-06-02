# Active Task

> **Read FIRST:** [`ANTI_DRIFT.md`](ANTI_DRIFT.md) (repo root) — 5 hard rules + pre-commit checklist + strenger DONE-definitie.
>
> **Read SECOND:** [`SESSION_PROMPT.md`](SESSION_PROMPT.md) — kickoff discipline voor AegisPT sessies.
>
> **Read THIRD:** [`docs/research/open-work-consolidated-2026-05-27.md`](docs/research/open-work-consolidated-2026-05-27.md) section E#8 (remaining classes). Do NOT promote from `TASK_QUEUE.md` (frozen).

## Title

Injection-class re-prover strategies — remaining classes (continued open-work E#8): add SSTI / insecure-deserialization / SSRF / command-injection re-provers to `finding_verifier.py`.

## Goal

E#8's SQLi re-prover (`99f114c`) is DONE; the other injection classes still fall to
`inconclusive` → `UNCLASSIFIED` → kept (false positives leak). Add bounded, scope-gated,
independent re-prover strategies for: **SSTI** (benign `{{7*7}}`→`49` differential vs a control
literal — clean + deterministic), **SSRF** (re-issue the URL param against a known-internal vs an
out-of-scope/blocked control and compare), **insecure-deserialization** (hard to re-prove
generically — likely `inconclusive`-by-default unless a replay recipe exists; document why),
**command-injection** (benign `;echo <nonce>` / `$(echo <nonce>)` reflection of the nonce).
Mirror `_verify_sqli`'s conservative contract: `confirmed` on a clear signal, `failed` ONLY when
demonstrably inert, else `inconclusive` (never drop on doubt). Wire each into `_select_strategy`
+ `verify_finding`. Acceptance = per class, a unit test (failed-on-inert / confirmed-on-signal /
inconclusive-on-ambiguous) + at least one live FALSE_POSITIVE or confirmed observation where a
real target produces that class (e.g. SSTI on XBEN-009). Commit score-lane-only.

## Context (state — 2026-06-02)

- Daily-5 is FULLY + CANONICALLY solved 5/5 (002, 014, 009, 005, 020).
- Reliability hardening DONE: **E#10** any-tool flag-capture (`8fe32fc`), **E#8 SQLi** re-prover
  (`99f114c`), **E#9** reliability docs (`af426fb`, `docs/reliability-and-false-positives.md`).
  This task is the REMAINING E#8 injection classes.
- Pattern to mirror: `api/app/services/finding_verifier.py` `_verify_sqli` + `_select_strategy`
  + the `verify_finding` dispatch; tests `api/tests/test_sqli_reprover.py`.

## Hard rules (operator-set)

1. No 4th overhaul. Discipline, not architecture.
2. No idle waiting — finish inline OR hand a concrete next-action.
3. `substrate-shipped` ≠ `live-proven`. No DONE on substrate-only (N/A for a docs task —
   acceptance is the doc matching the code).
4. Hard wall-clock budget on every cloud-LLM run.
5. Commit after a task is done.
6. Lane separation: do NOT touch the concurrent Codex UI/reporting lane's files
   (`ui-v2/*`, `CURRENT_STATE.md`/`DECISIONS.md`/`DONE_LOG.md` while it holds them,
   `docs/validation/codex-ui-reporting-*`, `api/app/services/reports.py`/`report_center.py`).

## When does this active task end?

When the SSTI/SSRF/command-injection re-prover strategies exist (deserial documented as
inconclusive-by-default), each unit-tested + at least one live confirmed/FALSE_POSITIVE
observation, committed score-lane-only. Next = broaden the benchmark set beyond the daily-5
(now fully + canonically solved), or pick the next open-work section B/C item.

## Carry-over (deferred, blocked by concurrent codex lane)

XBEN-014/009/005/020 + E#10 + E#8 DONE_LOG.md entries are pending: DONE_LOG.md / CURRENT_STATE.md
remain held by the live Codex UI lane. Content is preserved in the score-lane commit messages +
artifact READMEs; land them once codex releases the file.
