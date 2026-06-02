# Active Task

> **Read FIRST:** [`ANTI_DRIFT.md`](ANTI_DRIFT.md) (repo root) — 5 hard rules + pre-commit checklist + strenger DONE-definitie.
>
> **Read SECOND:** [`SESSION_PROMPT.md`](SESSION_PROMPT.md) — kickoff discipline voor AegisPT sessies.
>
> **Read THIRD:** [`docs/research/open-work-consolidated-2026-05-27.md`](docs/research/open-work-consolidated-2026-05-27.md) section E#9. Do NOT promote from `TASK_QUEUE.md` (frozen).

## Title

Honest reliability + false-positive + coverage documentation (open-work E#9): write `docs/reliability-and-false-positives.md`.

## Goal

Write `docs/reliability-and-false-positives.md` (NL+EN) — a single honest reference the operator
can cite (and not over-claim from), cross-checked against the code. Cover: (1) the tiered
reliability model — captured-flag/`DETERMINISTIC_PROOF` = hard grader-matchable proof; the
re-prover-confirmed classes (admin_access/stored_xss/info_disclosure/**sqli** after E#8) = high;
everything else = `UNCLASSIFIED`/operator-review; (2) the 3 false-positive mechanisms
(pre-persistence re-prover `finding_verifier.py`, M2 verdict gate `m2_verdict_gate.py`, manual
`false_positive_reason`/`validation_status` fields) AND the remaining `inconclusive→UNCLASSIFIED`
leak for classes without a re-prover yet (SSTI/deserial/SSRF/cmd-injection — see E#8 remaining);
(3) the coverage-honesty caveat — test execution is AI-picker + tool-orchestration driven
(emergent), NOT a systematic WSTG-checklist engine, so coverage is not exhaustive-by-construction;
(4) compliance frameworks (SOC2/ISO27001/PCI/NIS2/DORA/TIBER) are report-time mapping VIEWS, not
certifications; (5) an explicit customer-facing "do NOT claim" list. Acceptance = the doc exists,
is consistent with `finding_verifier.py` strategies + `m2_verdict_gate.py` verdicts +
`methodology_mapping.md`, and is linked from `AegisPT.md` + `docs/methodology_mapping.md`. Commit
score-lane-only.

## Context (state — 2026-06-02)

- Daily-5 is FULLY + CANONICALLY solved 5/5 (002, 014, 009, 005, 020).
- Reliability follow-ups: **E#8 SQLi re-prover DONE** (commit `99f114c`; SSTI/deserial/SSRF/
  cmd-injection re-provers remain), **E#10 any-tool flag-capture DONE** (commit `8fe32fc`).
  This task (E#9) is the documentation capstone.

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

When `docs/reliability-and-false-positives.md` exists, is code-consistent, and is linked from
`AegisPT.md` + `docs/methodology_mapping.md`, committed score-lane-only. Next = the remaining E#8
injection-class re-provers (SSTI/deserial/SSRF/cmd-injection), or broaden the benchmark set.

## Carry-over (deferred, blocked by concurrent codex lane)

XBEN-014/009/005/020 + E#10 + E#8 DONE_LOG.md entries are pending: DONE_LOG.md / CURRENT_STATE.md
remain held by the live Codex UI lane. Content is preserved in the score-lane commit messages +
artifact READMEs; land them once codex releases the file.
