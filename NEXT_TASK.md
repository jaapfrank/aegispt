# Active Task

> **Read FIRST:** [`ANTI_DRIFT.md`](ANTI_DRIFT.md) (repo root) — 5 hard rules + pre-commit checklist + strenger DONE-definitie.
>
> **Read SECOND:** [`SESSION_PROMPT.md`](SESSION_PROMPT.md) — kickoff discipline voor AegisPT sessies.
>
> **Read THIRD:** [`docs/research/open-work-consolidated-2026-05-27.md`](docs/research/open-work-consolidated-2026-05-27.md) section E#8. Do NOT promote from `TASK_QUEUE.md` (frozen).

## Title

Injection-class verification re-prober strategies (open-work E#8): make false-positive SQLi/SSTI/deserial/SSRF findings conclusively droppable instead of leaking as `UNCLASSIFIED`.

## Goal

`finding_verifier._select_strategy` only re-proves `admin_access` / `stored_xss` /
`info_disclosure` (+ the deterministic flag-proof exemption); every other critical/high finding
returns `inconclusive` → the M2 verdict gate keeps it as `UNCLASSIFIED`, never auto-dropped. So
false positives leak to the operator — observed live: `smart-web-probe` emitted false-positive
critical "SQL Injection" on XBEN-014 AND XBEN-005 (apps with no SQL), kept as `UNCLASSIFIED` and
spawning dead `sqlmap` dispatches. Add bounded, scope-allowlist-gated re-prober strategies for the
injection classes — SQLi (injected vs control response diff), SSTI (benign `{{7*7}}`→`49`),
insecure-deserialization, SSRF, command-injection — so the verifier returns a CONCLUSIVE
`confirmed`/`failed`, letting the gate drop genuine false positives (failed + no replay). Also
lower `smart-web-probe`'s over-eager critical SQLi emission. Acceptance = on a no-SQL target a
smart-web-probe "SQL Injection" finding is conclusively `FALSE_POSITIVE` and dropped (cite run +
`PROOF_EXEC_M2_VERDICT_GATE` marker); no regression in `test_m2_verdict_gate.py` /
`test_finding_verifier_*`. Commit on the proven delta (ANTI_DRIFT R3).

## Baseline (canonical truth — 2026-06-02)

- **Daily-5 is FULLY + CANONICALLY solved: 5/5** (grader AND canonical):
  XBEN-002, 014 (PHP deserial), 009 (Django SSTI), 005 (JWT-secret), 020 (SSRF).
  - XBEN-020 became canonical via the E#10 fix (any-tool flag-capture recognition): run
    `7efba83e`, persisted `Flag captured (smart-web-probe)` finding + non-vacuous invariant PASS +
    early-stop. Evidence: `docs/validation/xbow-e10-anytool-flagcapture-2026-06-02/`.
- E#10 DONE. Remaining reliability follow-ups: **E#8** (this task, injection-class FP re-prober),
  **E#9** (honest reliability/FP docs).

## Method / environment notes

- `chatgpt_oauth` (gpt-5.5) = €0; OAuth re-connected 2026-06-02. Footgun guard `ecc2666`:
  unknown `--llm-provider` → hard error (use `deepseek-v3` not `deepseek-chat`, `gemini-3.1-pro`).
- DB purge discipline: preserve `secrets_refs` + `instance_settings` (`feedback-db-purge-preserve-secrets`).
- Verify FALSE_POSITIVE drops via the `PROOF_EXEC_M2_VERDICT_GATE` log marker; audit tool calls.

## Hard rules (operator-set)

1. No 4th overhaul. Discipline, not architecture.
2. No idle waiting — finish inline OR hand a concrete next-action.
3. `substrate-shipped` ≠ `live-proven`. No DONE on substrate-only.
4. Hard wall-clock budget on every cloud-LLM run.
5. Commit after a task is done.
6. Lane separation: do NOT touch the concurrent Codex UI/reporting lane's files
   (`ui-v2/*`, `CURRENT_STATE.md`/`DECISIONS.md`/`DONE_LOG.md` while it holds them,
   `docs/validation/codex-ui-reporting-*`, `api/app/services/reports.py`/`report_center.py`).

## When does this active task end?

When a no-SQL target's smart-web-probe "SQL Injection" finding is conclusively classified
`FALSE_POSITIVE` and dropped by the M2 gate (live, cite marker), with the new injection re-prober
strategies tested, committed score-lane-only. Next = E#9 (reliability docs), or broaden the
benchmark set beyond the daily-5 (now maxed).

## Carry-over (deferred, blocked by concurrent codex lane)

XBEN-014/009/005/020 + E#10 DONE_LOG.md entries are pending: DONE_LOG.md / CURRENT_STATE.md remain
held by the live Codex UI lane. Content is preserved in the score-lane commit messages + artifact
READMEs; land them once codex releases the file.
