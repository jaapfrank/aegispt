# Active Task

> **Read FIRST:** [`ANTI_DRIFT.md`](ANTI_DRIFT.md) (repo root) — 5 hard rules + pre-commit checklist + strenger DONE-definitie.
>
> **Read SECOND:** [`SESSION_PROMPT.md`](SESSION_PROMPT.md) — kickoff discipline voor AegisPT sessies.
>
> **Read THIRD:** [`docs/research/open-work-consolidated-2026-05-27.md`](docs/research/open-work-consolidated-2026-05-27.md) section E#10. Do NOT promote from `TASK_QUEUE.md` (frozen).

## Title

Flag-capture recognition for ALL tools (open-work E#10): persist a canonical `Flag captured` finding + early-stop + invariant coverage when ANY tool extracts a grader-matchable flag — closes the XBEN-020 canonical gap and makes daily-5 a true canonical 5/5.

## Goal

Make the production loop recognize a flag capture from ANY tool, not just `interactive-exploit`.
Today the canonical-solve machinery (the `Flag captured` finding, run early-stop, and
`check_finding_persistence_invariant.py`) only watches `interactive-exploit.captured_flags`. On
XBEN-020 (run `dde572f4`) `smart-web-probe` extracted the SSRF flag → harness `solved=true`, but
NO `Flag captured` finding persisted, the invariant passed VACUOUSLY (`captured flags: 0`), and
no early-stop fired (full 1582s budget burned). Add a post-task flag-scan (reuse `_FLAG_RE`:
`xbow-…`/`flag{…}`/`aegispt{…}`) over every tool execution's stdout; on a match persist a
canonical `Flag captured` finding (`evidence_ref`→that exec, `target_id`→scope, methodology tag),
trigger early-stop, and extend the invariant to validate captures from any tool. Acceptance =
re-run XBEN-020 → persisted `Flag captured` finding + non-vacuous invariant PASS + early-stop
(run < budget) → XBEN-020 becomes a canonical solve. Commit on the proven delta (ANTI_DRIFT R3).

## Baseline (canonical truth — 2026-06-02)

- **Daily-5 XBOW grader solve = 5/5** (all `solved=true`, byte-equal): XBEN-002, 014, 009, 005, 020.
- **Daily-5 canonical-finding-persisted = 4/5.** The gap is **XBEN-020**: grader-solved via SSRF
  (smart-web-probe captured `xbow-3437878f…`), but the flag is NOT in any persisted finding, the
  invariant is vacuous, and no early-stop fired. Evidence + full write-up:
  `docs/validation/xbow-daily5-020-2026-06-02/`.
  - XBEN-014 (PHP deserial, `496656c`), 009 (Django SSTI, `b523b66`), 005 (JWT-secret, `b3692d4`)
    are clean canonical solves (interactive-exploit capture + invariant PASS).
- Proven lever (3× on 014/009/005): surface the vuln in recon → strong model exploits → canonical
  capture. XBEN-020 shows the OTHER failure mode: capture happened but wasn't canonicalized.

## Method / environment notes

- **Provider:** `chatgpt_oauth` (gpt-5.5) = €0; OAuth re-connected 2026-06-02 (`secrets_refs`≥1).
- **Provider-name footgun guarded** (`ecc2666`): valid names incl. `deepseek-v3` (NOT
  `deepseek-chat`), `gemini-3.1-pro`, `chatgpt_oauth`. Unknown → hard error (no silent claude burn).
- **DB purge discipline:** preserve `secrets_refs` + `instance_settings` (`feedback-db-purge-preserve-secrets`).
- Verify every claimed canonical SOLVE: byte-equal vs `flag_injected`, persisted `Flag captured`
  finding, transcript + scope, **non-vacuous** `check_finding_persistence_invariant.py` PASS;
  audit the individual tool calls.

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

When XBEN-020 re-runs to a CANONICAL solve (persisted `Flag captured` finding + non-vacuous
invariant PASS + early-stop), making daily-5 a true canonical 5/5, committed score-lane-only. At
that point the daily-5 subset is fully + canonically solved → next = re-rank open-work section B
(with daily-5 maxed), e.g. E#8 injection-class FP re-prober, or broaden the benchmark set.

## Carry-over (deferred, blocked by concurrent codex lane)

The XBEN-014 / 009 / 005 / 020 DONE_LOG.md entries are pending: DONE_LOG.md / CURRENT_STATE.md
remain held by the live Codex UI lane. Content is preserved in the score-lane commit messages
+ artifact READMEs; land them once codex releases the file.
