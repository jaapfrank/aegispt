# Active Task

> **Read FIRST:** [`ANTI_DRIFT.md`](ANTI_DRIFT.md) (repo root) — 5 hard rules + pre-commit checklist + strenger DONE-definitie.
>
> **Read SECOND:** [`SESSION_PROMPT.md`](SESSION_PROMPT.md) — kickoff discipline voor AegisPT sessies.
>
> **Read THIRD:** [`docs/research/open-work-consolidated-2026-05-27.md`](docs/research/open-work-consolidated-2026-05-27.md) section B. Do NOT promote anything from `TASK_QUEUE.md` (388 packages frozen).

## Title

Daily-5 score-lane: solve XBEN-020-24 (the LAST unsolved daily-5) — daily-5 4/5 → 5/5, byte-equal-verified, committed on metric delta.

## Goal

Solve XBEN-020-24 via the proven recon→exploit lever. **Diagnose first** (read the challenge
source + the prior no-flag run's tool-call trace) to find the binding gap before spending a run —
both XBEN-014 (PHP-sink) and XBEN-005 (hardcoded JWT secret) turned out to be RECON-completeness
gaps, not exploit-craft. Acceptance = `docs/validation/xbow-daily5-020-<date>/` with byte-equal
CAPTURED == `flag_injected`, persisted critical finding, transcript + scope provenance,
`check_finding_persistence_invariant.py` PASS. Commit ONLY on the metric delta (ANTI_DRIFT Rule 3).

## Baseline (canonical truth — 2026-06-02)

- Daily-5 solved = **4/5**:
  - XBEN-002-24 (stable)
  - XBEN-014-24 — PHP insecure deserialization (`docs/validation/xbow-daily5-2026-06-01/`)
  - XBEN-009-24 — Django SSTI (`docs/validation/xbow-daily5-009-2026-06-01/`)
  - XBEN-005-24 — JWT forgery w/ hardcoded `SECRET_KEY` (`docs/validation/xbow-daily5-005-2026-06-02/`, run `d1682412`)
- Remaining unsolved: **XBEN-020-24** (no-flag, "wrapper deadline" per the 2026-05-27 baseline).
- Proven lever (3×): surface the vuln in recon (`pre-recon-source`) → the strong model exploits it.
  XBEN-005 confirmed it again: `cred_count 0→4` (commit `c35fd9d`) + gpt-5.5 → SOLVE.

## Method / environment notes

- **Provider:** `chatgpt_oauth` (gpt-5.5) = €0 Anthropic credits, the proven solver. OAuth was
  re-connected 2026-06-02 (`secrets_refs=1`) after the DB purge wiped it.
- **Provider-name footgun is now guarded** (commit `ecc2666`): the harness rejects an unknown
  `--llm-provider` instead of silently using claude-opus-4-8. Valid names incl. `deepseek-v3`
  (NOT `deepseek-chat`), `gemini-3.1-pro`, `chatgpt_oauth`, `gpt-5.5`. Keys for deepseek/gemini/
  xai/anthropic are in `~/.aegispt-secrets`.
- **DB purge discipline:** a full purge truncates `secrets_refs` (OAuth tokens) + breaks
  chatgpt_oauth. Preserve `secrets_refs` + `instance_settings` on any future purge
  (`feedback-db-purge-preserve-secrets`).
- Verify every claimed SOLVE: byte-equal vs `flag_injected`, persisted finding, transcript, scope;
  audit the individual tool calls (not just solve-status).

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

When `docs/validation/xbow-daily5-020-<date>/` exists with a byte-equal-verified XBEN-020 SOLVE
(invariant PASS), daily-5 at **5/5**, committed score-lane-only. At 5/5 the daily-5 subset is
fully solved → next active task = the next-highest-ROI score-lane item from open-work section B
(re-rank with daily-5 maxed), or broaden the benchmark set.

## Carry-over (deferred, blocked by concurrent codex lane)

The XBEN-014 / 009 / 005 DONE_LOG.md entries are pending: DONE_LOG.md / CURRENT_STATE.md remain
held by the live Codex UI lane. Content is preserved in the score-lane commit messages
(`496656c`, `b523b66`, this commit) + the artifact READMEs; land them once codex releases the file.
