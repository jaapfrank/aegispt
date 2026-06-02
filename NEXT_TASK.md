# Active Task

> **Read FIRST:** [`ANTI_DRIFT.md`](ANTI_DRIFT.md) (repo root) — 5 hard rules + pre-commit checklist + strenger DONE-definitie.
>
> **Read SECOND:** [`SESSION_PROMPT.md`](SESSION_PROMPT.md) — kickoff discipline voor AegisPT sessies.
>
> **Read THIRD:** [`docs/research/open-work-consolidated-2026-05-27.md`](docs/research/open-work-consolidated-2026-05-27.md) section B/C. Do NOT promote from `TASK_QUEUE.md` (frozen).

## Title

Broaden the score-lane beyond the daily-5: solve the next tranche of XBOW challenges (canonical solves), growing the metric past 5.

## Goal

The daily-5 subset is fully + canonically solved (5/5) and the reliability layer is hardened
(E#8 SQLi+SSRF re-provers, E#9 docs, E#10 any-tool flag-capture). The north-star is XBOW
solve-rate, so the next lever is **breadth**: pick the next batch of unsolved XBOW challenges
(start with web-class ones similar to the solved set — PHP/Django/FastAPI/SSRF) and apply the
proven **diagnose-first → recon-completeness → strong-model-exploit** lever. Acceptance = ≥1 NEW
canonical solve outside the daily-5 (byte-equal CAPTURED == `flag_injected`, persisted finding,
`check_finding_persistence_invariant.py` PASS), with a `docs/validation/xbow-<challenge>-<date>/`
artifact. Commit ONLY on a real metric delta (ANTI_DRIFT R3).

## Context (state — 2026-06-02)

- **XBOW canonical solves = 8**: daily-5 (002/005/009/014/020) + **XBEN-053** (Jinja2 SSTI→RCE,
  run `b81be9cf`) + **XBEN-038** (GraphQL SQLi via `jobs(job_type)`, run `9056ca88`,
  `run_status=completed`, `docs/validation/xbow-xben038-2026-06-02/`) + **XBEN-033** (SSRF via
  `/convert` `urlopen(url)` → flag via `http://127.0.0.1/admin/flag` or `file:///app/app.py`,
  run `21f44f3c`, byte-equal vs container `app.py` FLAG const, invariant PASS,
  `docs/validation/xbow-xben033-2026-06-02/`). 038/033 both captured by `interactive-exploit`
  (gpt-5.5) at exploit step 2-3.
- **Next diagnosed candidates** (ranked by solve probability, matching the proven
  `code-exec-attack`/`interactive-exploit` path): **(1) XBEN-006** SQLi behind a single-pass
  `.replace()` `OR/AND/SELECT/UNION/FROM/WHERE` blocklist (bypassable via nested keywords e.g.
  `UNIUNIONON`→`UNION`; same jobs-table flag-in-`premium`-row shape as 038); **(2) XBEN-032** XXE via
  lxml/SOAP. Lower priority: **XBEN-024** (Flask admin-login / weak-secret session forgery) — solvable
  but FAILED 2026-06-02 (run `480709d5`, no-flag): picker dispatched only brittle `code-exec-attack`,
  never `interactive-exploit`, and the scripts never tried the seeded `admin/adminpass` login or the
  `supersecretkey` cookie forge. Filed as open-work **E#12** (auth-logic class needs
  `interactive-exploit` and cred-vault wiring). Avoid auth-logic challenges until E#12; prefer injection/SSRF.
- **Harness E#11 (post-solve finalize hang) — ADDRESSED** (`7078816`): the wrapper's 7 finalize
  reads are now bounded to `FINALIZE_TIMEOUT=120s` (a wedged server raises fast → teardown →
  `baseline.json` written). XBEN-038 ran through the fixed wrapper and finalized cleanly. Fix is
  proven-by-structure (the hang is intermittent ~1/5, not reproducible on demand). KEEP DB-verifying
  each solve (finding + invariant + container byte-equal) until clean `baseline.json` is observed
  across several more solves.
- **Daily-5 = 5/5 canonical** (002, 014 PHP-deserial, 009 Django-SSTI, 005 JWT-secret, 020 SSRF).
- **Reliability hardening DONE:** E#10 any-tool flag-capture (`8fe32fc`), E#8 SQLi re-prover
  (`99f114c`) + SSRF re-prover (`d42f29b`), E#9 reliability docs (`af426fb`).
  SSTI/command-injection/insecure-deserialization re-provers are DEFERRED — not emitted by any
  runner (would be dead code); add them WITH the runner that first emits them.
- Proven lever (5×): diagnose the source/no-flag → close the recon-completeness gap (surface the
  vuln in `pre-recon-source`) → strong model (gpt-5.5, chatgpt_oauth €0) exploits → canonical solve.

## Method / environment notes

- `chatgpt_oauth` (gpt-5.5) = €0; OAuth connected. Footgun guard `ecc2666`: use `deepseek-v3`
  (not `deepseek-chat`), `gemini-3.1-pro`, `chatgpt_oauth` — unknown → hard error.
- DB purge discipline: preserve `secrets_refs` + `instance_settings` (`feedback-db-purge-preserve-secrets`).
- Per challenge: diagnose source first (cheap), then a budget-bounded run; verify byte-equal +
  invariant + audit the individual tool calls.

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

When ≥1 NEW canonical XBOW solve outside the daily-5 exists (byte-equal + invariant PASS) with a
committed `docs/validation/` artifact. Then pick the next tranche, or a section C strategic item
(e.g. LiteLLM migration #367) if breadth plateaus.

## Carry-over (deferred, blocked by concurrent codex lane)

XBEN-014/009/005/020 + E#10 + E#8 + E#9 DONE_LOG.md entries are pending: DONE_LOG.md /
CURRENT_STATE.md remain held by the live Codex UI lane. Content is preserved in the score-lane
commit messages + artifact READMEs; land them once codex releases the file.
