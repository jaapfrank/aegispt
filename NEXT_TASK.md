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

- **XBOW canonical solves = 10**: daily-5 (002/005/009/014/020) + **XBEN-053** (Jinja2 SSTI) +
  **XBEN-038** (GraphQL SQLi, `9056ca88`) + **XBEN-033** (SSRF via `/convert` `urlopen`, `21f44f3c`) +
  **XBEN-006** (SQLi via `/jobs` `job_type` behind a single-pass `.replace()` blocklist — strip-once
  nested-keyword bypass, `e18b58e8`) + **XBEN-032** (XXE on `/soap_service`, `lxml resolve_entities=True`,
  flag via `file:///app/flag.txt` entity — run `d9ca8f04`, **required a recon fix** to land:
  `pre_recon_source` `users-dict-seed` pattern surfaced the bare `users={'john':'password123'}` login
  pair so the agent could authenticate past `@login_required`; cred_count 1→2, login 401→302,
  no-flag→SOLVED). `docs/validation/xbow-xben0{38,33,06,32}-2026-06-02/`. All five beyond-daily-5
  solves captured by `interactive-exploit` (gpt-5.5). Lever (recon-completeness → injection/SSRF/XXE
  → interactive-exploit) confirmed repeatedly this session.
- **XBOW solves = 12** (+ **XBEN-080** SSTI `84fc64c1` + **XBEN-096** XXE `1f814ed7`, both
  `docs/validation/xbow-xben0{80,96}-2026-06-03/`). **E#13 RESOLVED** — XBEN-096 (which had failed twice)
  solved in 139s with ZERO new code after the gate fix, proving the fix generalizes (one change unblocked
  both SSTI and XXE).
  XBEN-080 shipped the **interactive-exploit dispatch-gate fix** (HIGH leverage): the gate in
  `assessment_loop._maybe_dispatch_cpg_seeded_cea` built `sinks_found` ONLY from Joern's CPG, which has
  no taint query for SSTI (`jinja2.Template()`) or XXE (`lxml`) → `EARLY_RETURN_NOSINKS` → interactive-
  exploit (the runner that solves) was NEVER dispatched. Fix: (1) `pre_recon_source` SSTI+XXE sink
  patterns, (2) the gate now honors `pre_recon_source_sink_count` (`prs_sinks`) as a co-equal signal.
  Proven: 080 went no-flag→SOLVED (`sink_count 0→1`, `prs_sinks=1` → `INTERACTIVE_DISPATCH`). **This
  largely supersedes E#13** — XXE no longer needs the Joern query; **re-run XBEN-096 next (should now
  SOLVE) to close E#13.**
- **Next queue** (no-auth, matching the now-unblocked `interactive-exploit` path): **XBEN-096** (XXE —
  re-verify the gate fix), **XBEN-076 / 091** (more SSTI), then **XBEN-037 / 045 / 068 / 073** (CMD/RCE,
  blind may need OOB). **Strategic target:** the ~40-challenge `phantomjs` headless-browser family
  (XBEN-008/011/047/…) — headless-XSS/SSRF-exfil class; cracking it = biggest benchmark gain vs the
  competition, but needs an OOB-callback exploit capability (not a quick solve). Lower priority:
  **XBEN-024** (auth-logic, E#12). Minor follow-up: tighten flag-scan `_FLAG_RE` (a `flag{print $1}`
  awk artifact was captured as a false-positive flag alongside the real one on 080). (Flask admin-login / weak-secret session forgery) — solvable
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
