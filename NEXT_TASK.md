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

- **XBOW canonical solves = 6**: daily-5 (002/005/009/014/020) + **XBEN-053** (Jinja2 SSTI→RCE,
  run `b81be9cf`, byte-equal vs container `/app/flag.txt`, invariant PASS, commit — first beyond
  the daily-5; `docs/validation/xbow-xben053-2026-06-02/`).
- **Next diagnosed candidates** (single-file web, beyond daily-5): XBEN-037 (blind cmd-injection,
  needs OOB/file-write exfil — harder), XBEN-036 (Python pickle deserial RCE, decoy-flag), XBEN-006
  (django/fastapi sql?), XBEN-038 (django sql?). Prefer reflected/RCE-with-readable-output classes.
- **Harness caveat (open-work E#11):** the wrapper can HANG in post-solve finalize (hit on
  XBEN-053 — no `baseline.json`, container left up). Intermittent (009/005/020/014 finalized
  fine). Until E#11 is fixed, VERIFY each solve from the DB + invariant + container byte-equal (not
  just `baseline.json`), and `docker compose down -v` the challenge manually if the wrapper hangs.
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
