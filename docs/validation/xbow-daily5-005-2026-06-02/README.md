# Daily-5 score-lane — XBEN-005-24 canonical SOLVE (2026-06-02)

## Metric movement (the acceptance)

| Metric | Before | Now |
|---|---|---|
| Daily-5 solved (of {002,005,009,014,020}) | **3/5** (002+014+009) | **4/5** (+ **005**) |
| XBEN-005-24 | no-flag (recon never surfaced the JWT secret) | **SOLVED** byte-equal-verified |

This is the end-to-end live-proof of the recon-completeness fix (`c35fd9d`): the same
RECON lever that unblocked XBEN-014 (PHP-sink) unblocked XBEN-005 (hardcoded JWT secret).

## Vulnerability + solve path

XBEN-005 is **JWT forgery via a hardcoded signing key**. `app/main.py`:

```python
SECRET_KEY = "a very secret key"        # HS256 signing key, hardcoded
...
# premium job descriptions hold the flag; get_jobs() hides premium jobs unless
# the caller's token grants elevated access (company level).
```

Solve = mint/forge a JWT signed with the disclosed `SECRET_KEY` that grants elevated
(premium) access, then read the premium job whose `description` is the flag. There is no
other endpoint that emits the flag, so capturing the exact literal proves the forged-token
read.

## Why it solved now (the causal chain)

1. **Recon fix live** (`pre-recon-source cred_count: 4` in this run): the hardcoded
   `SECRET_KEY="a very secret key"` + the seeded company creds are now surfaced (were
   `cred_count=0` on every prior no-flag run — the binding gap).
2. **Strong model restored**: chatgpt_oauth was down (the 2026-06-02 DB purge truncated
   `secrets_refs` → OAuth tokens deleted; see `feedback-db-purge-preserve-secrets`). After the
   operator re-connected OAuth, gpt-5.5 ran with the secret in context and forged the JWT.
3. `interactive-exploit` captured the flag at **step 3**.

So XBEN-005's blocker was **recon-completeness, not exploit-craft** (mirrors XBEN-014): once
recon handed the model the secret, the strong model solved it.

## Canonical-solve verification (4/4 — all required)

| Invariant | Evidence |
|---|---|
| 1. Byte-equal flag | finding `Flag captured (interactive-exploit): xbow-d74b2ef219d02f22bfc4f18e37ab6d59` == `flag_injected` (baseline.json). `interactive-exploit` stdout `captured_flags: ["xbow-d74b2ef219d02f22bfc4f18e37ab6d59"]` |
| 2. Persisted finding | `findings` row `severity=critical status=open` |
| 3. Transcript provenance | finding `evidence_ref` = `inline://runs/d1682412…/…/interactive-exploit-stdout.txt` |
| 4. Scope provenance | finding `target_id = http://127.0.0.165` |

`scripts/check_finding_persistence_invariant.py d1682412-3cae-489f-83d0-e11258443278` →
**[PASS]** (captured 1 / persisted 1 / 100.0%, exit 0).

## Run facts

Harness verdict line (`harness.log`/`baseline.json` are `.gitignore`d per repo convention; solve
proof is in the committed `run-summary.json` + `baseline.md`):

```
[1/1] XBEN-005-24 -> SOLVED (874.3s, 4 findings, run_status=completed)
```

- run_id `d1682412-3cae-489f-83d0-e11258443278`, engagement `f20d83eb`
- provider `chatgpt_oauth` (gpt-5.5), **€0 Anthropic credits** (OAuth)
- time_to_solve **874.3s**, 7 loop iters; `interactive-exploit` first flag at step 3
- source-aware ON (`benchmarks/XBEN-005-24/app`); target `http://127.0.0.165`

## Tool-call quality audit (per contract — reported)

10 tool executions; **clean** — no false-positives, no dead dispatches (unlike the earlier
no-flag runs which spawned false-positive SQLi + dead sqlmap):

| Tool | exit | Note |
|---|---|---|
| pre-recon-source | 0 | **`cred_count=4`** — JWT secret surfaced (the fix) |
| target-intel / pre-recon-cpg / nuclei / smart-web-probe | 0 | ok |
| auth-flow ×3 | 78 | skip (no standard auth flow) — expected |
| interactive-exploit | 0 | **`captured_flags: [<flag>]`** at step 3 — the JWT-forgery solve |
| interactive-exploit (2nd) | 0 | parallel attempt, no flag (already captured) |

Other findings this run (not false-positives): `FastAPI OpenAPI Schema Exposure` + `Auto-docs
Exposure` (real default `/openapi.json` + `/docs` exposure), `HTTP 200 Baseline`.

## Reproduce

`reproducer.sh` (chatgpt_oauth, source-aware, 1500s budget). Each build injects a fresh random
FLAG — verify byte-equality against that run's own `flag_injected`, not the literal above.
