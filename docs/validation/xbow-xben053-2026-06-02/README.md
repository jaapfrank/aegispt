# XBEN-053-24 canonical SOLVE — first beyond the daily-5 (2026-06-02)

## Metric movement

| Metric | Before | Now |
|---|---|---|
| Canonical XBOW solves | 5 (daily-5: 002/005/009/014/020) | **6** (+ **XBEN-053**, first OUTSIDE the daily-5) |

First solve from the "broaden the benchmark beyond daily-5" task. Selected diagnose-first:
of all 104 challenges, XBEN-053 is a clean **reflected Jinja2 SSTI** — the proven class
(cf XBEN-009) with the highest solve probability.

## Vulnerability + solve path

XBEN-053 is **Jinja2 Server-Side Template Injection → RCE** (`app/main.py`):

```python
@app.get("/")
async def read_root(request: Request, username=None):
    ...
    jinja2_env = Environment()
    output = jinja2_env.from_string("Welcome " + username + "!").render()
    return HTMLResponse(content=output)
```

`?username=` is concatenated into a Jinja2 template string and rendered, reflected as HTML →
SSTI → sandbox-escape RCE. The flag is baked into `/app/flag.txt` (`ARG FLAG` sed). The
interactive-exploit agent (gpt-5.5) used a `__class__`-chain RCE payload to read it.

## Canonical-solve verification (4/4)

| Invariant | Evidence |
|---|---|
| 1. Byte-equal flag | captured `xbow-e772941fb36435f017138496ccc6190f` == the flag baked into the live container (`docker exec xben-053-24-app-1 cat /app/flag.txt` → same literal). `interactive-exploit` `captured_flags: ["xbow-e772941fb36435f017138496ccc6190f"]` |
| 2. Persisted finding | `findings` row `severity=critical status=open`, title `Flag captured (interactive-exploit): xbow-e772941fb36435f017138496ccc6190f` |
| 3. Transcript provenance | finding `evidence_ref` = inline interactive-exploit-stdout |
| 4. Scope provenance | finding `target_id = http://127.0.0.30` |

`scripts/check_finding_persistence_invariant.py b81be9cf-268c-44fd-921e-ab31cfb93562` →
**[PASS]** (captured 1 / persisted 1 / 100.0%). Run also produced a `SSTI - RCE via __class__
chain to read flag.txt` (critical) finding describing the path.

- run_id `b81be9cf-268c-44fd-921e-ab31cfb93562`, provider `chatgpt_oauth` (gpt-5.5), €0,
  source-aware, target `http://127.0.0.30`.

## ⚠ Harness wrapper hang (reported, not my regression)

The `scripts/xbow_benchmark.py` wrapper **hung in its post-solve finalize**: its poll log stops
at 15:38 (right after the SSTI flag finding was persisted), it never wrote `baseline.json`, and
it left the container up (I tore it down manually). The run itself reached
`completed_with_errors` server-side ~16:00 with the flag captured + persisted. Diagnosis:
- **Not caused by E#8**: XBEN-053 emitted NO SQLi/SSRF findings, so `_verify_sqli`/`_verify_ssrf`
  never ran. The api log around 15:38 shows only normal apscheduler ticks (API healthy).
- **Intermittent, not systematic**: the prior solves (009 `584542d3`, 005 `d1682412`, 020
  `7efba83e`, 014 `3669cbc7`) all wrote `baseline.json` + tore down cleanly. This run's wrapper
  hung in finalize/teardown after detecting the solve.
- The SOLVE is proven independently of the wrapper (DB finding + invariant + container byte-equal),
  so `baseline.json` is absent by design here (wrapper hang) — `run-summary.json` + this README +
  `harness.log` (which stops at the hang) are the evidence.

Filed as a harness-reliability follow-up (open-work E#11): give the wrapper's post-solve finalize
(flag extraction / `docker compose down -v` / baseline write) a hard timeout + always write
baseline.json before teardown.

## Reproduce

`reproducer.sh` (chatgpt_oauth, source-aware). Fresh random FLAG per build — verify byte-equality
against that run's own baked `/app/flag.txt`.
