# E#8 — SQL-injection re-prover drops smart-web-probe false positives (2026-06-02)

## What this fixes

The cross-runner verifier (`finding_verifier.py`) only had re-prove strategies for
`admin_access` / `stored_xss` / `info_disclosure` (+ the deterministic flag-proof exemption).
Every other critical/high finding returned `inconclusive` → the M2 verdict gate kept it as
`UNCLASSIFIED` (never auto-dropped). So `smart-web-probe`'s **false-positive critical "SQL
Injection"** findings on dead login forms with no backend SQL (XBEN-014/005) leaked to the
operator and spawned dead `sqlmap` dispatches.

## The fix (E#8)

`_verify_sqli` — an independent, bounded (≤4 requests, no loops), scope-gated SQLi re-prover:

- **`confirmed`** — a SQL-engine error signature appears on a `'` injection, OR a classic
  auth-bypass payload (`admin' OR '1'='1' --`) produces a success-vs-failure differential vs a
  benign control on the page's **real form fields** (extracted from the HTML, not guessed).
- **`failed`** — ONLY when the injection is *demonstrably inert*: no SQL error AND the
  injection-payload response is materially identical (reflection-normalised) to the control →
  the input is not processed in a SQL context.
- **`inconclusive`** — anything ambiguous (possible blind/2nd-order, reflection without a clear
  signal, no usable form) → KEEP for review. Never drops on doubt.

Wired into `_select_strategy` (`"sql injection"`/`sqli` in title/methodology → `"sqli"`) and the
`verify_finding` dispatch. The M2 gate then drops a `failed` finding with no replay recipe as
`FALSE_POSITIVE`.

## Live-proof — XBEN-014 re-run (run `208e2530`, gpt-5.5, €0)

XBEN-014 is a PHP deserialization challenge with a **dead login form (no backend SQL)**.
smart-web-probe emitted 3 false-positive "SQL Injection" findings; with E#8 live, each was
re-proved `failed` and dropped by the gate (`gate-markers.txt`):

```
PROOF_EXEC_M2_VERDICT_GATE … finding=SQL Injection - Classic Auth Bypass    verdict=FALSE_POSITIVE drop=True gate_on=True
PROOF_EXEC_M2_VERDICT_GATE … finding=SQL Injection - Boolean Blind (admin…) verdict=FALSE_POSITIVE drop=True gate_on=True
PROOF_EXEC_M2_VERDICT_GATE … finding=SQL Injection - Password Field Bypass  verdict=FALSE_POSITIVE drop=True gate_on=True
```

| | Before E#8 | After E#8 (run `208e2530`) |
|---|---|---|
| smart-web-probe SQLi verdict | `inconclusive` (no strategy) | `failed` (`_verify_sqli`, injection inert) |
| M2 gate | `UNCLASSIFIED` (kept, critical) | `FALSE_POSITIVE drop=True` |
| SQLi findings in persisted findings | present (3, critical) | **absent (0)** — dropped |

Persisted findings for the run: only `Default Credentials` (medium) + `HTTP 200 Baseline` (info)
— **zero** SQL-Injection findings.

## Validation

- 5 unit tests `api/tests/test_sqli_reprover.py` (failed-on-inert, confirmed-on-error,
  confirmed-on-bypass-differential, inconclusive-on-ambiguous, strategy-selection); 48-test
  `test_finding_verifier.py` + `test_m2_verdict_gate.py` regression green; ruff + compileall clean.
- Conservative by design: `failed` (→ droppable) only on a demonstrably-inert injection; real
  error-based / auth-bypass SQLi is `confirmed`; ambiguous stays `inconclusive` (kept).

## Remaining (continued E#8 scope)

SSTI / insecure-deserialization / SSRF / command-injection re-prover strategies are NOT yet
added — those classes still fall to `inconclusive`. Filed as continued work; this commit lands
the SQLi re-prover (the live-evidenced false-positive class).
