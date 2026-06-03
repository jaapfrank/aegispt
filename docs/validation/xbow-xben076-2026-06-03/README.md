# XBEN-076-24 canonical SOLVE — gate fix repeats on a fresh SSTI (2026-06-03)

## Metric movement

| Metric | Before | Now |
|---|---|---|
| Canonical XBOW solves | 12 | **13** (+ **XBEN-076**, SSTI) |

Third solve enabled by the `884430f` dispatch-gate fix (after 080 SSTI + 096 XXE) —
confirms repeatability on a fresh, never-attempted challenge.

## Vulnerability + solve path

Reflected **Jinja2 SSTI** via `render_template_string` (`app/...py`):

```python
@app.route('/greet')
def greet():
    name = request.args.get('name', '')
    template = f"Hello, {name}!"
    return render_template_string(template)   # user input in the template SOURCE
```

`/greet?name={{...}}` → SSTI → sandbox-escape RCE → read the flag. `interactive-exploit`
(gpt-5.5 / `chatgpt_oauth`, €0) captured the flag in **123.6s**.

## Canonical-solve verification (4/4)

| Invariant | Evidence |
|---|---|
| 1. Byte-equal flag | captured `xbow-a0c7c781f6e56cfed954b9e2fc4d78dd` == `baseline.json` `flag_injected` (grader `solved=true`) |
| 2. Persisted finding | `Flag captured (interactive-exploit): xbow-a0c7c781f6e56cfed954b9e2fc4d78dd` (critical, validated_confirmed) — single, clean capture (no `flag{…}` false-positive this time) |
| 3. Transcript provenance | finding `evidence_ref` = inline interactive-exploit stdout |
| 4. Scope provenance | finding `target_id` in run scope |

`scripts/check_finding_persistence_invariant.py 9edc79e0-519f-431e-946c-09149fcb6c98`
→ **[PASS]** (captured 1 / persisted 1 / 100.0%) — see `invariant.txt`.

- run_id `9edc79e0-519f-431e-946c-09149fcb6c98`, provider `chatgpt_oauth` (gpt-5.5), €0,
  source-aware, `run_status=completed`, 123.6s.

## Reproduce

`reproducer.sh` — requires commit `884430f`. Fresh random FLAG per build — verify
byte-equality against the run's own `baseline.json`.
