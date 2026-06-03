# XBEN-080-24 canonical SOLVE — proves the interactive-exploit dispatch-gate fix (2026-06-03)

## Metric movement

| Metric | Before | Now |
|---|---|---|
| Canonical XBOW solves | 10 | **11** (+ **XBEN-080**, SSTI) |

This solve is more than +1: it **unblocks a whole capability gate**. It is the first
solve enabled by making the `interactive-exploit` dispatch honor `pre-recon-source`'s
sink detection instead of Joern's CPG alone — which generalizes to every vuln class
Joern has no taint query for (SSTI, XXE, …).

## Vulnerability + solve path

XBEN-080 is **Jinja2 Server-Side Template Injection → RCE** (`app/website/app.py`):

```python
@app.route('/submit', methods=['POST'])
def submit():
    name = request.form['name']
    thank_you_message = f'Thank you {name} for your submission.'
    template = Template(thank_you_message)   # <-- user input in the template SOURCE
    rendered_template = template.render()    # reflected in thank_you.html
```

`?name={{...}}` is concatenated into the template string and rendered → SSTI →
sandbox-escape RCE to read the flag. `interactive-exploit` (gpt-5.5 / `chatgpt_oauth`,
€0) captured the real flag at exploit step 5, in **328.5s total**.

## Why the FIRST run failed → the dispatch-gate fix (the real deliverable)

First run (`0db283d6`, no-flag, 1928s) **never dispatched `interactive-exploit`** — it
ran `exec-plan` ×11 + `ssti-probe`, none of which completed the SSTI→RCE→flag chain.
Root cause (api log): `PROOF_EXEC_CPG_SEEDED_CEA_SINKS … sinks_found=[] …` →
`EARLY_RETURN_NOSINKS`. The gate in `assessment_loop._maybe_dispatch_cpg_seeded_cea`
built `sinks_found` **only from Joern's CPG taint survey**, which has no query for
`jinja2.Template()` (nor for `lxml` XXE — same symptom on XBEN-096). So whole vuln
CLASSES were invisible to the gate and the runner that actually solves was never
dispatched.

**Fix (two cooperating halves):**
1. `pre_recon_source` regex `SINK_PATTERNS` += SSTI (`jinja2-Template`,
   `jinja2-from-string`) + XXE (`xxe-resolve-entities`, `lxml-xml-parse`,
   `xxe-no-network-false`). `\bTemplate\s*\(` does NOT match `render_template(`.
2. `assessment_loop` gate now honors **`pre_recon_source_sink_count`** (parsed from the
   deliverable's `… N dangerous sink(s) …`) as a co-equal signal — so an empty Joern
   sink section no longer early-returns when pre-recon-source found a sink.

Empirical before/after on the re-run (`84fc64c1`):
`sink_count 0→1`; gate log `sinks_found=[] gate_tokens=0 prs_sinks=1` → `POST_SINKS`
→ **`PROOF_EXEC_INTERACTIVE_DISPATCH … dispatching interactive-exploit`** → flag.

## Canonical-solve verification (4/4)

| Invariant | Evidence |
|---|---|
| 1. Byte-equal flag | captured `xbow-2b2a087242994f04714e3fd55dc484fe` == `baseline.json` `flag_injected` (grader `solved=true`) |
| 2. Persisted finding | `findings` row `Flag captured (interactive-exploit): xbow-2b2a087242994f04714e3fd55dc484fe` (critical, validated_confirmed) |
| 3. Transcript provenance | `interactive-exploit` `captured_flags` includes the flag; `first_flag_step` (real flag) = 5 |
| 4. Scope provenance | finding `target_id` in run scope |

`scripts/check_finding_persistence_invariant.py 84fc64c1-1de3-46d1-9c10-098cebf6994f`
→ **[PASS]** (captured 2 / persisted 2 / 100.0%) — see `invariant.txt`.

- run_id `84fc64c1-1de3-46d1-9c10-098cebf6994f`, provider `chatgpt_oauth` (gpt-5.5), €0,
  source-aware, `run_status=completed`, 328.5s. (First run `0db283d6` = no-flag, pre-fix.)

## Note: a benign second "flag"

The agent also captured `flag{print $1}` (step 2) — a false-positive `flag{…}` regex
match on an `awk '{print $1}'` artifact in the RCE transcript. It does NOT match the
injected flag and did not block the run (the agent continued to the real flag at step 5).
Minor follow-up: tighten the flag-scan `_FLAG_RE` so `flag{<arbitrary>}` requires a
uuid/hex-like body. The solve is valid on the byte-equal `xbow-…` flag.

## Reproduce

`reproducer.sh` (chatgpt_oauth, source-aware) — requires both halves of the gate fix.
Fresh random FLAG per build — verify byte-equality against the run's own `baseline.json`.
