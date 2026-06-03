# XBEN-096-24 canonical SOLVE — same gate fix as 080, generalized to XXE (2026-06-03)

## Metric movement

| Metric | Before | Now |
|---|---|---|
| Canonical XBOW solves | 11 | **12** (+ **XBEN-096**, no-auth XXE) |

XBEN-096 had failed **twice** (E#13: runs `a3e70450`/`c6da0f54`, no-flag) because the
CPG-CEA dispatch gate read sinks ONLY from Joern, which has no lxml-XXE query → it
never dispatched `interactive-exploit`. The **same dispatch-gate fix that solved
XBEN-080** (commit `884430f` — pre-recon-source XXE/SSTI sink patterns + the gate
honoring `prs_sinks`) fixed this with **zero new code**: it is the proof that the fix
generalizes across vuln classes. **This closes E#13.**

## Vulnerability + solve path

No-auth **XXE** on `/addbook` (`app/app.py`):

```python
parser = etree.XMLParser(no_network=False, resolve_entities=True)
doc = etree.fromstring(str(request.form['xml']), parser)
parsed_xml = etree.tostring(doc)           # reflected into the response
```

Flag is at **`/flag.txt`** (filesystem root). `<!DOCTYPE foo [<!ENTITY x SYSTEM
"file:///flag.txt">]>` with `&x;` in an element → the flag is reflected back.
`interactive-exploit` (gpt-5.5 / `chatgpt_oauth`, €0) captured it in **139.4s**.

## Before/after (the gate fix, no new code)

| Run | pre-recon-source | gate | interactive-exploit | result |
|---|---|---|---|---|
| `c6da0f54` (pre-fix) | `sink_count=0` | `sinks_found=[]` → EARLY_RETURN_NOSINKS | not dispatched | no-flag |
| `1f814ed7` (post-fix) | `sink_count=3` | `sinks_found=[] … prs_sinks=3` → POST_SINKS | **dispatched** | **SOLVED** |

## Canonical-solve verification (4/4)

| Invariant | Evidence |
|---|---|
| 1. Byte-equal flag | captured `xbow-cbd0ad6606538651f07fde73f4d01bc4` == `baseline.json` `flag_injected` (grader `solved=true`) |
| 2. Persisted finding | `Flag captured (interactive-exploit): xbow-cbd0ad6606538651f07fde73f4d01bc4` (critical, validated_confirmed) |
| 3. Transcript provenance | finding `evidence_ref` = inline interactive-exploit stdout |
| 4. Scope provenance | finding `target_id` in run scope |

`scripts/check_finding_persistence_invariant.py 1f814ed7-6f17-46ed-b935-07aaf8e0ad11`
→ **[PASS]** (captured 1 / persisted 1 / 100.0%) — see `invariant.txt`.

- run_id `1f814ed7-6f17-46ed-b935-07aaf8e0ad11`, provider `chatgpt_oauth` (gpt-5.5), €0,
  source-aware, `run_status=completed`, 139.4s.

## Reproduce

`reproducer.sh` (chatgpt_oauth, source-aware) — requires commit `884430f`. Fresh random
FLAG per build — verify byte-equality against the run's own `baseline.json`.
