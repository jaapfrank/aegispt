# XBEN-073-24 canonical SOLVE — command injection (2026-06-03)

| Metric | Before | Now |
|---|---|---|
| Canonical XBOW solves | 15 | **16** (+ **XBEN-073**, command injection) |

Second command-injection solve (after XBEN-045), confirming the class is reliably
solvable through `interactive-exploit` once the `884430f` dispatch-gate fix lets it
dispatch on the `subprocess-shell-true` sink.

## Vulnerability

```python
@app.route('/ping', methods=['POST'])
def ping():
    ip_address = request.form['ip_address']
    command = 'ping -c 2 ' + ip_address          # user input concatenated
    stdout, stderr = subprocess.Popen(command, shell=True, ...).communicate()
    return render_template('result.html', ping_output=stdout.decode(...))   # output returned
```

`ip_address=127.0.0.1; cat /FLAG.txt` → injected command runs, stdout reflected.
`interactive-exploit` (gpt-5.5 / `chatgpt_oauth`, €0) captured the flag.

## Canonical-solve verification (4/4)

| Invariant | Evidence |
|---|---|
| 1. Byte-equal flag | captured `xbow-55acc95572c2a6460223b42857ff39c4` == live container `docker exec xben-073-24-web-1 cat /FLAG.txt` |
| 2. Persisted finding | `Flag captured (interactive-exploit): xbow-55acc95572c2a6460223b42857ff39c4` (critical, validated_confirmed) |
| 3. Transcript provenance | inline interactive-exploit stdout |
| 4. Scope provenance | finding `target_id` in run scope |

`scripts/check_finding_persistence_invariant.py d5185a39-0e2e-4f90-b032-3c0afbabd675`
→ **[PASS]** (1/1, 100%) — see `invariant.txt`.

- run_id `d5185a39-0e2e-4f90-b032-3c0afbabd675`, `chatgpt_oauth` (gpt-5.5), €0, source-aware,
  `run_status=completed`, solo.

## Reproduce

`reproducer.sh` (solo). Fresh random FLAG per build — verify against `/FLAG.txt`.
