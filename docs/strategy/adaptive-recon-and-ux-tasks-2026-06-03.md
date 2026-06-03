# Adaptive recon + exploit-UX tasks — 2026-06-03

Operator feedback during the headless-XSS harvest. Three improvements, scoped with
exact anchors. NONE are hacks: each must keep the working solve-pipeline (currently
6/6 on the headless cluster) intact — proven with solve-rate before/after, not just
green units.

## R1 — Adaptive Joern/CPG dispatch (NOT a hard skip)  [engine]

Today `pre-recon-cpg` (Joern) is dispatched UNCONDITIONALLY after pre-recon-source
(`assessment_loop.py:3044`, the `if has_pre_recon_source_task and not
has_pre_recon_cpg_task` bootstrap). Joern parse+query costs ~2-3 min/run before the
exploit can even start. For the headless cluster it is redundant: pre-recon-source
already yields the win-condition + sinks, and the dispatch gate
(`assessment_loop.py:~2367`) passes on `prs_sinks` alone.

Operator's principle (verbatim intent): "a smart system knows Joern isn't needed —
or, if nothing comes out of the other tests, still runs Joern." So:
- SKIP the CPG bootstrap when pre-recon-source already produced a usable lead
  (its stdout payload `sink_count > 0` OR `headless_dialog_count > 0` OR
  gate-tokens present).
- FALLBACK (correctness-critical): if the run later reaches a no-progress state —
  specialists returned no hypotheses AND no findings AND no flag — THEN dispatch
  pre-recon-cpg (Joern may surface a sink pre-recon-source's regexes missed, e.g.
  a Joern-only taint path). Without this fallback, skipping Joern can LOSE solves
  where pre-recon-source's sinks are misleading — so the skip must never be final.

Acceptance: (a) on a headless-cluster challenge, CPG is NOT dispatched and the
challenge still SOLVES, measurably faster; (b) on a challenge where pre-recon-source
finds nothing, CPG IS still dispatched (fallback fires); (c) re-run ≥3 previously
solved challenges (mixed classes) → all still solve (no regression).

## R1b — Duplicate recon-task dispatch (iterate race)  [engine, SAFE, do FIRST]

Empirical queue-latency (harvest runs, 2026-06-03): interactive-exploit median
**207s** in queue before exec (max 459s); pre-recon-cpg median 120s. Timeline of run
6651d119 shows tasks executing SERIALLY (one starts only as the prior frees the
inline dispatcher), and — the smoking gun — **TWO pre-recon-cpg tasks** dispatched
6s apart (39:45 + 39:51), plus the known double-nmap. Root cause: the harness polls
`/assessment-loop/iterate` every 12s; when an iterate takes >12s, two overlapping
iterates BOTH pass the `not has_pre_recon_cpg_task` guard (assessment_loop.py:3040-44)
because the first task isn't committed/visible yet → duplicate bootstrap dispatch.
The duplicate Joern (~94s) sits on the exploit's critical path.

Fix (SAFE — the tool still runs exactly once, zero solve-risk): make the bootstrap
dispatch idempotent — dedup by (run_id, tool, phase) at insert time (DB unique guard
or a SELECT-FOR-UPDATE check), OR serialize iterate per run with an advisory lock.
This is the user's "time lost in the queue" signal and the cheapest real win.
Acceptance: each run dispatches pre-recon-cpg (and nmap per host) AT MOST once;
interactive-exploit median queue wait drops measurably.

## R2 — nmap per-host dedup  [engine]

`planned_targets_for_tool(..., derive_url_hosts_for_nmap=True)`
(`assessment_loop.py:4885/5291/5346`) expands a URL target into BOTH the bare host
and the URL form, so nmap is dispatched twice for the same host (observed run
6f47e235: `nmap http://127.0.0.182` + `nmap 127.0.0.182`, both exit 0). Wasteful +
the operator saw a confusing WAITING(one)+DONE(other) pair for "the same" nmap.
Fix: dedup nmap targets to one scan per resolved host (strip scheme/port, collapse
`http://X`+`X` to one). Acceptance: a URL-scope run dispatches nmap ONCE per host.

## R3 — Stream interactive-exploit reasoning live  [engine emit + codex UI]

The exploit runner already records every step (reason → HTTP request → observe) in
the transcript artifact, but only writes it at the END, so the UI shows
"(waiting for stdout/stderr…)" for the whole 50-300s run. Operator wants to watch
gpt-5.5 think. Engine side (mine): emit incremental step events as they happen
(append-only progress channel / partial stdout). UI side (codex lane): render the
live step stream in the task card. Acceptance: per-step reasoning appears in the
task view while the exploit is still running, not only at completion.

## Discipline
- R1 is correctness-sensitive (skipping Joern can cost solves) → build with
  solve-rate before/after on ≥3 challenges, never units-only.
- Do NOT destabilize the working pipeline mid-harvest. Apply post-harvest, restart,
  live-prove, then commit the live evidence.
