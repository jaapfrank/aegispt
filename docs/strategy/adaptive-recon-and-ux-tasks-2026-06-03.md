# Adaptive recon + exploit-UX tasks — 2026-06-03

## STATUS
- **R1c (duplicate interactive-exploit) — DONE** (commit e4f8be5). Live: XBEN-059 n_ie 2→1 AND still solved.
- **R1b (duplicate pre-recon-cpg) — DONE** (commit e4f8be5). Live: XBEN-062 n_cpg 2→1.
- R1 (adaptive Joern skip) — OPEN (correctness-sensitive; needs the fallback + solve-rate before/after).
- R2 (nmap per-host dedup) — OPEN.
- R3 (stream exploit reasoning live) — OPEN (engine emit + codex UI).
- Serial-dispatcher queue latency (interactive-exploit median ~207s queued) — OPEN, architectural.


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

## R1c — Duplicate interactive-exploit dispatch (the BIGGEST waste)  [engine, correctness-sensitive]

The duplicate-dispatch race (R1b) also hits interactive-exploit — the EXPENSIVE step
(gpt-5.5, 100-280s each). Operator saw "interactive-exploit x2" on a single target;
DB confirms both queued the SAME second, identical target (http://127.0.0.100),
identical recon + ai_reasoning, source_finding_id null → not two hypotheses, a
double-fire. The focused-assessment path already has an in-process memo
(`_FOCUS_DISPATCHED_OBJECTIVES`, assessment_loop.py:2202-2207, "target
double-dispatch=0"); the REGULAR CPG-CEA single-shot dispatch (assessment_loop.py:
~2570-2612) lacks the equivalent guard, so overlapping iterates double-fire it.

Evidence it's a race (not intentional 2x): across solved harvest runs the exploit
count is 1 OR 2 depending on iterate timing (XBEN-012 ran 1; 015/016/018 ran 2).

CORRECTNESS CAVEAT — do NOT blindly dedup to 1: in XBEN-015 and XBEN-016 only ONE of
the two "identical" exploits captured the flag (gpt-5.5 is stochastic → the redundant
shot sometimes IS the winning attempt). So the fix must: (a) kill the WASTEFUL
SIMULTANEOUS duplicate (same-iterate / same-second double-fire) via the same memo
guard the focused path uses; (b) PRESERVE retry-on-miss — a 2nd attempt dispatched
SEQUENTIALLY only after the 1st task completes WITHOUT a flag, not two blind parallel
fires. Acceptance: when the 1st exploit solves, exploit-count=1 (no wasted 2nd);
when it misses, a 2nd attempt still fires; cluster solve-rate unchanged on a ≥4
before/after re-run.

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
