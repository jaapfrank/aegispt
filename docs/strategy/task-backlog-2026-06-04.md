# Consolidated task backlog — 2026-06-04

Authoritative prioritized list. Supersedes the scattered R1-R5 / T-AI entries in
adaptive-recon-and-ux-tasks-2026-06-03.md + ai-owns-orchestration-2026-06-03.md
(those keep the detailed design notes; this is the ORDER + status).

## DONE this arc (2026-06-03/04) — all committed + live-proven
- Headless-XSS cluster lever (win-condition + required-dialog-message): **21 canonical
  solves** (008/004/013/050/047/011 + 012/015/016/017/018/046/048/049/051/059 +
  062/064/065/070/087). XBOW ~17→~38 (≈37%). [5b9b01a, d34a068]
- Race-safe dispatch dedup (interactive-exploit + pre-recon-cpg). [e4f8be5]
- target-intel web-first port sweep; nmap deferred to a follow-up. [f5919c1]
- SSRF/auth-logic DISPATCH lever (server-fetch sinks + forgeable secret). [28a81b3]
- Multi-step chain-reasoning in the exploit prompt (policy-safe, no regression). [239593b]
- recon_planner brain (AI-elective recon, flag-gated, fallback-safe). [bd8cff1]

## ACTIVE / NEXT (ROI order)

### T-CHAIN1 — Internal-endpoint chain surfacing  [BUILDING NOW]
Surface INTERNAL-ONLY endpoints (gated by `request.remote_addr`/localhost checks) +
their request params so the exploit agent knows the SSRF target. Completes the
chain-reasoning prompt (239593b): together they should SOLVE XBEN-024 (SSRF ->
localhost-only /reset_password?username=admin&newpassword=x -> admin login) and the
SSRF-to-internal-endpoint class. Generic source observation, not a recipe.
- Files: workers/runners/pre_recon_source/runner.py (detect remote_addr gate + the
  route's params), surface an "INTERNAL-ONLY ENDPOINTS (SSRF-reachable)" block.
- Acceptance: unit test (a remote_addr-gated route + its params surfaced) + LIVE
  XBEN-024 solve (the multi-step chain proof) with no single-step regression.

### T-AI1 — AI-elective recon chokepoint
recon_planner brain exists; wire a single pre-dispatch recon-decision chokepoint so
the model owns the recon set, not the 4 hardcoded sources. Correctness-sensitive
(see ai-owns-orchestration finding: candidate-level recon is mostly useful; a naive
veto stalls). Design the chokepoint carefully; flag-gated; before/after solve-rate.

### R5 — Terminate promptly on a miss
A miss idles out the full wall-clock budget at "decision point" (operator: "nothing
running in the UI"). Finalize when no dispatchable action + no new signal for N
iterations. Largely mitigated by the dedup+sweep (leaner pipeline) but still real.

### T-AI2 — AI owns the FULL tool flow (recon->exploit->pivot)
The big one: the picker owns every step; `_goal_tool_sequence`/seed fixed lists become
pure fallback. The genuine "AI owns orchestration" north-star. Major redesign.

### R3 — Stream interactive-exploit reasoning live
Engine emits step-by-step reasoning; codex UI renders it (kills the "(waiting for
stdout)" dead feel). Engine side here; UI side is the codex lane.

### T-DECOMP — Keep decomposing assessment_loop.py (7400+ lines)  [continuous]
Each time we touch an area, extract the cohesive logic into a focused unit-tested
module (recon_planner.py is an example). Next candidates: the goal/seed candidate
builders -> goal_planner; `_maybe_dispatch_cpg_seeded_cea` -> its own module.

### R2 — nmap per-host dedup  [cleanup, mostly moot after the sweep]

## FRONTIER (not a quick task — strategy, not a sprint)
- Genuine multi-step CHAIN ASSEMBLY is a model frontier (XBEN-024 missed even with
  the chain prompt + the facts present). Needs stronger agentic loop AND/OR the
  Trusted-Access-for-Cyber approval to lift the ChatGPT-OAuth cyber-policy that
  refuses less-restricted exploit prompting (project_trusted_access_cyber_pending).
- Recon-surfacing levers remain the reliable NEAR-TERM solve-rate lever; the
  AI-owns-reasoning direction is the long game.
