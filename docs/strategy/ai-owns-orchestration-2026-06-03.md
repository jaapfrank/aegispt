# North-star gap: AI should OWN orchestration, not a hardcoded decision-tree — 2026-06-03

## Operator insight (verbatim intent)
"Who actually decides the steps — the system or the AI? I can't imagine that if you
give the AI the right info it would try nmap. If the system decides, then it is not
AI-driven, it is still a dumb script system."

Correct. Verified in code. Today the loop is a HYBRID and the recon/orchestration
backbone is hardcoded, not AI.

## Evidence — what is hardcoded vs AI
HARDCODED (scripted decision-tree, no LLM):
- `_goal_tool_sequence(objective_type, target_type)` (assessment_loop.py:4983) returns
  FIXED tool lists; `first = "nmap" if target_type in {"cidr","ip_or_host"} else "httpx"`.
  nmap fires by rule, regardless of whether it is useful (a known web app on a known
  port) — already flagged running with 0 hosts in nearly every solved run.
- `_objective_type()` (:4965) = keyword string-matching on the objective text.
- pre-recon-source / pre-recon-cpg bootstraps (:3010, :3123) = "if not has_X_task:
  dispatch X" — fixed sequence, not an AI choice.
- `_seed_candidate` / `_goal_oriented_candidate` seed the early actions from these
  fixed sequences, so recon runs BEFORE the AI has results to reason about.

AI-DRIVEN (real intelligence):
- the picker (`_claude_select_next_action` / 5 specialists) ranks hypotheses + picks
  the next exploit action.
- the interactive-exploit runner loop: request -> observe -> decide with gpt-5.5, live.

## The gap vs the north-star (black-box superintelligence / full replacement)
The smart part (exploitation) is AI; the orchestration backbone (recon, tool order,
bootstraps) is a scripted tree. R1/R4/R5 (skip CPG/nmap, terminate on miss) are
BAND-AIDS on that tree. The real direction: the AI decides the WHOLE flow — given the
target envelope + cheap probes, the model itself chooses which recon (if any) is worth
running ("single web app on a known port -> skip nmap, go to source + content-discovery").

## Direction (not a quick task — an architecture shift)
- Make recon AI-elective: present the target facts to the model and let it choose the
  recon set + order, instead of `_goal_tool_sequence` fixed lists. Keep the hardcoded
  sequence only as a fallback when the model declines to choose.
- Measure: does AI-elected recon keep/raise solve-rate while cutting wasted tools
  (nmap-0-hosts, redundant CPG) and idle time? Before/after on a mixed challenge set.
- This subsumes R1 (adaptive CPG) and R4 (skip nmap): both become emergent properties
  of the AI owning the decision, not new hardcoded branches.

## Ordered task backlog (captured 2026-06-03)

### T-AI1 EMPIRICAL FINDING (2026-06-03) — recon dispatch is SPRAWLED, no chokepoint
Built `recon_planner.py` (10 tests, fallback-safe, commit bd8cff1) + wired it behind
AEGISPT_AI_ELECTIVE_RECON into `_build_goal_oriented_reasoning`. Live test (flag ON,
XBEN-008): the planner marker NEVER fired and nmap STILL dispatched — because
`_build_goal_oriented_reasoning` is NOT on the hot path for these runs. Tracing the
nmap task's `source` field showed it came from **`next_step_hint`**: the
**target_intel runner** (`workers/runners/target_intel/runner.py:370`) emits a
"run nmap" hint when "URL has no explicit port and the default-port probe got no
response" — it probes port 80, fails (app is on :5000, which IS already in scope),
and asks for nmap. `_maybe_queue_next_step_hints` (workers/orchestration/tasks.py:5068)
auto-queues it.

=> Recon dispatch is sprawled across ≥4 hardcoded sources: `_goal_tool_sequence`,
`_seed_candidate` (LOOP_SEED_TOOLS_BY_TARGET_KIND), the plan, AND runner-emitted
next_step_hints — there is NO single point to inject AI control. THIS sprawl is the
concrete reason it behaves like a "dumb script." The planner is the right capability
but needs a CHOKEPOINT, not one more wire.

REFINED T-AI1: add a single pre-dispatch recon-decision chokepoint (e.g. in the
inline dispatcher / `_maybe_queue_next_step_hints` + the candidate-merge in
assessment_loop) that, when AI-elective, asks the planner whether a recon tool is
worth running for THIS target before it is queued — regardless of which source
proposed it. Quick deterministic sub-win available immediately: target_intel should
NOT emit the nmap hint when the port is already known from scope/envelope (it probes
:80 instead of the scoped :5000). Keep recon_planner.py as the decision brain.

### T-AI1 — AI-elective recon  [planner built; chokepoint wiring next]
Replace the hardcoded `_goal_tool_sequence` first-tool rule with an AI recon planner:
given the target envelope (single web URL w/ known port vs IP/CIDR vs unknown) +
whether source is available + the available tool menu, the model chooses the recon
SET and ORDER, and may SKIP tools that add nothing (nmap on a known web port). The
hardcoded sequence stays ONLY as a deterministic fallback when the model declines or
errors. Subsumes R1 (adaptive CPG) + R4 (skip nmap).
- Files: new `api/app/services/recon_planner.py`; wire into the `_goal_tool_sequence`
  callers / seed path in `assessment_loop.py`.
- Acceptance: (1) unit — planner given a known-web-URL envelope omits nmap, keeps
  content-discovery/source; given an IP/CIDR keeps nmap; fallback used on LLM failure.
  (2) live before/after — a web-target run dispatches NO nmap and still solves; a
  CIDR/IP run still runs nmap. Solve-rate unchanged on a ≥4 mixed set.

### T-AI2 — AI owns the FULL tool flow (not just recon)
Extend T-AI1 so the picker owns every step; `_goal_tool_sequence` / `_seed_candidate`
fixed lists become pure fallback. The model drives recon→exploit→pivot end to end.

### Then (ordered)
- R5 — terminate promptly on a miss (stop idling out the budget; the recurring
  "nothing running in the UI"). [adaptive-recon-and-ux doc]
- R3 — stream interactive-exploit reasoning live (engine emit + codex UI), so the
  "(waiting for stdout)" gap shows the model thinking.
- R2 — nmap per-host dedup (cleanup; mostly moot once T-AI1 lands).
- Serial-dispatcher latency — let independent tasks run concurrently safely (the
  deeper cause of queue wait); needs care re: the no-parallel-runs contention.
- Headless-XSS breadth — finish the untested cluster (062/064/065/070/074/087 + the
  remaining ~17 fire-dialog challenges) once the loop is faster + leaner.

### T-DECOMP — keep decomposing assessment_loop.py (7407 lines)  [continuous]
The loop is a god-module; decomposition is already UNDERWAY (assessment_loop_internals/
{guards,picker_schema,picker_system_prompt,picker_decoder,recall,...} + service modules
attack_surface/finding_verifier/picker_specialists/recon_planner). Continue INCREMENTAL
extraction (NOT a big-bang rewrite of the solve-critical path): each time we touch an
area, pull the cohesive logic into a focused, unit-tested module and leave
assessment_loop.py as the thin orchestrator. Candidates to extract next: the goal/seed
candidate builders (`_goal_tool_sequence`/`_build_goal_oriented_reasoning`/
`_goal_oriented_candidate` -> a `goal_planner` module, naturally alongside T-AI1), the
CPG-CEA dispatch (`_maybe_dispatch_cpg_seeded_cea` -> its own module), and the
finalization path. Acceptance per extraction: behaviour-preserving (tests green) +
assessment_loop.py shrinks.
