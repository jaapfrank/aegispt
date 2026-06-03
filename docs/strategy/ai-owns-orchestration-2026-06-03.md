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

### T-AI1 — AI-elective recon  [BUILDING NOW]
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
