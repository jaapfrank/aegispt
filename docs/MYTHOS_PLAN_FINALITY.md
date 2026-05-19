# Mythos Convergence Plan — Finality Document

**Effective**: 2026-05-15
**Status**: LOCKED — see Section 4 for legitimate revisit conditions
**Authorities**: Operator (jaapfrank), Agent (Claude Opus 4.7)

## 1. Purpose

This document exists because the prior planning sessions on 2026-05-15 produced multiple architectural pivots before any execution. The operator asked: *"Dat we over een week niet weer dezelfde discussie hebben."*

This document is the artifact that prevents that. It records:

- Exactly what the plan IS (and what it is not)
- What evidence underpins it
- What would constitute a legitimate reason to revisit
- What does NOT constitute a reason to revisit

If a future session opens this file and the operator has not explicitly invoked one of the revisit triggers in Section 4, the plan stands as-written.

## 2. The plan (18 tasks)

Tasks `#321` through `#338` in `TASK_QUEUE.md`. Mapped one-to-one with `codex/tasks/backlog-371-*.json` through `backlog-388-*.json`. Validated via `python3 scripts/validate_backlog_tasks.py`.

**Phase 1 — Evidence-graph adoption (#321-#324)**
Build, do not fork. Verdict reasoning: existing `build_normalized_evidence_graph` (api/app/services/assessment_graph.py:371) already produces normalized nodes + edges with confidence + provenance. PentAGI's "knowledge graph" is the external Graphiti service (https://github.com/getzep/graphiti); they don't have proprietary IP to fork. Adopting Graphiti as separate infra is a separate strategic decision (Neo4j + Postgres-vector + ops burden) and is OUT OF SCOPE of this plan. We expand what we have.

**Phase 2 — Universal auth + pattern cache (#325-#329)**
Build, do not fork. Verdict reasoning: HexStrike's `bugbounty_authentication_bypass_testing` is a static cheatsheet (returns hardcoded payload-string arrays, does not fetch or execute). Their `BrowserAgent.run_active_tests` is explicitly "safe mode, GET-only, no state-changing operations." Our existing `xss_proof/runner.py:_try_register_with_ai` already does AI-driven account registration. Pattern cache (#327) is novel — neither competitor has cross-engagement learning.

**Phase 3 — Picker hardening (#330-#333)**
Build, do not fork. Verdict reasoning: structured outputs is an Anthropic feature, soft retry is engineering hygiene, memory truncation is cost optimization. No upstream equivalent and no need.

**Phase 4 — Cross-target + verifier + primitives (#334-#337)**
Build with informed design. Verdict reasoning: #334 (cross-target provenance) studies PentAGI's task graph pattern but builds our own. #335 (cross-runner verifier) is novel. #336 (SMB/LDAP exec_plan steps) wraps our existing impacket/ldap_enum runners — no fork needed since we already have these tools, just need primitive-level exposure.

**Tool breadth — Specialized fork (#338)**
Fork, do not build. Verdict reasoning: HexStrike fork-test on 2026-05-15 confirmed each tool wrapper is ~45-65 lines of trivial subprocess + parameter handling. Lifting 10-15 wrappers we lack (Volatility, Hydra, Ghidra, etc.) saves ~10-15 hours vs writing from scratch. MIT licensed. No HexStrike runtime dependency — we lift code, not server.

## 3. Evidence underpinning the verdicts

The verdicts above are not opinions. They are based on:

- **`docs/research/2026-05-15-hexstrike-code-spike.md`** — concrete line-by-line analysis of HexStrike's auth, governance, browser agent, and tool wrappers. Verified by `grep`-counts and direct code reads.
- **PentAGI repo inspection on 2026-05-15** — verified `backend/pkg/graphiti/client.go` is a 145-line wrapper around external `github.com/vxcontrol/graphiti-go-client`. Verified `GetFlowTaskGraph` returns parent-child task hierarchy via REST (not a semantic graph). Verified Graphiti runs as separate docker-compose service.
- **HexStrike Volatility wrapper read** — `hexstrike_server.py:11870` is 45 lines of Flask handler. `hexstrike_mcp.py:1736-1756` is 20 lines of MCP wrapper. Pattern trivially liftable.
- **Empirical generality test from prior session** — confirmed our 5 new probes (info-disclosure, param-pollution, stored-xss, cookie-tamper, file-upload) produce 0 findings on 3 non-Gruyere targets due to hardcoded Gruyere auth flow. This is the concrete problem #325-#329 solves.
- **Live cache verification** — confirmed `cache_read > 0` from hop 1 onwards in picker logs after enabling prompt caching. Caching works.

## 4. Legitimate revisit triggers (exhaustive)

The plan is LOCKED. It revisits ONLY if one of these is true:

1. **Anthropic deprecates Opus 4.7 or fundamentally changes Claude API pricing or capability.** A pricing increase under 2× does not qualify. Model deprecation does.
2. **A review checkpoint task (#324, #329, #333, #337) produces explicit no-go data.** Each checkpoint task has explicit go/no-go criteria. If no-go fires, corrective task is queued ahead of next phase.
3. **A specific build task encounters infeasibility documented in code.** Not "this is harder than expected" — "this is impossible because X, with evidence Y". The blocker must be specific, demonstrable, and recorded in the task's DONE_LOG entry as the reason for halting.
4. **A production-impact issue arises from completed work.** Security regression, evidence-chain breakage, data loss, kill-switch malfunction. Operator-initiated only.
5. **Operator explicitly requests a re-plan in writing.** Not implicit, not via "ik vraag me af of...". The operator must say plainly: "revisit the Mythos plan, here is what changed."

## 5. NOT a legitimate revisit trigger (exhaustive)

The plan does NOT revisit because of:

1. **A new open-source project appeared.** Note it for future consideration, do not re-architect.
2. **An interesting blog post, conference talk, or research paper.** Same.
3. **An AI/agent framework released a new feature.** Same.
4. **The Agent (Claude) thinks of a "better" architecture mid-task.** This is what caused the planning purgatory. NOT a trigger.
5. **A competing tool published a benchmark.** Note for marketing context. Not a re-plan trigger.
6. **The operator says "interesting" or "what about X" in conversation.** Conversation is exploration; only an explicit re-plan request per trigger 5 above counts.
7. **A task takes longer than estimated.** Estimates are not contracts. Recalibrate within the task, do not re-plan the whole arc.
8. **A pivot looks "obvious" in hindsight.** All pivots look obvious in hindsight. That is not evidence.

## 6. Execution rules

When a task is active (in NEXT_TASK.md):

- Stay strictly inside the task's `scope` and `must_not_touch` lists.
- If something out-of-scope appears important, file it as a NEW backlog task with `generated_by: "discovered-during-task-#NNN"` and KEEP WORKING on the active task.
- Do not promote the new backlog item ahead of the existing plan. It joins at the queue end.
- Do not auto-pivot. If you genuinely believe the plan should change, write up the case and present it to the operator with explicit reference to Section 4 of this document. If no Section 4 trigger applies, the case is filed as future-consideration, not as plan change.

## 7. Plan completion criteria

The Mythos plan is COMPLETE when:

- #321 through #338 all show DONE in DONE_LOG.md.
- The #337 final demo report exists and is signed off by the operator.
- AGENT_SYSTEM_MAP.md sections 3, 4, 5, 10 reflect post-Mythos state.
- A new strategic planning session is opened by the operator to scope what comes next.

After completion, this document is preserved as historical record. A new finality document is written for the next planning epoch.

## 8. Operator-Agent agreement

I, the Agent (Claude Opus 4.7, this session 2026-05-15), commit to:

- Executing #321 through #338 as written, with the verdicts in Section 2.
- Honoring Section 4 (legitimate triggers) and Section 5 (NOT triggers).
- Following Section 6 (execution rules) when a task is active.
- Not proposing architectural pivots inside active tasks. If I notice something, I note it. If it is important, I file a future-consideration backlog item.

I, the Operator (jaapfrank), commit to:

- Treating tasks as locked once promoted to NEXT_TASK.md.
- Not asking "should we maybe X instead" mid-task. Such questions go in a separate planning thread.
- Invoking Section 4 explicitly when a re-plan is warranted.

By committing this document to git, both parties have signed.

## 9. Reference

- `TASK_QUEUE.md` — sequential queue, items 321-338
- `codex/tasks/backlog-371-*.json` through `codex/tasks/backlog-388-*.json` — task packages
- `docs/AGENT_SYSTEM_MAP.md` — cross-session system reference
- `docs/research/2026-05-15-hexstrike-code-spike.md` — HexStrike + PentAGI spike report
- `AGENTS.md` — agent operational conventions

If you are reading this in a future session: read those five documents first, then come back here.
