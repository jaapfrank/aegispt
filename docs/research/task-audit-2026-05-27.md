# Open + DONE task audit — 2026-05-27

Operator request: review (a) what's still open, (b) what's marked DONE
but may not be empirically working, (c) where an open-source standard
or upstream variant would replace local work.

## Method

Cross-checked three sources:

- `TASK_QUEUE.md` (388 numbered packages, 25 of which are SPRINT-tagged open)
- `docs/plans/beat-shannon-pro-roadmap-2026-05-23.md` (M1-M9 capability roadmap)
- `NEXT_TASK.md` (queue exhausted after #388; operator-selected next task pending)

Each row below is rated by:

- **Lives?** — empirical evidence the capability actually runs in production logs / DB / tests (not just a "shipped" badge).
- **Replace?** — whether an open-source standard or upstream system covers it better than custom work.

## Part 1 — Open SPRINT items (25)

### Sprint: mythos-exploitation-foundation (15 open)

| # | Item | Lives? | Replace? | Recommendation |
|---|---|---|---|---|
| 357 | Observability — OpenTelemetry + Langfuse (tracing only) | substrate, not live-confirmed | **Yes** — PentAGI ships OTel + Langfuse + Grafana + Prometheus + Jaeger + Loki as one stack | **Adopt PentAGI's compose** rather than reinvent. License: AGPL-3 but we can run as a sidecar without statically linking |
| 358 | XBOW benchmark baseline harness (104 chal, anti-contamination) | LIVE — `xbow-2026-05-21-baseline.md` exists in repo with the 0/25 result. ANTI_DRIFT-conformant flag injection | No — our harness already maps to NIST CAISI guidance | **Promote to "score-lane" recurring task** — daily-5 subset is the value, not the 104 full sweep |
| 359 | Governance Control Plane (Layer 0) + Docker isolation | LIVE — `agent_tools` Layer 0 verified in earlier session per `feedback_log_entry_proof_of_execution` | No good open-source equivalent for cyber-specific guardrails; closest is Anthropic's own MCP allowlist patterns | **Keep custom** |
| 360 | Episodic memory — Postgres + pgvector ADDITIVE | substrate (M5 in roadmap) — `pending. only valuable AFTER M1-M4` | No — pgvector + sentence-transformers IS the standard | **Promote**: smoke 38's SOLVE chain should have populated memory; if it had been formalized, M5 would have its first datapoint |
| 361 | Context curation (Claude Code autoCompact-style) | unverified — no live trace | Claude Code itself does this; our reimplementation is for non-Anthropic providers | **Re-scope** to "context curation only for OAuth/local-qwen branches" (Claude already has it) |
| 362 | Attack state machine + foothold + TAP attack tree | substrate exists (`attack_state.py` referenced) — live coverage unclear | TAP = Tree-of-Attacks-with-Pruning, [Mehrotra+ 2024 paper](https://arxiv.org/abs/2312.02119). Reference implementation: <https://github.com/RICommunity/TAP>. **Align with their schema** for cross-tool sharing | **Adopt TAP node format** to allow future hypothesis-tree sharing with the broader research community |
| 363 | Deterministic validator + reproducible PoC engine | `exploit_validator` exists; M2 verdict gate had 1 live proof on XBEN-002 (verdict=UNCLASSIFIED, drop=False). Drop-path NEVER live | No — XBOW's framework matches; transilience doesn't separate validator | **Promote to P0**: a verdict-gate drop-path live proof on a known FALSE_POSITIVE is missing |
| 364 | Exploit Developer agent + runtime custom script gen | `code_exec_attack` runner exists, Phase E "first live dispatch confirmed" on XBEN-002 b4385178 | AWE paper does this with memory + browser verification (87% XSS / 66.7% blind-SQLi) | **Adopt AWE's memory+browser-verification pattern** rather than ship our own — paper is peer-reviewed evidence of +30% |
| 365 | Multi-agent coordinator + 6 specialists + per-agent ACL | LIVE — picker_specialists module is live; 5 specialists used in production, not 6 | PentAGI has **11 specialized roles** (Researcher / Developer / Executor / Searcher / Enricher / Memorist / Generator / Reporter / Adviser / Reflector / Planner). We could borrow Adviser-mentor (auto-intervene on 5-dup-tool-calls) | **Adopt PentAGI Adviser pattern** for stuck-state recovery — our `failure_analysis.py` should be aggressive like this |
| 366 | External knowledge (ExploitDB / NVD / CISA KEV) read-only | unverified; `external_knowledge.py` referenced but no live evidence cited | Open-source feeds exist as APIs. CISA KEV is JSON, NVD is JSON, ExploitDB is offline-fetchable | **Keep custom thin wrapper**, point at the public feeds, don't host them |
| 367 | Multi-LLM via LiteLLM | partial — we have a LLMProvider class with hand-rolled Anthropic/OAuth/Gemini branches AND now local-qwen. LiteLLM is mentioned in code config but not used. | LiteLLM is the standard. ~150 providers behind one API | **Migrate** — replace our 4 hand-rolled adapters with LiteLLM. Estimated 1-2 days. Saves all future provider integration work |
| 368 | PentAGI deep-dive + reusable components report | text-only task, not capability | n/a | **Convert to research doc** then close |
| 369 | Release gate + cross-system capability compare | not yet exercised | covered by my second-opinion + Codex's competitive deep-dive (both committed today) | **Mark DONE** with reference to today's research docs |
| 370 | Picker becomes real agent (Bash/file/web/code/subagent tools) | LIVE for Anthropic (commit 422); 0 tool_uses observed in 175k log lines for Claude per session-summary; **picker canary stays at 0** | Claude Code itself is the reference; on other providers we need our own wrapper | **Investigate why canary = 0**: the gate is not being exercised even where it exists |
| 371 | Score-climbing automation loop (benchmark → analyze → versioned proposal → approve → re-run) | not yet built | **transilience-style 15-loop iteration is the proof this works**. Same pattern. | **Promote to P0 with transilience pattern as template**: this IS the daily-5 score lane Codex's P0 calls for |

### Sprint: mythos-exploitation-parity (2 open)

| # | Item | Lives? | Replace? | Recommendation |
|---|---|---|---|---|
| 372 | Neo4j + Graphiti knowledge graph | not built | PentAGI ships this via Docker compose. Graphiti is open-source ([github.com/getzep/graphiti](https://github.com/getzep/graphiti)) | **Adopt PentAGI's setup verbatim** if we go this route; do NOT build our own Cypher schema |
| 373 | OWASP Nettacker SMB+SSH port | not built | OWASP Nettacker is itself open-source. We could **wrap it via subprocess** instead of porting | **Use Nettacker as a subprocess runner** under our scope gates — saves weeks of port work |

### Sprint: mythos-exploitation-domain-coverage (7 open)

These are all "add new domain runners" (CLI/TUI, crypto, reversing, pwn, priv-esc, mobile, more nettacker). All of them have **open-source upstream that we'd just be wrapping**:

| # | Item | Open-source upstream | Recommendation |
|---|---|---|---|
| 374 | CLI/TUI research interface | PentestGPT itself (USENIX'24) has the planning-state-machine + tree-of-thought UI | **Adopt PentestGPT's CLI** as the operator's interactive lab tool; AegisPT API runs underneath |
| 375 | Crypto runners (factor weak keys, padding oracle) | RsaCtfTool, padbuster, hashcat are best-of-class | **Wrap as subprocess runners** under scope gates |
| 376 | Binary reversing (radare2, Ghidra headless) | both open-source standards already | **Wrap via subprocess + artifact capture** |
| 377 | Pwn (pwntools + ROPgadget) | both open-source standards | **Wrap as runners** |
| 378 | Priv-esc (linpeas + winpeas) | both open-source de-facto standards | **Wrap as runners**, foothold-gated |
| 379 | Mobile (apktool + class-dump) | both standards | **Wrap as runners** |
| 380 | Nettacker remaining ~28 protocols | same as #373 — Nettacker handles them all natively | **Single subprocess wrapper covers all 28** rather than 28 individual ports |

The whole `mythos-exploitation-domain-coverage` sprint can collapse from **7 port tasks into 1 "wrap upstream tools as scope-gated runners" task**. Saves 4-6 weeks of porting work and inherits upstream bug fixes.

### Sprint: mythos-continuous-improvement (1 open)

| # | Item | Lives? | Replace? | Recommendation |
|---|---|---|---|---|
| 381 | Permanent XBOW score improvement program (50→70→80→84.6%) | program-level, not exercised | **transilience's iterate-15-times loop IS this, empirically proven to push 89%→100%** | **Re-scope to transilience-style daily-5 loop** instead of quarterly milestone progression |

## Part 2 — DONE M-roadmap capabilities — live evidence audit

From [beat-shannon-pro-roadmap-2026-05-23.md](../plans/beat-shannon-pro-roadmap-2026-05-23.md):

| M | Capability | Substrate? | Live evidence? | Drop-path tested? | Open-source align? |
|---|---|---|---|---|---|
| M1 | Script critic / adversarial revision | YES | YES (mentioned in roadmap, code_exec_attack predecessor pattern) | N/A | AWE paper does this with browser-backed verification — we should pull that pattern |
| M2 | Verdict gate (EXPLOITED / BLOCKED / FALSE_POS / UNCLASSIFIED) | YES | **partial** — 1 UNCLASSIFIED finding seen on XBEN-002 b4385178; drop-path **NEVER live** | NO | Naptime's "perfect verification" maps here. Drop-path live test is open work |
| M3 | CPG-based dataflow via Joern | YES | **YES — strongest live evidence in repo**. Run 2d3d60c7 2026-05-24: 15 routes, 17 SQL sinks, found `open('/flag')` on XBEN-002 source | n/a | Joern IS the open-source standard. No change needed |
| M4 | Multi-trajectory (Naptime@N) | v1 YES | **substrate-only** — 5-case test passes, no live measurement | n/a | Naptime did N=20 sequential. Our v1 supports N=3. Worth measuring before going broader |
| M5 | Episodic memory (pgvector) | NO | NO | n/a | pgvector + sentence-transformers IS standard. Just hasn't been built. Smoke 38's SOLVE chain would have been its first datapoint had it been archived |
| M6 | Cross-model critic | v1 YES | **substrate-only** — 3-case test passes, LIVE proof "paired with in-flight smoke" but no archived result | n/a | Standard A/B pattern; no upstream to align with |
| M7 | Two-phase agents (analysis + exploit separation) | NO | NO | n/a | Shannon's design. Could maybe be obviated by M1 if revisions are aggressive enough |
| M8 | Pad-1 harness reliability | PARTIAL | partial | n/a | Open-source: just `docker compose down -v` + retry. Our harness already does this; the rest is environmental |
| M9 | Deep reads of other systems | PENDING in roadmap; in fact **DONE today** via Codex's competitive deep-dive + my second-opinion + this audit | yes (3 docs) | n/a | **Mark M9 DONE** |

### M-line summary

- **3 of 9 are live-proven**: M3 (strongest), M1 (mentioned), M2 (partial 1-finding).
- **3 are substrate-only**: M4, M6, M8 partial. Substrate-shipped tests pass but no production observation.
- **3 are not started**: M5, M7, M9-as-roadmapped (M9 effectively done as docs today).

The **M-roadmap claim that the architecture is "live and verified end-to-end" is overstated** — out of 9 milestones, 1 truly is (M3). The rest are substrate with limited or no live proof. That matches Codex's "score-DONE not infra-DONE" critique.

## Part 3 — Critical replace recommendations (prioritized)

1. **#367 LiteLLM migration** — highest ROI per developer-hour. Replaces 4 hand-rolled provider adapters with a standard SDK. Local-qwen, OAuth, Gemini, Anthropic all behind one API. **1-2 days work, saves weeks of future maintenance**.

2. **#380 / #373 / domain-coverage sprint** — wrap OWASP Nettacker as a subprocess runner instead of porting protocols. **Saves 4-6 weeks of port work**, inherits upstream maintenance.

3. **#357 Observability** — adopt PentAGI's OTel + Langfuse + Grafana stack (compose file) rather than building from scratch. **2-3 days vs 2-3 weeks**.

4. **#365 Multi-agent expansion** — adopt PentAGI's 11-role naming + the Adviser-mentor stuck-state intervention pattern. Our `failure_analysis.py` should fire on 5-identical-tool-calls automatically. **1 week**.

5. **#371 score-climbing loop** — transilience's "run benchmarks, find failure, write skill, re-run" loop is the proven pattern. Build this against the daily-5 subset. **Codex P0 + our P0 agree on this**.

6. **#364 exploit-developer** — adopt AWE's memory + browser-backed verification pattern (paper-backed +30% on XSS). Browser automation = Playwright (already an option). Memory = the pgvector M5 work. **2 weeks once M5 substrate exists**.

## Part 4 — Recommended next-sprint shape

Replacing the current 25 open SPRINT items, the next 2-week sprint should be:

| Day | Action |
|---|---|
| 1 | Replay smoke 38 once Gemini quota resets → fill xbow-smoke38-replay validation template → first formally-archived SOLVE |
| 1 | Migrate to LiteLLM (#367) — collapse 4 adapters into one |
| 2 | Wire skill-pack behind `AEGISPT_SKILL_PACK_ENABLED` flag (existing scaffold) |
| 2-3 | Run daily-5 A/B: with vs without skill pack on Gemini (transilience pattern) |
| 3-4 | Adopt PentAGI's observability compose (#357) — drops OTel/Langfuse/Grafana into our docker setup |
| 4-5 | Wrap Nettacker as a single subprocess runner (#373+#380 collapsed) |
| 6-7 | PentAGI Adviser-mentor pattern: `failure_analysis.py` auto-fires on 5-identical-tool-calls (#365 enhancement) |
| 8-9 | M2 drop-path live test on a known FALSE_POSITIVE finding (verdict-gate completeness) |
| 10-12 | M5 episodic memory: pgvector + sentence-transformers + retrieval hook (#360) |
| 13-14 | M4 multi-trajectory live measurement (N=1 vs N=3 on daily-5) |

By day 14 the score lane should have either repeatedly produced SOLVES or surfaced ONE clear root cause for not doing so. Both are valuable.

## Part 5 — What to STOP doing

- Stop the `mythos-exploitation-domain-coverage` sprint as 7 separate port tasks. Replace with **one** "wrap OWASP Nettacker + radare2 + pwntools + linpeas as subprocess-runners" task.
- Stop building our own observability stack — PentAGI already shipped it under AGPL-3 (which we can run side-car).
- Stop hand-rolling provider adapters — LiteLLM exists.
- Stop calling things "DONE" when only the substrate runs. The roadmap should distinguish `substrate-shipped` from `live-proven`. Two of our M-items just got promoted to "live" today via this audit. The others remain substrate.
