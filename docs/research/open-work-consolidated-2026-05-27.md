# Open work — consolidated, 2026-05-27

Operator request 2026-05-27: capture ALL open work so the next session doesn't forget half of it. This consolidates findings from:

- [agentic-ai-pentest-second-opinion-2026-05-27.md](agentic-ai-pentest-second-opinion-2026-05-27.md) (my independent diagnosis + Appendix A with 12 verified sources)
- [agentic-ai-pentest-market-progress-diagnosis-2026-05-27.md](agentic-ai-pentest-market-progress-diagnosis-2026-05-27.md) (Codex)
- [ai-pentest-competitive-deep-dive-2026-05-27.md](ai-pentest-competitive-deep-dive-2026-05-27.md) (Codex deep-dive with NodeZero/Pentera/Terra/Synack/Cobalt)
- [task-audit-2026-05-27.md](task-audit-2026-05-27.md) (25 open SPRINT items + M1-M9 audit + replace recommendations)
- The smoke 38-47 empirical evidence accumulated this session

## A — Completed in extended session (2026-05-27 / 28)

ALL section-A items shipped + a follow-on second sprint of surgical orchestration-strip fixes per operator's "geen 4de overhaul, surgical reductie" framing:

1. ✅ **Smoke 47d/47e/48 — XBEN-002 SOLVED 3/3 STABLE**. First formal score-lane: 0/25 → 1/25 archived in `docs/validation/xbow-smoke47d/47e/48-*-2026-05-27/`.
2. ✅ **Daily-5 baseline established**: 1/5 SOLVED, 4 no-flag with diagnostics — `docs/validation/xbow-daily5-baseline-2026-05-27.md`.
3. ✅ **Subagents shipped**: `.claude/agents/smoke-monitor.md` + `.claude/agents/diagnose-no-flag.md` (active next session). Used as `general-purpose` patterns this session — produced 3 forensic diagnoses (smokes 49/50/52) and 1 root-cause analysis (XBEN-014 wrapper hang).
4. ✅ **6 surgical fix commits** addressing every operator-flagged orchestration anti-pattern:
   - `bb2fd36` — emit_finding kwarg-tolerant + budget-guard on next_best_action_selector + 2 vuln-class skills (SSTI + IDOR)
   - `4b15a36` — pre-execute compile-check on code-exec-attack
   - `d9b26b0` — wrapper skips sync /dispatch + SSTI Django-bypass skill refinement
   - `1f556a5` — credential-vault auto-populate from pre-recon-source + 2 vuln-class skills (JWT-forgery + SQLi-REST)
   - `5bc9d42` — orchestrator finalizes run on wall_clock_budget_exhausted (closes Gemini-leak)
5. ✅ **4 vuln-class skills in `docs/skills/`**: access-control-state-change-post + ssti-engine-fingerprint-then-escape + jwt-none-and-disclosed-secret-forgery + sqli-rest-api-error-and-blind.
6. ✅ **Wave 3 empirical validation** (smokes 55/56/57): detection delta on the 4 unsolved daily-5 targets: **7 findings (pre-fix) → 22 findings (post-fix)**, 3.1× increase. Wrapper-dispatch-skip unblocked XBEN-014 and XBEN-020 entirely (previously stuck/crashed, now run to completion).
7. ✅ **Wave 4 in flight** (smokes 58/59) at end of session: testing credential-vault auto-populate fix (post-restart) on XBEN-009 + XBEN-005.

**Score-lane status at session end**: 1/5 SOLVED (XBEN-002 STABLE). Detection on 4 unsolved improved 3.1×. New bottleneck = exploit-craft sophistication (Phase B escape patterns), NOT infrastructure.

## B — Score-lane critical (1-2 weeks)

Ranked by ROI per developer-hour against the daily-5 metric.

1. **Skill-pack A/B integration** (existing scaffold in `docs/skills/`). Wire `AEGISPT_SKILL_PACK_ENABLED` env-gate into `_AI_PICKER_SYSTEM_PROMPT`. A/B: same 5 XBENs, same provider, with vs without skills. **Empirical backing: transilience 89%→100% on Claude Sonnet 4.6, AWE paper +30.5% XSS / +33.3% blind-SQLi with vuln-class pipelines.**
2. **M2 verdict gate DROP-PATH live test**. Substrate shipped (commit pre-session); only KEEP-path ever exercised. Need a FALSE_POSITIVE classification observed in production. Acceptance: 1 finding marked `drop=True verdict=FALSE_POSITIVE` in api log.
3. **Daily-5 scorelane harness** (#371 from TASK_QUEUE). Pin 5 fixed XBENs, one provider, one commit-improvement-rule per day. Transilience-style 15-iter loop.
4. **Local-qwen throughput fix**. Smoke 46 proved path works but 27B IQ3_M is too slow. Two paths:
   - Download Qwen3.6-8B Q4_K_M (~5GB, 30 min) → 3-4× faster, picker prompt fits
   - Slim picker prompt for local-qwen branch to <3KB (1 day work, separate sprint)
5. **Cache hit-rate observability follow-through**. `a810f0d` adds per-site logging. After next smoke, parse the new `PROOF_EXEC_ANTHROPIC_USAGE_2026052712` log lines + compute average hit_pct per site. Cache_creation costs 1.25× input — if a site is mostly creating (not reading) we're paying MORE, not less.

## C — Strategic replace (the bigger reorderings)

From [task-audit-2026-05-27.md](task-audit-2026-05-27.md) replace recommendations, ranked by ROI:

1. **LiteLLM migration (#367)** — collapse 4 hand-rolled provider adapters (Anthropic / OAuth / Gemini / local-qwen) into 1 SDK. **1-2 days, saves weeks of future maintenance.**
2. **Domain-coverage 7→1 task** — wrap OWASP Nettacker / radare2 / pwntools / linpeas / apktool / class-dump / Ghidra-headless as subprocess runners under our scope gates instead of porting them. **Saves 4-6 weeks of port work**, inherits upstream maintenance.
3. **PentAGI observability compose adoption (#357)** — adopt their OTel + Langfuse + Grafana + Jaeger + Loki stack via compose-file. License AGPL-3 (sidecar usage OK). **2-3 days vs 2-3 weeks.**
4. **PentAGI Adviser-mentor stuck-state pattern (#365)** — auto-intervene on 5-identical-tool-calls. Our `failure_analysis.py` should do this but doesn't aggressively. **1 week.**
5. **AWE memory + browser-backed verification (#364)** — Playwright + pgvector retrieval injected at exploit-developer time. Paper-backed +30% on XSS / +33% on blind-SQLi. **2 weeks once M5 substrate exists.**
6. **TAP attack tree node-format alignment (#362)** — adopt the Tree-of-Attacks-with-Pruning schema (Mehrotra+ 2024, [arxiv 2312.02119](https://arxiv.org/abs/2312.02119), [github RICommunity/TAP](https://github.com/RICommunity/TAP)) so future hypothesis-trees can be shared with the research community.

## D — Frozen / deprioritized (don't promote until daily-5 moves)

Per operator decision 2026-05-27 ("geen 4de overhaul"):

- **25 open SPRINT items** in TASK_QUEUE.md (mythos-exploitation-foundation/parity/domain-coverage/continuous-improvement). Bevroren tot score-lane beweegt.
- **388 backlog packages**. Geen promotion naar NEXT_TASK.md.
- **DEFERRED items from May 15** (#306-#317, ~10 items). Reconsider-flag is set; do not re-pick this session.
- **M5 episodic memory (pgvector)** — wait until daily-5 produces SOLVED chains worth memorizing.
- **M7 two-phase agents** (analysis + exploit separation) — Shannon's design, may be obviated by M1 if revisions are aggressive enough.

## E — Quality / observability follow-ups (small but worth not losing)

These came up during today's session but were not full sprints:

1. **Picker `tool_uses_called` canary investigation**. Per session-summary, in 175k log lines, 0 `execute_tool_call` invocations on Claude. The picker has tool-use semantics wired but never exercises them. Investigate why — prompt may discourage tool calls. (#370 dependent.)
2. **`provider_kind=unknown` cosmetic in logs**. Pre-session fix `f260a4b` addressed Gemini; verify all four paths now log accurate `provider_kind` (anthropic, chatgpt_oauth, gemini, local_qwen).
3. **Per-provider daily request counter** — already in TASK_QUEUE Discussion as a follow-up to Gemini's 1106-429 incident. Warn at 200, hard-stop at 240.
4. **Source-aware vs black-box scoreboard separation** — track and report two metrics separately. The May-21 baseline conflates them.
5. **`no-exploit-no-report` enforcement at report export** — findings storage can keep hypotheses; report export must filter to `verified_exploited` OR explicit `unverified`. M2 verdict gate is the substrate; the export-time filter is not yet wired.
6. **Credential-vault auto-populate from pre-recon-source/CPG (operator-flagged 2026-05-27)**. The pattern: `pre_recon_source` detects `username='test' password='test'` literals in source; those creds go into the CPG-CEA prompt as `SEED CREDENTIALS` and into the `code-exec-attack` script context — but **NOT into the credential vault**. Downstream runners that REQUIRE creds (`session-security`, `auth-flow`, IDOR-bac, password-reset, account-takeover) all SKIP silently with messages like `session-security skipped: requires a configured username/password credential context`. The credentials are right there in the artifact, not wired across. Fix: pre-recon-source emits a "seed_credentials" structured field; the orchestrator persists them into the credential vault for the run; session-security et al. consume them automatically. (Also surfaces in 47d SOLVE — only CPG-CEA used the creds; all 5 cred-dependent runners were dead-ends in the same run.)
7. **Default nuclei template `aegispt-http-status-200` produces info-only noise** (operator-flagged 2026-05-27). It matches HTTP 200 = "target reachable" and emits a finding. Doesn't influence mission state (info filtered out of `deriveMissionState`) but clutters output. Replace with a template that scrapes HTML comments / form fields / `Server` headers / `meta` tags for cred / version leaks. The recon-deliverable runner already has the regex pattern (line 75) — surface it via a nuclei template too OR ensure recon-deliverable runs in every loop (today it gets bypassed on source-aware runs where CPG path takes priority).
8. **Injection-class verification re-prober strategies — close the false-positive leak** (operator-flagged 2026-06-02 reliability review). [capability] **[SQLi DONE 2026-06-02 — commit `99f114c`, run `208e2530`: 3 smart-web-probe SQLi FPs dropped FALSE_POSITIVE; evidence `docs/validation/xbow-e8-sqli-reprover-2026-06-02/`. SSTI/deserial/SSRF/cmd-injection re-provers REMAIN.]** **Problem:** `finding_verifier._select_strategy` only has independent re-prover strategies for `admin_access` / `stored_xss` / `info_disclosure` (+ the deterministic flag-proof exemption). Every other critical/high finding returns `inconclusive` → the M2 verdict gate classifies it `UNCLASSIFIED` → it is KEPT, never auto-dropped. So false positives in unverified classes leak to the operator. Observed live: `smart-web-probe` emitted **false-positive critical "SQL Injection"** on XBEN-014 AND XBEN-005 (apps with no SQL); both stayed `UNCLASSIFIED` (not dropped) and also spawned dead `sqlmap` dispatches. **Goal:** add bounded, scope-allowlist-gated re-prober strategies for the injection classes — SQLi (injected vs control response diff), SSTI (benign `{{7*7}}`→`49` probe), insecure-deserialization, SSRF, command-injection — so the verifier returns a CONCLUSIVE `confirmed`/`failed`, letting the M2 gate drop genuine false positives (failed + no replay) instead of leaking them. Also lower `smart-web-probe`'s over-eager critical SQLi emission (require a server-side-effect signal, not just a reflected error string). **Acceptance:** on a no-SQL target a smart-web-probe "SQL Injection" finding is conclusively `FALSE_POSITIVE` and dropped by the gate (cite run + `PROOF_EXEC_M2_VERDICT_GATE` marker); no regression in `test_m2_verdict_gate.py` / `test_finding_verifier_*`. **Files:** `api/app/services/finding_verifier.py`, the smart-web-probe runner. (Relates to E#5 no-exploit-no-report.)
9. **Honest reliability + false-positive + coverage documentation** (operator-flagged 2026-06-02). [docs] **[DONE 2026-06-02 — commit af426fb: docs/reliability-and-false-positives.md, linked from AegisPT.md + methodology_mapping.md]** Write `docs/reliability-and-false-positives.md` (NL+EN) covering: (1) the tiered reliability model — captured-flag/`DETERMINISTIC_PROOF` = hard grader-matchable proof; the 3 re-proven classes = high; everything else = `UNCLASSIFIED`/operator-review; (2) the 3 false-positive mechanisms (pre-persistence re-prober, M2 verdict gate, manual `false_positive_reason`/`validation_status` fields) AND the `inconclusive→UNCLASSIFIED` leak gap (E#8); (3) the coverage-honesty caveat — test execution is AI-picker + tool-orchestration driven (emergent), NOT a systematic WSTG-checklist engine, so coverage is not exhaustive-by-construction; (4) compliance frameworks (SOC2/ISO27001/PCI/NIS2/DORA/TIBER) are report-time mapping VIEWS, not certifications; (5) an explicit customer-facing "do NOT claim" list. **Acceptance:** doc exists, cross-checked against `finding_verifier.py` strategies + `m2_verdict_gate.py` verdicts + `methodology_mapping.md`, and linked from `AegisPT.md` + `docs/methodology_mapping.md`.
10. **Flag-capture recognition must cover ALL tools, not just interactive-exploit** (found 2026-06-02 on XBEN-020). [capability — reliability] **[DONE 2026-06-02 — run `7efba83e` canonicalized XBEN-020; evidence `docs/validation/xbow-e10-anytool-flagcapture-2026-06-02/`]** **Problem:** the canonical-solve machinery is interactive-exploit-centric. On XBEN-020 (SSRF), `smart-web-probe` extracted the grader flag via the SSRF and the harness marked `solved=true` — but (a) NO `Flag captured` finding was persisted (all 6 findings are SSRF *vulnerability* findings; the flag lives only in the tool-execution stdout), (b) `check_finding_persistence_invariant.py` PASSED VACUOUSLY (`captured flags: 0` — it only queries `tool='interactive-exploit'`), and (c) NO early-stop fired (`loop_stop_reason=""`, full ~1582s budget burned, because early-stop keys off `interactive-exploit.captured_flags`). So a genuine solve is invisible to the findings/report surface, the solve-canary, and budget control. This is the "solve seen but not in findings" class the invariant was meant to guard — but the guard only watches one tool. **Goal:** a post-task flag-scan (reuse the `_FLAG_RE` pattern: `xbow-…` / `flag{…}` / `aegispt{…}`) over EVERY tool execution's stdout; on a match persist a canonical `Flag captured` finding (`evidence_ref` → that exec, `target_id` → scope, methodology tag), trigger run early-stop, and extend `check_finding_persistence_invariant.py` to validate captures from any tool. **Acceptance:** re-run XBEN-020 → a persisted `Flag captured` finding + non-vacuous invariant PASS + early-stop (run < budget), making it a canonical solve (cite run + finding id). **Files:** `api/app/services/assessment_loop.py` (post-task flag-scan), `scripts/check_finding_persistence_invariant.py`. Evidence: `docs/validation/xbow-daily5-020-2026-06-02/`.

## F — Externally-owned items (operator action needed)

These I cannot ship; the operator must act.

1. **OpenAI Trusted Access for Cyber program** — application submitted, no response. Until approved, OAuth `cyber_policy` filter blocks heavy offensive prompts. (See [oauth-cyber-policy-block-2026-05-26.md](oauth-cyber-policy-block-2026-05-26.md) and `feedback_no_prescriptive_recipes` memory note.)
2. **Anthropic credit-top-up cadence** — operator added €20 today; €3,10 spent already. Decide on per-week budget and surface it as `AEGISPT_RUN_BUDGET_SECONDS` default + per-engagement budget overrides.
3. **Trusted Access timing** — once OpenAI approves, the OAuth defensive-prompt path (6b0ac53) becomes redundant for the picker. The defensive-prompt code is harmless to keep; could simplify later.

## G — What this session SHIPPED (so the next session knows what's already done)

Commits today, in order:

| Commit | What | Tests |
|---|---|---|
| 90da522 | Gemini 429 fail-fast guard (1h backoff) | 4 green |
| 13e553f | OAuth `response.completed` fallback parser | 4 green |
| d500a53 | OAuth missing logger import bug | tests already green |
| 942f21f | OAuth error-event capture (`cyber_policy` reason surfaced here) | 3 added, 7 green total |
| f9a598b | Doc: OAuth `cyber_policy` block diagnosis | doc-only |
| 614c0e3 + 648ee3b | Doc: Gemini daily quota block | doc-only |
| e3b05ae | Local-qwen picker + specialists branch + Qwen `<think>` stripper | import sanity |
| 441a415 | Live CLI screen (/live-cli route) + export of LiveTaskDrillDown + LiveEventsFeed | tsc clean |
| 939559e | Doc: independent second-opinion + 12-source WebFetch appendix | doc-only |
| 6b0ac53 | OAuth defensive-framed CPG-CEA prompt | not yet smoke-tested |
| d5cccea | Wrapper iterate explicit timeout 600→1800s | manual |
| bdcd3e9 | Wrapper client-default timeout 600→1800s | manual |
| 5a0ac46 | **Hard wall-clock budget guard** on picker + CPG-CEA dispatch | 8 green |
| a810f0d | Cache hit-rate logging across 3 missing call sites | compile clean |
| 1c621e1 | Doc: open + DONE task audit (this doc's parent) | doc-only |

Test posture: **19 unit tests added this session, all green.**

## H — Hard discipline rules (operator-set this session)

1. **No 4th overhaul.** The architecture is fine. Discipline failure has been the problem. (Operator stated 2026-05-27.)
2. **No idle waiting.** Always finish inline OR hand operator a concrete next-action.
3. **Don't claim DONE on substrate-only**. Per audit, 8 of 9 M-items overstated. New rule: `substrate-shipped` ≠ `live-proven`.
4. **Hard wall-clock budget** on every cloud-LLM-using run. Default 1800s. Wrapper plumbs `--wait-seconds` into `wall_clock_budget_seconds`. Operator can override per-run via env or config.
5. **Cache hit-rate must be observable, not inferred**. Logging now in place; next smoke produces the numbers.

## What this means for the next session start

When the next Claude/Codex/operator session opens this repo:

1. Read this doc first.
2. Check `NEXT_TASK.md` for the immediate active task.
3. Don't promote anything from `TASK_QUEUE.md` (frozen).
4. Don't start a 4th overhaul — even if the architecture looks tempting.
5. Focus on score-lane delta on the daily-5 subset.
