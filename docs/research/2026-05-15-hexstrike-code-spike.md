# HexStrike AI Code Spike — Per-Task Comparison

**Date**: 2026-05-15
**Author**: spike during Mythos-convergence planning session
**Context**: Operator pushed back on the assumption that "we build the auth-discoverer at least as well" and asked for a real code-level comparison before committing to the 17-task plan.

## Scope of this spike

Cloned `0x4m4/hexstrike-ai` shallow under `/tmp/hexstrike-spike/`. Read the relevant code paths instead of installing the server. The repo is two monolithic Python files:

- `hexstrike_mcp.py` — **5,470 lines**. MCP layer using `fastmcp`. 151 `@mcp.tool()` decorators. Single `setup_mcp_server()` function spans lines 267-5415 (~5,148 lines) — all tools registered inside.
- `hexstrike_server.py` — **17,289 lines**. Flask backend that does the real tool execution.

Total: 22,759 lines. Not "150 modular tool servers" as the marketing implies — it is one Flask server with 150 tool endpoints, fronted by one MCP layer that translates MCP calls into HTTP.

## What this changes about the "fork and integrate" story

A monolithic 22k-line Python project is fundamentally different from a modular MCP server ecosystem. Cherry-picking one tool wrapper means:

- Lifting code from `hexstrike_server.py` (which has its own helpers, classes, logger, color engine, dependency assumptions)
- Lifting corresponding code from `hexstrike_mcp.py`
- Or running the entire Flask server as a sidecar and consuming its HTTP API

There is no clean "fork the Nmap wrapper" operation. You either take a lot, take a sidecar, or read-and-reimplement.

---

## Per-claim verification

### Claim 1: "HexStrike has a real auth discoverer"

**Verified: PARTIALLY false.**

The MCP tool `bugbounty_authentication_bypass_testing` (mcp.py:5092) is a **static lookup table**. The entire function body:

```python
bypass_techniques = {
    "form": [
        {"technique": "SQL Injection", "payloads": ["admin'--", "' OR '1'='1'--"]},
        {"technique": "Default Credentials", "payloads": ["admin:admin", "admin:password"]},
        ...
    ],
    "jwt": [ ... ],
    "oauth": [ ... ],
    "saml": [ ... ]
}
return {"success": True, "workflow": {...}, "manual_testing_required": True}
```

It accepts `target_url` but does not fetch it, does not parse forms, does not execute anything, does not establish a session. It returns a JSON cheatsheet of advice strings. The flag `manual_testing_required: True` is in the response.

This is **not auth discovery**. This is documentation as a function call.

### Claim 2: "HexStrike's BrowserAgent does form interaction"

**Verified: PARTIALLY true — passive only.**

`BrowserAgent.navigate_and_inspect` (server.py:13672) uses Selenium to:

- Navigate to URL
- Take screenshot
- Extract: `forms, links, inputs, scripts, cookies, local_storage, session_storage, network_requests, console_errors`
- Perform `_analyze_page_security` (cookie flags, CSP, headers — passive checks only)

It does **not** submit forms. It does **not** register accounts. It captures DOM state and analyzes it.

`BrowserAgent.run_active_tests` (server.py:13819) does limited active testing: comment says **"safe mode. Only GET forms with text inputs to avoid state-changing operations."** It only tests reflected XSS by appending a payload to GET form params and checking if it appears in the response. Maximum 5 forms per page.

This is **discovery + passive analysis + GET-only reflected-XSS check**. It is explicitly designed NOT to do active auth flows.

### Claim 3: "HexStrike has Safe Mode, scope guards, audit logging"

**Verified: FALSE.**

`grep -cn 'safe_mode|scope_check|allowlist|audit' hexstrike_server.py` → 1 match. That match is `--script=default,discovery,safe` (an nmap CLI argument).

`grep` on the MCP file returns 27 hits — all are `safe_get` / `safe_post` HTTP wrappers (network error handling, not security). One reference to "safe mode" is the comment in `run_active_tests` (which only means GET-only).

There is **no scope allowlist enforcement** anywhere in the codebase. No audit log of tool executions. No approval gate. No intrusive-tier system. No kill switch.

Check Point's critique is accurate: governance is genuinely absent.

### Claim 4: "Our existing xss_proof has equivalent or better auth flow"

**Verified: TRUE — for the specific function of auto-creating test accounts on unknown apps.**

`workers/runners/xss_proof/runner.py`:
- `_ai_analyze_auth(base_url, page_html)`: calls Claude Haiku with HTML, returns ordered HTTP request steps for registration with type-specific guidance.
- `_try_register_with_ai(client, base_url, page_html)`: executes those steps, captures cookies, returns session info.

This is **actual AI-driven account creation on an unknown stack**. HexStrike does not have this. Their browser agent extracts forms but never submits them. Their bypass-testing tool returns a cheatsheet.

### Claim 5: "HexStrike has credential cracking we lack"

**Verified: TRUE.**

HexStrike exposes mature wrappers we do not have:
- `hydra_attack` — credential brute-force (we have nothing equivalent for password spraying)
- `john_crack` — John the Ripper integration
- `hashcat_crack` — Hashcat integration
- `evil_winrm` — Windows credential abuse (mentioned in README; need to verify in code)

We have credential vault for managing captured creds but no offensive cracking suite.

### Claim 6: "Their `select_optimal_tools_ai` is a better picker than ours"

**Not verified — needs separate read.** Filed for follow-up if path requires.

---

## What HexStrike actually adds (objectively)

Even with the spike's findings, HexStrike has genuine value:

1. **Tool inventory breadth**: 151 tools wrapped, several specialized areas we don't cover:
   - Binary analysis (Ghidra, Radare2, GDB, IDA-via-Pwntools, angr, ROP gadget search, libc database)
   - Forensics (Volatility, Foremost, Steghide, Exiftool)
   - Credential cracking (Hydra, John, Hashcat)
   - SPA/JS-heavy reconnaissance (Selenium-based, deep DOM)
   - Active recon (Subfinder, Amass, Katana, GAU, Waybackurls, ParamSpider)

2. **JS-rendered app handling**: their `BrowserAgent` handles SPA's. Our HTTP-based probes miss apps where forms load via JavaScript.

3. **Working code for tools we lack**: even without their MCP server, the tool invocation logic itself (how to call Nmap with the right flags, parse output, etc.) is valuable reference.

4. **MCP server scaffolding pattern**: the fastmcp-based registration pattern. We could mirror this for our own MCP servers.

## What HexStrike does NOT have (objectively)

1. **Account creation discoverer for unknown apps** — we are clearly ahead in `xss_proof._ai_analyze_auth`
2. **Pattern cache across runs / cross-engagement learning** — neither has this; our planned task #327 is genuinely novel
3. **Cross-runner verifier for critical findings** — our planned task #335 is novel
4. **Compliance reporting structure** (PTES / OWASP WSTG / NIST mapping)
5. **Scope allowlist enforcement** at the tool-call boundary
6. **Intrusive-tier governance + operator approval workflow**
7. **Audit chain / evidence integrity hash chain**
8. **Comic-strip narrator for non-technical operators**
9. **Capability pack lifecycle / version pinning**
10. **Per-engagement run isolation** (their server is single-process, no container sandboxing per session)

## Per-task forken-vs-bouwen verdict for the 17 Mythos tasks

| Task | Title | Verdict | Reason |
|---|---|---|---|
| #321 | Evidence-graph adoption audit | **Build (ours)** | Audit is repo-specific. Output is OUR adoption plan, not externalizable. |
| #322 | Evidence-graph ingestion helpers | **Look at PentAGI first** | PentAGI's pgvector+Graphiti memory layer is more mature than building our own. Spike PentAGI's approach before deciding. |
| #323 | Picker reads evidence-graph | **Build (ours)** | Tightly coupled to our picker design. No upstream equivalent for our context-projection problem. |
| #324 | Phase 1 review checkpoint | **Build (ours)** | Process work. |
| #325 | Auth discoverer: form detection | **Build (ours, generalize xss_proof)** | HexStrike's form extraction is passive-only Selenium. Our xss_proof already does the harder thing (AI auth analysis). Generalize what we have. |
| #326 | Auth discoverer: AI recipe builder | **Build (ours, generalize xss_proof)** | We are ahead of HexStrike here. xss_proof's pattern is a working reference. |
| #327 | Auth pattern cache | **Build (ours, novel)** | Neither HexStrike nor PentAGI has this. Genuine differentiator. |
| #328 | Migrate 5 probes to auth discoverer | **Build (ours)** | Our codebase. |
| #329 | Phase 2 review checkpoint | **Build (ours)** | Process work. |
| #330 | Picker structured outputs | **Build (ours)** | Anthropic feature, ours to integrate. |
| #331 | Loop soft retry | **Build (ours)** | Engineering concern in our code. |
| #332 | Memory tool truncation | **Build (ours)** | Cost optimization on our memory backend. |
| #333 | Phase 3 review checkpoint | **Build (ours)** | Process work. |
| #334 | Cross-target provenance | **Cherry-pick PentAGI's task graph design** | PentAGI's "Penetration Task Graph" is exactly cross-target provenance, more mature. Worth studying before designing ours. |
| #335 | Cross-runner verifier | **Build (ours, novel)** | Neither competitor has this. Strong differentiator. |
| #336 | SMB / LDAP exec_plan primitives | **Fork from HexStrike OR reimplement** | HexStrike has SMB/LDAP tool wrappers we lack. Either lift from their Flask server (license MIT, reasonable) or reimplement using impacket directly (we already have impacket as runner). Decision should be after spike of their wrappers. |
| #337 | Final demo | **Build (ours)** | Process work. |

**Summary**: 14 of 17 tasks stay as planned. **#322 and #334** should look at PentAGI for design lessons before building. **#336** is the only task where fork-from-HexStrike is potentially the better path.

## Strategic recommendation revision

The original concern was "are we duplicating substantial functionality". Spike result: **mostly no**. HexStrike's strengths are areas we either explicitly don't cover (credential cracking, binary analysis, forensics) or where they take a complementary approach (passive Selenium discovery vs our active AI-driven HTTP). Their weaknesses (governance, account creation, pattern learning, cross-target chains) are exactly where we plan to invest.

The one place we'd save real work by forking is **specialized tool wrappers we don't have** — Ghidra, Volatility, Radare2, Hydra. These are not in the 17 Mythos tasks. They'd be **a separate parallel track** ("Specialized Tool Pack" — fork wrappers for tools outside our current coverage).

## Recommended additional task (NOT in the original 17)

**#338 (new): Specialized Tool Pack — fork HexStrike wrappers for tools we lack.**

Scope: identify 10-15 tools in HexStrike that we lack and that are useful (Ghidra, Volatility, Radare2, Hydra, Hashcat, John, Pwntools, angr, libc-database, Foremost, Steghide, Subfinder, Amass, Katana, ParamSpider). Lift the invocation logic from `hexstrike_server.py` into our runner contract, add scope check + audit + intrusive-tier guard at the runner boundary. Attribute MIT license. Result: ~10-15 new runners in our codebase that extend coverage to areas HexStrike has and we don't.

Estimated effort at AI tempo: **3-5 days**. Adds significant breadth to our tool surface without changing our architecture.

This task could be inserted BEFORE Phase 4 (after #333) or run in parallel.

## What the operator should decide

Three concrete asks:

1. **Confirm verdict**: keep the 17 tasks as planned, with #322 + #334 noting "study PentAGI design first" and #336 noting "consider fork".
2. **Add #338**: the specialized-tool-pack task.
3. **PentAGI spike**: should I do a similar code-level spike on PentAGI for #322 and #334, before committing those tasks?

## Appendix — files inspected

- `/tmp/hexstrike-spike/hexstrike_mcp.py`:5092-5160 — bugbounty_authentication_bypass_testing
- `/tmp/hexstrike-spike/hexstrike_mcp.py`:5198-5280 — browser_agent_inspect + http_framework family
- `/tmp/hexstrike-spike/hexstrike_server.py`:13623-13885 — BrowserAgent class (navigate_and_inspect, run_active_tests, _extract_forms)
- `/tmp/hexstrike-spike/hexstrike_server.py`:14136-14250 — browser_agent_endpoint
- `/tmp/hexstrike-spike/requirements.txt` — dependencies
- `/tmp/hexstrike-spike/hexstrike_mcp.py:267-5415` — single setup_mcp_server function
- Grep coverage: safe_mode, scope_check, allowlist, audit, auth, login, register, browser_agent

Spike clone retained at `/tmp/hexstrike-spike/` for the duration of this session.
