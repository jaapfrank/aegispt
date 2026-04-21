# AegisPT — Product Recommendations & Competitive Gap Analysis

**Date:** April 2026  
**Scope:** Full product review covering UI/UX, live operations, missing capabilities, AI opportunities, and competitive positioning  
**Competitive reference:** Horizon3.ai NodeZero, Pentera, Cobalt, Cymulate, XM Cyber, BreachLock, SafeBreach, Picus, HackerOne, Synack, Hadrian

---

## 1. Market Context

The market category has formally shifted. Gartner published the **2026 Market Guide for Adversarial Exposure Validation (AEV)** in March 2026, replacing the older BAS and Automated Pentesting categories. The new category merges: BAS + automated pentesting + attack path management + remediation orchestration into a single platform expectation.

By 2029, Gartner projects 60% of organisations will have formal exposure validation practices. The market is valued at $2.74B (2025), growing at 12–15% CAGR. Cloud testing is the fastest-growing modality at 16.63% CAGR.

**The product race in 2026 is:**
1. Agentic AI that autonomously executes, pivots, and chains exploits
2. Remediation orchestration that closes the loop from finding to verified fix
3. Attack path intelligence that shows choke points, not just findings
4. MCP server / LLM integration for natural language access to everything
5. AI attack surface testing (shadow AI, LLM apps, MCP servers in the target environment)

AegisPT has strong foundations that align with this direction. The evidence-first architecture, supervised AI build lane, and methodology alignment are genuine differentiators. But several critical capability layers are missing and the user experience needs substantial work before the product can compete commercially.

---

## 2. Current Strengths — What to Protect

Before listing gaps, the things that are architecturally ahead of most competitors:

**Evidence provenance model.** Hash-bound artifacts, replayable findings, exact run inputs, pack version tracing, methodology alignment per finding. No commercial competitor in this space exposes this at this depth.

**Supervised AI build lane (Codex).** AI proposes packs, human reviews, validation gate, promotion, immutable deployment artifact. This is more honest and auditable than the "AI-powered" black boxes marketed by Pentera and Cymulate.

**Methodology alignment per finding.** PTES + OWASP WSTG + NIST 800-115 + ASVS per finding, structured into the data model, not bolted on as labels.

**Open tool stack.** ZAP, Nuclei, Nmap, Semgrep, Playwright — real tools with known behaviors. Security teams can audit exactly what runs.

**Single operator flow.** Intake → discovery → pack generation → validation → evidence → report without tool switching or losing provenance.

These are the things to build on, not to compromise when adding features.

---

## 2b. Detailed Competitive Feature Comparison

### Where AegisPT is genuinely ahead of the market

| Strength | Why it matters | Competitors that lack it |
|----------|---------------|--------------------------|
| Evidence provenance per finding | Hash-bound artifact + tool version + run inputs + methodology reference. Auditor-grade reproducibility. | NodeZero, Pentera (black-box outputs), Cymulate (BAS-style, no deep artifact chain) |
| Supervised AI build lane (Codex) | AI proposes, human reviews, validation gate, immutable deployment artifact, pack provenance on every finding. More honest than "AI-powered" black boxes. | All competitors — they market AI but don't expose the generation/validation/provenance chain |
| Methodology alignment per finding | PTES + OWASP WSTG + NIST 800-115 + ASVS structured into the data model per finding | Cobalt does this manually with human testers. No automated platform does this structurally. |
| Open tool stack | ZAP, Nuclei, Nmap, Semgrep, Playwright. Operators can audit exactly what runs and extend it. | NodeZero, Pentera, Cymulate all use proprietary or semi-opaque scanning engines |
| Single operator flow without tool switching | Intake → discovery → pack generation → validation → evidence → report in one product | Most competitors split across BAS + PTaaS + exposure management + remediation tooling |

### Where the competition is clearly ahead

| Gap | Leader | Specific capability AegisPT lacks |
|-----|--------|----------------------------------|
| Remediation loop | Pentera Resolve, NodeZero | Proof-of-resolution, 1-click retest, SLA tracking, auto-ticket creation |
| Attack path graph | XM Cyber, Pentera | Choke point analysis, visual path chains, "fix this → closes N paths" intelligence |
| Enterprise integrations | Cobalt (50+), Pentera (100+) | Zero integrations — findings stay inside the platform |
| Continuous / scheduled validation | NodeZero, Cymulate, Cobalt | Every competitor offers scheduled recurring scans |
| Cloud / IAM attack surface | Pentera Cloud, NodeZero, XM Cyber | No AWS/Azure/GCP runners, no IAM testing, no Kubernetes |
| Active Directory testing | NodeZero (GOAD-solved), Pentera Core | Nmap discovery only — no LDAP, no Kerberoasting detection, no AD abuse |
| AI / LLM application testing | HackerOne, Cobalt, Synack | No prompt injection testing, no shadow AI detection |
| Compliance report packaging | Pentera, NodeZero, BreachLock | Methodology alignment exists but no SOC2/ISO27001/PCI DSS formatted exports |
| Agentic AI copilot | Pentera (Peer), NodeZero (HVT) | Wizard is good but AI does not adapt or recommend during execution |
| MCP server / LLM integration | NodeZero, SafeBreach | No natural language access to findings or run management |
| Multi-tenancy / MSSP | NodeZero, Cobalt | Single-tenant only |

---

## 3. UI/UX Recommendations

### 3.1 Fix the font stack immediately (30 minutes)

`Bahnschrift`, `Aptos`, `Segoe UI Variable` do not exist on macOS, Linux, or Windows without Office 2021+. Every non-Windows operator sees generic `sans-serif`. This silently breaks the visual identity.

**Fix in `ui/assets/styles.css`:**

```css
/* Replace current body font-family with: */
font-family: "Inter", system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;

/* Add to <head> in index.html: */
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
```

Same fix needed for heading font — `Bahnschrift` is Windows-only. Replace with `Inter` at `font-weight: 700`.

Inter is what Pentera, Cobalt, and most enterprise security products use. It reads as serious without being clinical.

---

### 3.2 Consolidate from 8 screens to 5

Current navigation: Intake → Mission Control → Surface Map → Pack Status → Findings → Evidence Replay → Reports → Explorer → History. That is 8 context switches for a first-time operator.

**Changes:**

- **Merge Evidence Replay into Findings Theater.** Evidence is already co-fetched with finding detail. Show it as an expandable panel within the finding card, not a separate screen. This is the highest-friction navigation in the product — selecting a finding and immediately needing to go elsewhere to see its evidence is broken.

- **Merge Explorer into Report Center.** The Run Dossier (the unique part of Explorer) belongs as a "Run Context" tab in Report Center. The Customer Index and Engagement Dossiers are redundant with the persistent engagement dropdown.

- **Keep:** Intake, Mission Control, Surface Map, Findings Theater (with embedded evidence), Report Center (with run dossier tab).

**Result:** 5 screens. The phase navigation (Intake → Execution → Analysis) already groups them correctly. The sub-nav per phase becomes clean.

---

### 3.3 Surface Map — make it actually show something

The `surface-map-canvas` div is empty without inventory. This is the first screen operators go to after discovery, and it shows nothing.

**Minimal implementation (no external library, uses existing inventory data from `state.mission.inventory`):**

Render a grid of host cards in the canvas area. Each card shows:
- IP / hostname
- Open ports as small badges
- Detected services (nginx, Apache, SSH, etc.)
- Worst finding severity as a colored left border (green/amber/red)
- Technology fingerprints from `vendor_product_fingerprints`

Click a card → populates the existing `surface-asset-detail` panel.

**D3 force-directed graph (the real wow — 2–3 days, D3 from CDN):**

Nodes = discovered hosts, sized by finding count, colored by worst severity. Edges = network relationships within same CIDR. Tool icons on left edge. Animated scan beams during active runs (see Section 4). Click to select. This is the image that makes someone pull out their phone.

---

### 3.4 Add first-run onboarding

When `state.engagements.length === 0`, the operator sees a blank wizard with no context. Add a single-sentence callout above the wizard: **"Start by describing your mission in plain language below."** with an arrow. This is the most common first impression and currently the worst moment in the flow.

---

### 3.5 Empty states across all panels

Every panel that can be empty needs a helpful empty state — not a blank div. Pattern: short sentence explaining what will appear here and what action leads to it. Example for Findings Theater: "No findings yet. Run a validation to see results here." Example for Surface Map: "No hosts discovered yet. Run a network discovery scan to map this environment."

---

### 3.6 Visual design ceiling — tone down the scan-grid aesthetic

The dark navy aesthetic with orbit blobs and scan-grid background works in a demo. In a boardroom or enterprise procurement review, it reads as "hacker cosplay." The current direction of "quieter information hierarchy" in CURRENT_STATE.md is right — continue that path. The scan-grid and orbit blobs should be reduced further in opacity or made toggleable. Pentera and Cobalt both use clean dark dashboards without ambient scan effects, and they close enterprise deals.

The colour semantic system (cyan = info, amber = warning, red = critical, green = resolved) is well-designed and should stay. The panel structure with eyebrow/heading/subcopy hierarchy is solid. What needs to reduce is the decorative ambient layer.

---

### 3.7 Architecture concern — vanilla JS state management ceiling

The current module structure (`app.js` → `wizard.js`, `mission-control.js`, `findings.js`, etc.) is cleaner than most vanilla JS projects at this scale. The `dom.*` reference pattern and `renderAll()` approach work.

However, the shared mutable `state` / `runtime` object in `runtime.js` is already showing strain. `app.js` is 1,196 lines. `aggregateInventorySnapshotsForUi()` alone is 120 lines inside `app.js`. As attack-path visualization, remediation tracking, and real-time SSE feeds are added, managing DOM state manually will cause increasingly hard-to-trace bugs.

**Recommendation:** Do not migrate to React — that is 3+ weeks of neutral work. Instead, before adding the next major feature (attack path graph, remediation screen), migrate state management to a small observable store pattern. Two options:
- **Preact Signals** (2KB, drop-in): `signal()` and `computed()` replace the shared mutable `state` object. Components re-render only when their specific signals change.
- **Vue 3 Composition API** (incremental migration): Start mounting individual screens as Vue components while keeping the rest vanilla. Vue 3's Composition API is close enough to the existing pattern that migration is screen-by-screen.

Either approach prevents the state management from becoming the blocking constraint when the feature list grows.

---

### 3.8 Stop re-fetching all run findings on every engagement refresh

In `app.js` line 379, `refreshSelectedEngagement()` fires one API call per run in parallel to fetch findings. On a mature engagement with 10+ runs at 5-second intervals during active scans, this is 10+ calls every 5 seconds. Fetch findings only for the selected run on engagement change. Lazy-load other runs' findings on demand (history/comparison screen only).

---

## 4. Static Wow Moments — No Backend Required

These are high-impact visual changes that use data already in memory. None require new API endpoints.

### 4.1 The finding card as a classified intelligence brief

The `FindingTheaterRead` already returns `severity_rank`, `confidence_label`, `exploitability`, `business_impact`, `technical_details`, `methodology` (full PTES + WSTG + NIST + ASVS), `risk_snapshot`, `next_steps`, and `verification_status`. All of this is currently rendered as paragraph text and badge lists.

**The risk gauge.** `risk_snapshot` has a calculated score. Render it as an SVG arc gauge — a half-circle meter with red sector for critical range, amber for high, yellow for medium. 30 lines of inline SVG. This single element changes the visual impression of the finding card from a text document to an analytical instrument.

**The methodology chain.** Render the PTES → WSTG → NIST → ASVS lineage as a horizontal pill-chain with directional arrows:

```
[PTES: Exploitation] → [WSTG-INPV-01: SQL Injection] → [NIST: Execution] → [ASVS 4.0 L2]
```

Each pill links to the relevant standard documentation. This is a genuinely unique capability in the market — no competitor shows per-finding methodology lineage in the UI. Compliance teams get exactly what they need, displayed in a way that makes it immediately legible.

**The exploitability indicator.** `exploitability` returns `operator-validated`, `plausible`, or `limited`. Show it as a three-segment horizontal bar filling to the appropriate position — not text. One reusable CSS component.

**Business impact as a callout block.** Replace the paragraph with a left-bordered colored callout block (matching severity colour), like a GitHub admonition box. Same content, 3× more readable and visually weighted.

**Evidence status indicator.** `verification_status` returns strings like "evidence-linked and ready for replay". Render this as a coloured status dot with a short label next to the finding title. Green dot = evidence-linked, amber = needs review, grey = incomplete. Operators immediately see which findings are audit-ready.

---

### 4.2 Terminal-style evidence display

The `related_executions` on `FindingEvidenceReplayRead` already carries `tool`, `tool_version`, `exit_code`, `stdout_excerpt` (400 chars), and `stderr_excerpt`. These are currently rendered as plain text.

Replace with a styled terminal panel:

```
┌─ nuclei v3.3.1  ·  target: api.example.com  ·  exit: 0 ─────┐
│ [CVE-2023-44487] api.example.com:443 [critical]               │  ← red highlight
│ Matched: {"error":"connection reset by HTTP/2 server"}        │
└───────────────────────────────────────────────────────────────┘
```

Dark `#0d1117` background, tool name badge with accent colour per tool (cyan for nuclei, amber for zap, green for nmap), the specific matching line highlighted. Copy-to-clipboard button top-right. For ZAP findings: parse stdout to extract HTTP method, path, and response code as a structured HTTP mini-block. For nmap: format the port table.

Security operators live in terminals. Seeing real tool output in a styled terminal panel is an immediate "this is real" signal that no badge redesign delivers.

---

### 4.3 Mission launch sequence

When `submitWizard()` resolves and the run is created, `navigateToScreen()` is called silently. This is the highest-stakes moment in the operator flow and currently has no feedback.

Add:
1. A brief 1.5-second "Mission created" overlay on the wizard panel showing the engagement name, then dismiss with a fade.
2. Navigate to Mission Control.
3. The newly created run card enters with a scale animation (0.95 → 1.0 with a brief cyan border glow).
4. The "Start Validation" button pulses once to draw the operator's eye.

Zero new API calls. Pure JS timing and CSS transitions. Creates a clear psychological boundary between planning and operating that makes the product feel intentional rather than accidental.

---

### 4.4 Tool pipeline swimlanes (static, no backend)

During and after a run, render tasks as a swimlane view — one row per tool, tasks moving left to right through states. Uses existing `state.selectedRun.tasks` data from the current poll:

```
nmap    [✓ 10.0.0.0/24]  [✓ 10.0.20.0/24]
httpx   [▶ api.example.com ~~~shimmer~~~]  [✓ shop]
zap     [◌ www.example.com queued]
nuclei  [◌ shop.example.com queued]
```

State indicators:
- `queued` → gray outlined card, low opacity
- `running` → cyan border + shimmer gradient animation sliding across the card
- `completed` → green border, finding count badge if any (`+3 ⚠`)
- `failed` → red border with `✕`

The shimmer on running tasks is 8 lines of CSS and the single most effective "something is happening" signal. It creates constant visible motion without being distracting.

---

### 4.5 Live finding severity bars (no backend)

`run.findings.findings_by_severity` is already in `RunRead` and updates on every poll. Render it as horizontal bars with `transition: width 0.4s ease` so they grow smoothly as findings arrive between polls:

```
critical  ████████           3
high      ██████████████     6
medium    ████████████       5
low       █████              2
```

Track `state._lastFindingCount` before each render. If count increased, flash the total number briefly (CSS scale + amber glow animation). A single critical finding landing during a scan should feel like an event.

---

## 5. Live Operations Experience — With Backend Changes

This is currently the biggest UX gap. During an active run, the operator has no visibility into what is happening, where the system is looking, or what it has found so far. The 5-second polling refresh gives a vague task list. There is no live feel.

### 4.1 Backend: SSE event stream for active runs

**New endpoint: `GET /api/v1/runs/{run_id}/stream`**

FastAPI `StreamingResponse` with `text/event-stream`. Polls the database every 1.5 seconds, diffs against already-sent state, pushes only deltas. No WebSocket complexity. EventSource on the frontend handles reconnection automatically.

Events emitted:
- `task.status` — when any task transitions state (queued → running → completed → failed). Includes `tool`, `target`, `status`, `updated_at`.
- `finding.new` — when a new finding is created. Includes `severity`, `title`, `target`.
- `run.status` — when run status changes.
- `run.done` — terminal event; client closes the stream.

**Required change in `task_dispatch.py` (5 lines):** Move inline dispatch to a background thread so dispatch returns immediately and the SSE stream can show real progress:

```python
if dispatch_mode == "inline":
    import threading
    thread = threading.Thread(target=process_task_by_id, args=(normalized_task_id,), daemon=True)
    thread.start()
    return dispatch_mode
```

Without this, inline runs block the thread and SSE cannot show live progress.

---

### 4.2 Backend: Live stdout streaming per task

**New file: `workers/runners/base/stdout_stream.py`**

```python
import os, redis as _redis

def push_stdout_line(task_id: str, line: str) -> None:
    try:
        r = _redis.from_url(os.getenv("REDIS_URL", "redis://localhost:6379/0"))
        key = f"aegispt:task:{task_id}:stdout"
        r.rpush(key, line.rstrip("\n"))
        r.expire(key, 7200)
    except Exception:
        pass  # never block execution on streaming failure
```

**Modify all six runners** to use `subprocess.Popen` instead of `subprocess.run`, reading lines as they arrive and calling `push_stdout_line`. Each runner change is approximately 10 lines. The orchestration layer (`tasks.py`) passes `task_id` down to `dispatch_runner()`.

**New endpoint: `GET /api/v1/tasks/{task_id}/stdout/stream`**

SSE endpoint that reads the Redis list for the task, pushes lines to the client at 500ms intervals, and closes when the task is done and the buffer is drained.

---

### 4.3 Frontend: Live Ops module

Replace the 5-second polling for active runs with an EventSource connection to the SSE endpoint. New module `ui/assets/modules/live-ops.js` wraps the EventSource lifecycle.

**Three visual components in Mission Control during an active run:**

**A. Target Scan Map (SVG, replaces the blank Surface Map during execution)**

Scope targets as nodes. Tool icons on the left edge. When `task.status = running` event arrives: an animated SVG line draws from the tool icon to the target node (`stroke-dasharray` animation — the classic radar sweep effect). Target node shows a pulsing cyan ring. When `task.status = completed`: beam goes solid, node recolors to worst finding severity. When `finding.new` arrives: a ripple animation pulses outward from the affected node. Click a node → navigates to Surface Map with that asset selected.

```
  [nmap]  ════════════▶  ● 10.0.20.0/24       ← pulsing, scanning
  [httpx] ──────────▶   ● api.example.com     ← done, amber (findings)
  [nuclei]  . . . .  ▶  ● shop.example.com    ← queued
  [zap]               ● www.example.com        ← not yet targeted
```

**B. Live Terminal Panel (right side)**

Dark terminal panel (`background: #0d1117`) streaming stdout from the currently active task via the task stdout SSE endpoint. Auto-scrolls. Tool name and target in header. Lines matching `[critical]`, `CVE-`, error patterns highlighted in red/amber. Shows last 80 lines. Copy button top-right.

```
┌─ nuclei v3.3.1  ·  api.example.com  ·  running ──────────┐
│ [INF] Templates: 847 loaded, 23 matched scope             │
│ [CVE-2023-44487] api.example.com:443 [critical]           │ ← red
│ [http-missing-security-headers] api.example.com [info]   │
│ [sqli-error-based] /graphql [high]                        │ ← amber
│ _                                                         │
└───────────────────────────────────────────────────────────┘
```

**C. Live Finding Counter**

Large count that increments with a CSS scale + amber flash animation when `finding.new` fires. Severity bars grow horizontally as findings land with `transition: width 0.4s ease`. Each new critical finding plays a distinct red flash on its severity bar.

**D. Task shimmer animation (task pipeline)**

Each running task card gets a `background: linear-gradient(90deg, ...)` shimmer animation via CSS `@keyframes`. 8 lines of CSS. Constant visible motion without being distracting — confirms something is actively executing.

---

### 4.4 Activity log (state-diff generated)

Compare `tasks` array before and after each poll/SSE event. Emit human-readable log entries:

```
14:33:01  nmap started scanning 10.0.20.0/24
14:33:47  nmap finished — 29 hosts discovered
14:34:02  httpx started probing api.example.com
14:34:31  nuclei found 3 findings on api.example.com  [+3]
```

These feed into the existing `statusFeed` array and appear in the left-rail activity panel. Zero new API calls — entirely derived from state deltas.

---

### 4.5 Build order for live operations

| Step | Work | Effort |
|------|------|--------|
| 1 | Background thread for inline dispatch | 5 lines |
| 2 | SSE run events endpoint | ~60 lines Python |
| 3 | `push_stdout_line` helper + Popen in runners | ~80 lines total |
| 4 | SSE task stdout endpoint | ~40 lines Python |
| 5 | `live-ops.js` EventSource client | ~50 lines JS |
| 6 | Task shimmer CSS animation | ~10 lines CSS |
| 7 | Live finding counter + animations | ~30 lines JS + CSS |
| 8 | Target scan map SVG | ~200 lines JS |
| 9 | Live terminal panel | ~80 lines JS + 30 CSS |

**Total: approximately 3–4 days of focused full-stack work.**

---

## 5. Missing Capabilities vs Competition

These are ordered by commercial impact — what enterprise buyers most often require before signing.

---

### 5.1 Remediation Loop (Critical — blocks enterprise deals)

**What the competition has:**
- Pentera Resolve (launched October 2025, post-DevOcean acquisition): 6-step workflow — Ingest → Deduplicate → Enrich → Prioritize → Assign & Route → Revalidate. Auto-creates tickets, routes to owners, SLA enforcement, proof-of-resolution export.
- NodeZero: Continuous Find-Fix-Verify model. 1-click retest for any finding. Audit-ready proof of resolution.
- Cobalt: Unlimited automated retests. Living report model that updates as findings are resolved.
- Cymulate: Automated vendor-specific control optimization pushes.

**What AegisPT has:** Strong finding evidence and reports. No mechanism to track remediation status, schedule retests, or produce proof-of-resolution.

**What to build:**

Per-finding status lifecycle extension: `open` → `remediation_in_progress` → `remediation_review` → `resolved` → `verified`.

A `Remediation` screen (or tab in Findings Theater) with:
- Status update controls per finding
- "Schedule Retest" — creates a new run scoped to the specific finding's target and check type
- Retest run linked back to original finding (parent/child relationship in the `runs` model)
- Proof-of-resolution export: a report variant that shows original finding, remediation notes, retest run output, and verification timestamp
- "Retest All Resolved" — batch action for pre-release or audit cycles

**Why this matters:** This single feature transforms the product from "we found your problems" to "we help you prove you fixed them." Every enterprise buyer asks for proof-of-resolution. Without it, the sales cycle hits a wall.

---

### 5.2 Attack Path Intelligence (High — key demo differentiator)

**What the competition has:**
- XM Cyber: Full attack path management. Choke point analysis — only 2% of exposures sit on choke points that, when fixed, eliminate multiple attack paths simultaneously. Business-critical asset targeting. Cloud + identity + misconfiguration chaining.
- Pentera: MITRE ATT&CK-mapped attack chains. Cross-environment paths (cloud to on-prem). AI highlights which paths matter.
- Cymulate: Kill-chain scale BAS with attack path discovery.

**What AegisPT has:** `attack_paths.py` service exists in `/api/app/services/` — but it is a placeholder (6KB file, minimal content). Inventory snapshots exist. Findings are linked to targets. The data to build attack paths is already there.

**What to build:**

A graph data structure linking findings to targets to other findings, derived from existing data:

1. **Node types:** Host, Service, Finding, Credential (protected ref), Pack
2. **Edge types:** host → has_finding, finding → enables_pivot_to, host → connects_to_host (same CIDR)
3. **Choke point detection:** any node that appears in 3+ distinct paths to critical targets
4. **Visualization:** D3 or Cytoscape.js force graph on the Surface Map. Nodes colored by type. Edges colored by relationship type. Choke points highlighted with a distinct ring. Click a choke point → shows all paths that run through it and remediation impact.

The `attack_paths.py` service is the right place for this logic. The Surface Map canvas is the right place for the visualization.

Even a simplified version — a list of "if you fix this finding, it closes N attack paths" — is enough to differentiate in demos and customer conversations.

---

### 5.3 Enterprise Workflow Integrations (High — unblocks enterprise adoption)

**What competitors have:**
- Cobalt: 50+ integrations including Jira, ServiceNow, GitHub, GitLab, Azure DevOps, Slack, Teams, PagerDuty, CrowdStrike, Splunk, Vanta
- Pentera Resolve: ServiceNow, Cortex XSOAR, PlexTrac, Blink, SentinelOne — 100+ integrations claimed
- NodeZero: ServiceNow VR (March 2026), Cortex XSOAR, MCP Server (connects to any LLM)
- BreachLock: Jira, Slack, Trello

**What AegisPT has:** No external integrations. Findings exist in the platform only.

**Build in this order:**

1. **Jira** — Bidirectional: push findings as Jira issues, sync status changes back. One integration opens most enterprise doors. Use Jira REST API v3 with OAuth 2.0. Map finding severity → Jira priority. Map finding status changes → Jira issue transitions. Store Jira issue ID on the finding model.

2. **Slack** — One-way push: finding notifications to a configured channel when a run completes or a critical finding is discovered. Simple webhook. High perceived value for low effort.

3. **Microsoft Teams** — Same as Slack, via Incoming Webhook connector. Covers enterprise buyers who standardised on Teams.

4. **ServiceNow** — Bidirectional via Table API. Required for any enterprise or government buyer with ITSM workflows. Map findings to Incidents or Vulnerability Response records.

5. **Webhook (generic)** — Allow operators to configure an arbitrary HTTPS endpoint. Covers custom SOAR workflows, Azure DevOps, and anything not explicitly supported. This is the "long tail" integration that costs one day and covers dozens of use cases.

**Implementation approach:**

Add an `integrations` table to the data model: `engagement_id`, `integration_type` (jira/slack/teams/servicenow/webhook), `config_json` (credentials, endpoints — encrypted with existing `local_secret_encryption_key`), `enabled`. Add an integration sync service that fires after run completion or finding status change. Expose a `/api/v1/integrations` router for configuration.

---

### 5.4 Continuous / Scheduled Mode (Medium-High — required for "always-on" buyers)

**What competitors have:**
- NodeZero: Pentests schedulable on any recurring interval (daily, weekly, custom). Multiple concurrent pentests.
- Cymulate: Always-on validation, continuous automated red teaming (CART).
- Cobalt: Continuous pentesting as an explicit product tier (March 2026).
- Pentera: Continuous multi-segment attack emulation by design.

**What AegisPT has:** Operator-initiated runs per engagement. No scheduling.

**What to build:**

A `schedule_json` field on the engagement or a dedicated `ScheduledRun` model: `engagement_id`, `profile_name`, `cron_expression`, `enabled`, `last_run_at`, `next_run_at`.

A scheduler worker that wakes up at configured intervals, checks for due scheduled runs, and dispatches them through the existing `dispatch_task_batch()` path. In Dramatiq mode, use a periodic task. In inline mode, use a background APScheduler thread.

The UI addition is minimal: a "Schedule" toggle in the engagement settings with a cron picker (or simple presets: daily / weekly / on-demand).

This unlocks the "continuous validation" positioning that every competitor is selling.

---

### 5.5 Cloud and Identity Attack Surface (Medium — required for enterprise scope)

**What competitors have:**
- Pentera Cloud: AWS + Azure + GCP IAM testing, container/Kubernetes escape, cross-environment chains. Claims 80% faster IAM risk validation vs manual.
- NodeZero: AWS credential testing, Azure credential handling, Kubernetes pentesting.
- XM Cyber: 56% of exposures affecting critical assets are in cloud. AWS + Azure + GCP attack path management.
- Cymulate: Cloud and Kubernetes BAS library, Microsoft Entra ID integration.

**What AegisPT has:** Web + internal network + code (Semgrep) surfaces. No cloud runner. No IAM testing. No Active Directory abuse scenarios.

**What to build — phased:**

**Phase 1 (foundational):**
- Cloud configuration runner using `aws cli` / `az cli` / `gcloud` (read-only API calls). Enumerate: IAM role policies, S3 bucket ACLs, security group rules, public-facing resources. No exploitation — pure discovery and misconfiguration detection. Generates findings for high-risk misconfigurations. This is safe, reversible, and produces immediate value.
- AD / LDAP enumeration runner using `ldap3` Python library. Read-only: enumerate users, groups, GPOs, privileged group membership, password policy, Kerberoastable accounts. No exploitation.

**Phase 2:**
- Integrate existing AD attack tools (BloodHound CE for graph data, CrackMapExec for safe enumeration) as controlled runners with approval gates, following the existing runner contract.
- Cloud privilege escalation path testing with explicit approval gates and scope enforcement.

**Phase 3:**
- IAM lateral movement simulation (cross-account role chaining)
- Kubernetes escape testing
- Cross-environment attack chain validation (cloud → on-prem)

---

### 5.6 Active Directory Testing (Medium — table stakes in enterprise internal assessments)

**What competitors have:**
- NodeZero: Domain trust enumeration, Golden Ticket, Kerberoasting, SCCM TAKEOVER-1, AD Password Audit (offline hash cracking), GOAD-solved in 14 minutes.
- Pentera Core: Full AD Password Assessment, lateral movement, privilege escalation, credential-based attack chains.
- XM Cyber: 80% of exposures identified as AD/identity misconfigurations — entire product philosophy.

**What AegisPT has:** Internal network discovery (Nmap). No AD-specific testing.

**What to build:**

Add an `ldap-enum` runner using `ldap3` for safe read-only AD discovery:
- Enumerate domain users, computers, groups
- Identify privileged group membership (Domain Admins, Enterprise Admins, etc.)
- Detect Kerberoastable accounts (SPNs on user accounts)
- Detect AS-REP roastable accounts (no preauth required)
- Detect password policy weaknesses (min length, complexity, lockout threshold)
- Map nested group memberships

Results feed into inventory snapshots as identity-class assets, and into findings with PTES/NIST methodology tags. This is a passive read-only operation that requires no exploitation approval gate — valid in even the most restricted environments.

---

### 5.7 AI / LLM Application Testing (Emerging — fast-growing segment)

**What competitors have:**
- HackerOne (Agentic PTaaS, January 2026): LLM application testing — prompt injection, data leakage, unsafe agent behavior. Code-aware testing with source code integration.
- Cobalt: AI/LLM applications as an explicit test type alongside web, network, mobile.
- Synack Glasswing (April 2026): Tests defenses against AI-security gaps.
- XM Cyber (March 2026): Shadow AI Discovery, MCP Server inventory, Cloud AI Visibility (AWS Bedrock, Azure OpenAI, GCP Vertex AI).

**What to build:**

A new runner type: `llm-probe`. Targets: an LLM API endpoint (OpenAI-compatible, Azure OpenAI, Anthropic, local Ollama). Tests:
- Prompt injection (system prompt override attempts)
- Data exfiltration via prompt (extract system prompt, training data)
- Jailbreak patterns (curated test set, not exhaustive)
- Excessive agency detection (does the model take destructive actions from instructions?)
- PII leakage via context window

This is a growing enterprise requirement as customers deploy internal LLM applications and AI agents. No other platform in this space offers it built-in on self-hosted open tooling. The runner is relatively simple — it is an HTTP client that sends structured test prompts to an API endpoint and evaluates responses.

---

### 5.8 Compliance Report Packages (Medium — accelerates sales cycles)

**What competitors have:**
- Pentera: PCI DSS v4.0, SOC 2, ISO 27001, NIST, CMMC/DFARS, DORA, NIS2, HIPAA, FedRAMP.
- NodeZero: SOC 2, PCI DSS, CMMC, HIPAA compliance-oriented reporting. FedRAMP High coverage.
- BreachLock: Downloadable audit-ready compliance reports in portal.
- Cobalt: Compliance-mapped findings and reports.

**What AegisPT has:** Methodology alignment (PTES/WSTG/NIST/ASVS) per finding. Report variants (executive, technical, evidence). No explicit compliance framework mapping in report templates.

**What to build:**

Compliance report templates that:
1. Map existing methodology tags to specific compliance control requirements
2. Group findings by compliance framework section (e.g., PCI DSS Req 6.4, SOC 2 CC7.1)
3. Show compliance coverage: "X of Y relevant controls tested, Z findings require remediation before audit"
4. Export as a PDF with the framework name, scope statement, and testing dates as a formal assurance header

Priority frameworks: **SOC 2** (most-requested in US SaaS market), **ISO 27001** (global enterprise), **PCI DSS v4.0** (financial/e-commerce — v4.0 mandatory since March 2025).

The methodology data is already in the finding model. This is primarily a reporting service extension — new report variants using existing data.

---

### 5.9 MSSP / Multi-Tenant Support (Medium — commercial scaling)

**What competitors have:**
- NodeZero: Full multi-tenant portal with subclient management (March 2025). Elastic licensing for concurrent pentests across client base. MSSP Vanguard Partner Program with three tiers. Parent asset pool access (February 2026).
- Cobalt: Multi-organization visibility for enterprise accounts.
- BreachLock: Dedicated project-manager style per-customer handling.

**What AegisPT has:** Single-tenant. No concept of multiple customers or operators with different permission scopes.

**What to build:**

An `organisations` table above the current `engagements` model. Operators belong to an organisation. Engagements belong to an organisation. An operator with `admin` role sees all engagements in their organisation. A `viewer` role sees reports and findings but cannot dispatch runs or manage scope. An `mssp` role pattern allows one organisation to manage engagements on behalf of another.

This does not require complex auth infrastructure — it is a model layer change and a permission check layer in the API. The JWT/session token carries the `organisation_id` and `role`. The UI adds an org switcher in the header.

---

## 6. AI Opportunities

### 6.1 MCP Server (High — strategic integration point)

NodeZero and SafeBreach both launched MCP servers in 2025. An MCP (Model Context Protocol) server exposes AegisPT's data and operations as tools that any LLM can call via natural language.

**What this enables:**
- Operator asks their LLM: *"What are my critical findings from last week's scan of api.example.com?"*
- LLM calls `aegispt_get_findings` tool → returns structured data → LLM summarises in plain language
- Operator asks: *"Schedule a retest of the SQL injection finding from run X"* → LLM calls `aegispt_schedule_retest`
- Security engineer asks: *"Write a Jira ticket for the XSS finding on the checkout endpoint"* → LLM uses finding detail to draft the ticket

**Implementation:** An MCP server is a small JSON-over-stdio or HTTP server that declares a manifest of tools and handles tool call requests. Use the `mcp` Python SDK (Anthropic-maintained). Expose read tools: `get_engagements`, `get_runs`, `get_findings`, `get_evidence`, `get_report`. Expose action tools: `dispatch_run`, `approve_run`, `update_finding_status`, `schedule_retest`. The existing API is the backend — the MCP server is a thin adapter.

This makes AegisPT queryable from Claude, ChatGPT, Cursor, and any other LLM with MCP support — dramatically expanding how operators interact with the platform.

---

### 6.2 AI-Powered Finding Enrichment (High — improves output quality)

Every finding currently gets a rule-based `business_impact`, `technical_details`, and `next_steps` from `finding_views.py`. These are template strings.

**What to add:** Call an LLM (Claude Haiku or Sonnet — cheap, fast) at finding creation time to generate:
- A contextualised business impact statement that references the specific target, technology stack (from inventory), and severity
- A technical explanation of the vulnerability in the context of the detected technology (not a generic template)
- Specific, actionable remediation steps for the detected technology version
- A risk narrative that synthesises finding + inventory + threat intel context

**Cost estimate:** ~500 tokens per finding. At Haiku pricing ($0.25/MTok input, $1.25/MTok output), processing 100 findings costs less than $0.10. For a pentest generating 50 findings, enrichment is essentially free.

**Implementation:** Add an async `enrich_finding_with_ai()` call in the findings creation path, after standard normalization. Store the enriched content in a `ai_enrichment_json` column on the `Finding` model. Display in the finding theater alongside the rule-based content.

---

### 6.3 AI Mission Planning Assistant (Medium — extends the wizard)

The conversational wizard already maps plain-language intent to deterministic run config. The next level is using an LLM to:
- Analyse the scope and recommend the right assessment type (passive/active/intrusive) based on what the operator described
- Warn about potential scope boundary issues ("Your CIDR includes 10.0.20.1 which is also in the denylist — should I exclude it?")
- Recommend follow-up runs after discovery ("Nmap found Apache 2.4.49 on 3 hosts — this version has CVE-2021-41773. I recommend running a targeted Nuclei check before the full active scan.")
- Synthesise threat intel relevance into plain language ("Based on the detected WordPress 6.4 installation, 3 active CVEs are relevant. Adding targeted checks for CVE-2023-5561...")

**Implementation:** Wire a lightweight LLM call into the wizard's `submitConversationAnswer()` processing — after the deterministic mapping, pass the resolved config through Claude Haiku for a consistency check and recommendation injection. Render AI suggestions as distinct "AI note" blocks in the wizard summary panel.

---

### 6.4 Threat Actor Mapping (Medium — differentiates reporting)

NodeZero launched Threat Actor Mapping in July 2025. XM Cyber shows which APT groups exploit your specific vulnerability profile.

**What to build:** After a run completes and findings are normalised, cross-reference `Finding.wstg_id`, `Finding.ptes_phase`, `Finding.methodology_tags`, and the detected `vendor_product_fingerprints` from inventory against a curated threat intel dataset (MITRE ATT&CK, open CTI feeds, CISA KEV).

Map findings to relevant threat actor groups (APT28, Lazarus Group, ransomware families, etc.) that commonly exploit that vulnerability class or that target that specific technology. Surface in the executive report as: *"The SQL injection pattern found on your API matches techniques used by [Threat Group]. They have targeted [industry] organisations in [region] in [recent campaigns]."*

**Data source options:** MITRE ATT&CK TAXII feed, CISA KEV JSON, OpenCTI community dataset, Mandiant Open Source Intelligence. All are freely available and machine-readable.

---

### 6.5 AI-Assisted Report Writing (Medium — saves operator time)

Cobalt, PlexTrac, and BreachLock all use LLMs to generate or accelerate pentest report content.

**What to add:** An "AI Draft" button in the Report Center that calls an LLM with the run's findings, methodology tags, inventory summary, and client context to draft:
- An executive summary paragraph (risk posture, critical findings, recommended priorities)
- A technical summary section per finding cluster
- A management-level risk narrative

The operator reviews and edits the draft before exporting. This reduces the report writing time from hours to minutes, especially valuable when the same operator is running multiple engagements.

---

### 6.6 AI Detection Engineering Assistant (Low-Medium — defensive value-add)

Cymulate launched an AI Detection Engineering Assistant in late 2025 that maps SIEM rules to relevant attack scenarios. A lightweight version for AegisPT:

After a run completes, offer an AI-assisted analysis of: *"What SIEM rules or EDR detections would have caught these findings?"* Generate Sigma-format detection rules for each finding, linked to the specific tool and technique used. Store these as `detection_hints_json` on the finding.

This is a differentiating feature that no other self-hosted open-stack platform offers. Security teams can take the Sigma rules directly into their SIEM (Elastic, Splunk, Wazuh). It turns AegisPT from a pure offensive tool into something that also improves defensive posture.

---

### 6.7 Agentic Pack Generation (Already Seeded — Codex Lane Expansion)

The existing Codex build lane is architecturally the right approach but currently requires significant operator involvement in each pack generation step. The path to a more autonomous version:

- **Phase 1 (current):** Operator triggers Codex task → AI generates pack → human reviews → validation gate → deploy
- **Phase 2:** After discovery, the system automatically proposes pack generation for the top 3 detected technologies without waiting for operator input. Operator reviews and approves. Reduces the number of steps from 5+ to 2.
- **Phase 3:** Multi-agent: one agent generates the pack, a second agent reviews it for safety and accuracy, a third runs it against a safe target for validation. Human still approves before production use but AI handles the preparation pipeline.

This maps directly to the multi-agent red team direction already documented in `docs/multi_agent_red_team_program.md`.

---

## 7. Priority Roadmap

Ordered by commercial impact and implementation effort. The rationale: items in P1 are the ones that block enterprise sales or remove the most operator friction today. P2 items differentiate the product. P3 items expand the addressable market.

### P1 — Next 30 days (unblock commercial viability)

| # | Feature | Effort | Backend? | Impact |
|---|---------|--------|----------|--------|
| 1 | Fix font stack (Inter via Google Fonts) | 30 min | No | Visual identity works cross-platform |
| 2 | Empty states across all panels | 0.5 day | No | First impression quality |
| 3 | Task shimmer animation (running state) | 2 hours | No | Constant visible motion during execution |
| 4 | Finding severity bars with grow animation | 2 hours | No | Live feeling from existing poll data |
| 5 | Tool pipeline swimlane view | 1 day | No | Clear "what is running" overview |
| 6 | Terminal-style evidence display | 0.5 day | No | Operators' native language |
| 7 | Finding card: risk gauge + methodology chain + exploitability bar | 1 day | No | Classified brief look |
| 8 | Mission launch sequence animation | 0.5 day | No | Psychological intake→execution transition |
| 9 | Surface Map host cards (grid, no D3) | 1 day | No | Something to show after discovery |
| 10 | Merge Evidence Replay into Findings Theater | 1–2 days | No | Removes highest-friction navigation |
| 11 | SSE run events endpoint + background dispatch | 1 day | Yes | Replace polling with live push |
| 12 | Stdout streaming (Popen + Redis + SSE endpoint) | 1.5 days | Yes | Live terminal panel |
| 13 | Target scan map SVG with animated beams | 2–3 days | Yes (SSE) | The primary demo visual |
| 14 | Basic remediation status + retest run | 2 days | Yes | "Proof of resolution" story begins |

---

### P2 — Next 60–90 days (differentiation and enterprise readiness)

| # | Feature | Effort | Impact |
|---|---------|--------|--------|
| 11 | Jira integration (bidirectional) | 3 days | Opens enterprise door |
| 12 | Slack webhook (finding notifications) | 1 day | Immediate ops team value |
| 13 | Attack path graph (D3 + choke points) | 1 week | Key demo differentiator |
| 14 | AI finding enrichment (Claude Haiku) | 2 days | Report quality improvement |
| 15 | Proof-of-resolution report variant | 2 days | Audit-ready retest output |
| 16 | Continuous scheduling (APScheduler) | 3 days | Always-on positioning |
| 17 | MCP server (read-only initial release) | 3 days | LLM integration story |
| 18 | SOC 2 compliance report template | 2 days | Most-requested framework |
| 19 | Teams webhook integration | 0.5 day | Enterprise collaboration |
| 20 | Threat actor mapping (MITRE ATT&CK + KEV) | 3 days | Reporting differentiation |

---

### P3 — Next 90–180 days (market expansion)

| # | Feature | Effort | Impact |
|---|---------|--------|--------|
| 21 | Cloud config runner (AWS/Azure read-only) | 1 week | Cloud attack surface entry |
| 22 | AD/LDAP enumeration runner | 1 week | Internal identity discovery |
| 23 | LLM/AI application testing runner | 1 week | Emerging segment first-mover |
| 24 | ServiceNow integration | 3 days | Enterprise ITSM requirement |
| 25 | ISO 27001 / PCI DSS report templates | 3 days | Global enterprise compliance |
| 26 | Multi-tenant / organisation model | 1–2 weeks | MSSP commercial model |
| 27 | AI mission planning assistant | 3 days | Extends wizard intelligence |
| 28 | AI report writing assistant | 2 days | Reduces operator reporting time |
| 29 | AI detection engineering (Sigma rules) | 3 days | Unique defensive output |
| 30 | MCP server (write/action tools) | 2 days | Full agentic integration |

---

## 8. Strategic Positioning Statement

The market is converging on AEV (Adversarial Exposure Validation). The platforms that win will combine:

- Autonomous or semi-autonomous attack execution
- Evidence-backed, methodology-aligned findings
- Attack path intelligence showing choke points
- Remediation orchestration with proof-of-resolution
- Continuous validation and scheduled campaigns
- AI assistance throughout — intake, execution, triage, reporting, remediation
- Enterprise workflow integrations

AegisPT's architecture already addresses the first two better than most competitors. The evidence-first model and supervised AI build lane are genuine moats that are difficult to replicate. The path to competing commercially requires closing the remaining gaps in order:

**Remediation loop** → **Live operations experience** → **Enterprise integrations** → **Attack path graph** → **Continuous mode** → **Cloud/identity surfaces** → **AI enrichment and MCP** → **Compliance packaging**

The strongest competitive narrative: *AegisPT is the only platform that gives you replayable, evidence-bound, methodology-aligned findings from a controlled open tool stack — and now closes the loop from discovery to verified remediation without switching tools.*

That is differentiated, credible, and commercially compelling against both the automated platforms (NodeZero, Pentera) and the PTaaS services (Cobalt, BreachLock).

---

## 9. What Not to Build

These would be distractions or directional mistakes at the current stage:

- **A proprietary scanner.** The open tool stack (ZAP, Nuclei, Nmap) is a trust advantage. A proprietary scanner would cost months to build and would be worse than mature tools.
- **A fully autonomous attack engine without approval gates.** The current model (deterministic with human approval for active checks) is the right architecture for enterprise buyers. Full autonomy creates liability that no enterprise security team will accept.
- **Generic "AI chat" on top of findings.** A chatbot wrapper over findings data is not a feature — it is a demo. Build specific AI capabilities (enrichment, mission planning, report writing, threat mapping) that do concrete jobs, not a chat interface that answers vague questions.
- **More screens.** The UI needs fewer surfaces, not more. Resist the temptation to add new screens for each new feature. Integrate new capabilities into the existing 5-screen structure.
- **Cloud SaaS before the on-premise experience is polished.** Fix the local install experience and make the product excellent for the Kali-native operator before expanding to a multi-tenant cloud deployment.

---

*This document reflects the competitive landscape as of April 2026 and is intended as a living product direction reference. It should be reviewed and updated quarterly as the market evolves.*
