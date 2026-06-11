# AegisPT — UI Redesign Specification

**Date:** April 2026
**Status:** Authoritative design spec — supersedes the structural notes in PRODUCT_RECOMMENDATIONS.md and LIVING_SYSTEM_EXPERIENCE.md where they conflict
**Based on:** Full code analysis of ui/index.html, ui/assets/styles.css, ui/assets/app.js, and all UI modules

---

## 1. The Problem, Stated Precisely

The current UI wastes approximately **380px of vertical space** on chrome before any content appears:

```
Hero block (h1 "Operator Console" + subcopy)     ~180px
Phase navigation bar (3 × 76px tall buttons)     ~120px
Context strip (engagement dropdown + summary)     ~ 80px
                                               ─────────
Total header chrome                               ~380px
```

On a 900px viewport, that is **42% of the screen** used for navigation and branding before a single piece of operational data is visible.

**Additional structural problems identified in code:**

| Problem | Where | Impact |
|---------|-------|--------|
| Phase-locked nav (`PHASE_SUBNAV` per phase) | app.js:51 | Can't reach Findings without completing intake |
| Wizard right panel always rendered | wizard-layout grid 1.7fr/0.78fr | 30% of screen shows empty summary sections |
| 9 screens, 3 phases, 10 subnav items | PHASE_SUBNAV | Confusing for returning operators |
| `--radius-xl: 28px`, `--radius-lg: 22px` | styles.css | Looks like a consumer mobile app |
| 7-column timeline grid in Mission Control | mission-control.js | Visually overwhelming, rarely useful |
| 5 filter dropdowns always visible in Findings | findings.js | Heavy toolbar, most filters unused |
| `scan-grid` at 0.48 opacity | styles.css | Decorative texture fights content |
| Two empty panels side-by-side at rest | theater-grid repeat(3, 1fr) | Dead screen real estate |
| Sidebar is 220px with phase label overhead | workspace grid | Space wasted on "CURRENT PHASE / Intake" label |

---

## 2. The Target Layout

### 2.1 Global Shell

```
┌──────────────────────────────────────────────────────────────────────────┐
│  AegisPT  │  [engagement selector ▾]    [run: active ●]  [⚙] [actor ▾]  │  ← 48px topbar
├───────────┼──────────────────────────────────────────────────────────────┤
│           │                                                              │
│  + New    │                                                              │
│  Mission  │                    MAIN CONTENT AREA                        │
│  ─────    │                    (full height, full width)                 │
│  OPERATE  │                                                              │
│  ○ Intake │                                                              │
│  ○ Run    │                                                              │
│  ○ Map    │                                                              │
│  ─────    │                                                              │
│  ANALYZE  │                                                              │
│  ○ Findings                                                              │
│  ○ Reports│                                                              │
│  ○ History│                                                              │
│  ─────    │                                                              │
│  BUILD    │                                                              │
│  ○ Packs  │                                                              │
│  ─────    │                                                              │
│  ⚙ Settings                                                              │
│           │                                                              │
│  [run     │                                                              │
│   status] │                                                              │
└───────────┴──────────────────────────────────────────────────────────────┘
     180px                          minmax(0, 1fr)
```

**What this removes:**
- The `.hero` block entirely — no "Operator Console" heading, no subcopy, no hero-side panel
- The `.flow-overview` phase navigation bar
- The `.context-strip` row (engagement dropdown moves to topbar)
- The "CURRENT PHASE" label above the sidebar nav items
- The phase-locked navigation model

**What stays:**
- All existing screen content (no data loss)
- All existing API contracts
- All test IDs on content components

---

### 2.2 Topbar (48px, fixed)

```
┌─────────────────────────────────────────────────────────────────────────┐
│ ◈ AegisPT  │  Customer API v1  ▾  │  ● 1 run active  │  ⚙  │  jaap ▾  │
└─────────────────────────────────────────────────────────────────────────┘
```

Elements (left to right):
- **Logo mark + wordmark** — `◈ AegisPT` — 140px
- **Divider**
- **Engagement selector** — dropdown, shows current engagement name, truncated — fills available space
- **Run status pill** — only visible when a run is active: `● 1 run active` (cyan when running, green when complete, red on failure)
- **Settings gear icon** — always present, navigates to Settings screen
- **Actor dropdown** — current actor name, click to change

CSS:
```css
.topbar {
  position: fixed;
  top: 0; left: 0; right: 0;
  height: 48px;
  display: flex;
  align-items: center;
  gap: 0;
  background: rgba(5, 9, 18, 0.97);
  border-bottom: 1px solid var(--line);
  z-index: 100;
}
.app-shell {
  padding-top: 48px;  /* clearance for fixed topbar */
}
```

---

### 2.3 Sidebar (180px, sticky)

```css
.sidebar {
  width: 180px;
  height: calc(100vh - 48px);
  position: sticky;
  top: 48px;
  overflow-y: auto;
  border-right: 1px solid var(--line);
  padding: 1rem 0;
  display: flex;
  flex-direction: column;
  gap: 0;
}
```

**Structure:**
```
[+ New Mission]   ← primary CTA button, full width, cyan outline

OPERATE           ← section label (0.68rem, uppercase, muted)
  Intake
  Mission Control
  Attack Map

ANALYZE
  Findings
  Reports
  History

BUILD
  Packs

──────────────    ← spacer (flex: 1)

⚙ Settings        ← at bottom, always visible

[run indicator]   ← only when run active
```

Nav item styling:
```css
.nav-item {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  padding: 0.45rem 1rem;
  font-size: 0.875rem;
  color: var(--text-muted);
  border-radius: 0;
  cursor: pointer;
  transition: background 0.12s, color 0.12s;
}
.nav-item:hover {
  background: rgba(255, 255, 255, 0.04);
  color: var(--text-soft);
}
.nav-item.active {
  background: rgba(107, 215, 255, 0.08);
  color: var(--cyan);
  border-right: 2px solid var(--cyan);
}
.nav-section-label {
  padding: 0.75rem 1rem 0.25rem;
  font-size: 0.68rem;
  letter-spacing: 0.18em;
  text-transform: uppercase;
  color: var(--text-muted);
  opacity: 0.55;
}
```

---

### 2.4 Workspace

```css
.workspace {
  display: grid;
  grid-template-columns: 180px minmax(0, 1fr);
  min-height: calc(100vh - 48px);
  margin-top: 48px;  /* topbar clearance */
}
```

Content area gets the full remaining width. No outer padding on the workspace — each screen manages its own internal padding (1.25rem).

---

## 3. Screen-by-Screen Redesign

### 3.1 Intake (Wizard)

**Current problem:** 1.7fr/0.78fr split. The right panel (0.78fr ≈ 30%) shows 6 empty sections at rest — "Nothing confirmed yet", "No safe inferences active", "No targets yet", etc.

**Redesign:** Full-width conversation. The summary panel becomes a **collapsible bottom drawer** that only appears when the first piece of context is confirmed.

```
┌──────────────────────────────────────────────────────────────────────────┐
│                                                                          │
│  New Mission                                              [Advanced ▾]   │
│  ──────────────────────────────────────────────────────────────────────  │
│                                                                          │
│  AEGISPT                                                                 │
│  Hello. What would you like to pentest today?                            │
│                                                                          │
│  ┌────────────────────────────────────────────────────────────────────┐  │
│  │ CURRENT QUESTION                                          [Intent]  │  │
│  │ Hello. What would you like to pentest today?                        │  │
│  │                                                                     │  │
│  │ [My LAN network]  [Our web application]  [Our API]  [An external   │  │
│  │  domain]  [A mixed environment]                                     │  │
│  │                                                                     │  │
│  │ ┌─────────────────────────────────────────────────────────────┐    │  │
│  │ │ Example: My LAN network, our customer portal...             │    │  │
│  │ └─────────────────────────────────────────────────────────────┘    │  │
│  └────────────────────────────────────────────────────────────────────┘  │
│                                                                          │
│                        [← Previous]  [Apply Answer →]                   │
│                                                                          │
│  ────── Mission Context (appears after first confirmed answer) ──────── │
│  Goal: External web app  ·  Scope: not set  ·  Safety: not set          │
└──────────────────────────────────────────────────────────────────────────┘
```

**The inline context bar at the bottom:**
- Hidden until Goal is confirmed
- Shows confirmed items as compact pills: `Goal: External app · Scope: 1 URL · Safety: Passive`
- Does NOT show empty sections
- `[Create Mission →]` button appears when all required items are confirmed

**Removes:** The wizard-layout grid entirely. No `.wizard-summary-panel`. No sticky right panel. No "Nothing confirmed yet" placeholder sections.

---

### 3.2 Mission Control

**Current problem:** 5 major panel areas, 7-column timeline grid, complex nested grids. The timeline shows 7 columns for 3-7 tasks — most are empty.

**Redesign:** Three clear columns during an active run.

```
┌─────────────────────┬───────────────────────────┬──────────────────────┐
│                     │                           │                      │
│  SCAN MAP           │  TASKS                    │  AI SIGNAL           │
│  (SVG spider web)   │  ─────────────────────    │  ─────────────────   │
│                     │  ▶ nmap  10.0.20.0/24 ~~  │  14:33 nmap done     │
│  [tools]──[targets] │  ✓ httpx api.example.com  │  ⚡ CVE-2021-41773   │
│                     │  ◌ nuclei (queued)        │     [Approve ✓]      │
│  ● api.example.com  │  ◌ zap (queued)           │  14:34 chain found   │
│    +3 ⚠             │                           │  [view →]            │
│                     │  FINDINGS SO FAR          │                      │
│                     │  critical  ████  3        │  STDOUT              │
│                     │  high      ████  6        │  ┌──────────────┐    │
│                     │  medium    ██    2        │  │ nuclei v3.3  │    │
│                     │                           │  │ [CVE-...]    │    │
│                     │  [View All Findings →]    │  └──────────────┘    │
│                     │                           │                      │
└─────────────────────┴───────────────────────────┴──────────────────────┘
```

**CSS:**
```css
.mission-grid {
  display: grid;
  grid-template-columns: minmax(320px, 1fr) minmax(280px, 1fr) 320px;
  gap: 1rem;
  padding: 1.25rem;
  align-items: start;
}
```

**Removes:** 7-column timeline grid, `.mission-support-grid` 3-column support area, separate ETA panel, separate status lanes panel. These are replaced by the compact task list and finding severity bars.

**When no run is active:**
```
┌──────────────────────────────────────────────────────────────────┐
│                                                                  │
│  No active run                                                   │
│  Select an engagement and start from Intake to create a run,    │
│  or select a completed run from History to review results.      │
│                                                                  │
│  [Start New Mission →]     [View History →]                     │
│                                                                  │
└──────────────────────────────────────────────────────────────────┘
```

---

### 3.3 Findings Theater

**Current problem:** 5 filter dropdowns always visible in a toolbar row. Two empty panels side-by-side (group list + detail, each taking 33% of screen).

**Redesign:** Compact filter bar (collapsed by default) + full-width findings list + detail drawer.

```
┌──────────────────────────────────────────────────────────────────────────┐
│  Findings                                    [▼ Filters]  [Group by: Severity ▾] │
├──────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  CRITICAL (3)                                                            │
│  ─────────────────────────────────────────────────────────────────────  │
│  ● SQL Injection — /graphql — api.example.com          [KEV] [→]        │
│  ● Path Traversal RCE — Apache 2.4.49                  [KEV] [→]        │
│  ● SSRF → Redis Chain — shop.example.com               [chain] [→]      │
│                                                                          │
│  HIGH (6)                                                                │
│  ─────────────────────────────────────────────────────────────────────  │
│  ● XSS Stored — /comments — www.example.com                    [→]      │
│  ...                                                                     │
│                                                                          │
└──────────────────────────────────────────────────────────────────────────┘
```

When a finding is clicked, a **side drawer** slides in from the right (400px wide, full height):

```
┌──────────────────────────────────────┬──────────────────────────────────┐
│  Findings list (left, shrinks)        │  ◈ SQL Injection            [×]  │
│                                       │  ─────────────────────────────   │
│  CRITICAL (3)                         │  [Risk Gauge SVG]               │
│  ● SQL Injection ← selected           │  Critical · Operator-validated   │
│  ● Path Traversal RCE                 │                                  │
│  ● SSRF → Redis Chain                 │  PTES: Exploitation →            │
│                                       │  WSTG-INPV-01 → NIST → ASVS L2 │
│  HIGH (6)                             │                                  │
│  ● XSS Stored                         │  ⚡ CISA KEV — actively exploited │
│                                       │                                  │
│                                       │  EVIDENCE ──────────────────── │
│                                       │  ┌─ nuclei v3.3.1 ·exit: 0 ──┐  │
│                                       │  │ [CVE-...] critical         │  │
│                                       │  └───────────────────────────┘  │
│                                       │                                  │
│                                       │  REMEDIATION ─────────────────  │
│                                       │  Upgrade Apache: sudo apt...     │
│                                       │  Verify: curl -s ...             │
│                                       │                                  │
│                                       │  [Schedule Retest]  [Jira →]     │
└──────────────────────────────────────┴──────────────────────────────────┘
```

**Filter bar (collapsed by default):**
```
[▼ Filters]  →  expands to show:  Run ▾  Severity ▾  Origin ▾  Status ▾  Methodology ▾
```

Filters are hidden when the finding list is empty. When expanded, they appear as a row below the heading. Most operators never need all 5 at once.

---

### 3.4 Report Center

**Current problem:** The right-side metadata panel with discovery notice, tag cloud, evidence/task counts feels disconnected from the report list on the left.

**Redesign:** Full-width layout. Report variants as cards. Selected run context as a compact strip above the cards.

```
┌──────────────────────────────────────────────────────────────────────────┐
│  Reports                                                                 │
│  Run: Acceptance · Local Host · 20260422 · completed                    │
│  1 url · 2 hosts · 0 findings · 5 reports ready                         │
├──────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  ┌───────────────────────────┐  ┌───────────────────────────┐           │
│  │ Executive Report          │  │ Technical Report          │           │
│  │ complete                  │  │ complete                  │           │
│  │ Leadership-ready summary  │  │ Full technical narrative  │           │
│  │ [↓ MD] [↓ HTML] [↓ PDF]   │  │ [↓ MD] [↓ HTML] [↓ PDF]   │           │
│  └───────────────────────────┘  └───────────────────────────┘           │
│                                                                          │
│  ┌───────────────────────────┐  ┌───────────────────────────┐           │
│  │ SOC 2 Package             │  │ Attack Narrative ✨AI      │           │
│  │ complete                  │  │ complete                  │           │
│  │ Maps findings to controls │  │ Synthesised attack story  │           │
│  │ [↓ MD] [↓ HTML] [↓ PDF]   │  │ [↓ MD] [↓ HTML] [↓ PDF]   │           │
│  └───────────────────────────┘  └───────────────────────────┘           │
│                                                                          │
└──────────────────────────────────────────────────────────────────────────┘
```

Report cards in a 2-column grid (or 3-column on wide viewports). Download buttons inline on each card. No separate catalog/metadata split.

---

### 3.5 Settings

**Always accessible from topbar gear icon.** Full-width layout with a left sub-nav for sections.

```
┌────────────────────────────────────────────────────────────────────────┐
│  Settings                                                              │
├──────────────┬─────────────────────────────────────────────────────────┤
│              │                                                         │
│  AI Provider │  AI Provider                                            │
│  Network     │  ─────────────────────────────────────────────────     │
│  Integrations│  Provider                                               │
│  Notifications  [○ Disabled  ◉ ChatGPT OAuth  ○ HTTP Webhook]         │
│  Instance    │                                                         │
│              │  ChatGPT Connection                                     │
│              │  ┌──────────────────────────────────────────────────┐  │
│              │  │  Not connected                    [Connect →]    │  │
│              │  └──────────────────────────────────────────────────┘  │
│              │                                                         │
│              │  Network Scope Defaults                                 │
│              │  (visible when Network section is selected)            │
│              │                                                         │
└──────────────┴─────────────────────────────────────────────────────────┘
```

---

## 4. CSS Changes — Concrete Values

### 4.1 Remove

```css
/* DELETE these entirely: */
.hero { ... }
.hero-copy { ... }
.hero-side { ... }
.hero-h1 { ... }
.hero-subcopy { ... }
.hero-metrics { ... }
.flow-overview { ... }
.flow-step { ... }
.flow-step-copy { ... }
.context-strip { ... }
.context-strip-row { ... }
.context-controls { ... }
.context-summary { ... }
.bg-orbit { ... }       /* decorative blobs */
.scan-grid { ... }      /* decorative grid texture */
.orbit-a { ... }
.orbit-b { ... }
```

### 4.2 Update

```css
/* Border radius — enterprise scale */
:root {
  --radius-xl: 10px;   /* was 28px */
  --radius-lg:  8px;   /* was 22px */
  --radius-md:  6px;   /* was 16px */
  --radius-sm:  4px;   /* was 12px */
}

/* Workspace — sidebar + main */
.workspace {
  display: grid;
  grid-template-columns: 180px minmax(0, 1fr);  /* was 220px */
  min-height: calc(100vh - 48px);
  margin-top: 48px;
  gap: 0;  /* was 1rem — sidebar is flush */
}

/* Body background — remove radial gradients */
body {
  background: #070e1a;  /* flat dark, no radial blobs */
}

/* Panel — slightly less shadow */
.panel {
  border-radius: var(--radius-lg);
  box-shadow: 0 4px 16px rgba(0, 0, 0, 0.2);  /* was 0 18px 46px */
}
```

### 4.3 Add

```css
/* Fixed topbar */
.topbar {
  position: fixed;
  top: 0; left: 0; right: 0;
  height: 48px;
  display: flex;
  align-items: center;
  padding: 0 1rem;
  gap: 0.75rem;
  background: rgba(5, 9, 18, 0.97);
  border-bottom: 1px solid var(--line);
  z-index: 200;
  backdrop-filter: blur(8px);
}

/* Sidebar */
.sidebar {
  width: 180px;
  height: calc(100vh - 48px);
  position: sticky;
  top: 48px;
  overflow-y: auto;
  border-right: 1px solid var(--line);
  padding: 0.75rem 0;
  display: flex;
  flex-direction: column;
  background: rgba(5, 8, 15, 0.6);
}

/* Nav items */
.nav-item {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  padding: 0.42rem 1rem;
  font-size: 0.875rem;
  color: var(--text-muted);
  cursor: pointer;
  transition: background 0.1s, color 0.1s;
  white-space: nowrap;
  overflow: hidden;
}
.nav-item:hover {
  background: rgba(255,255,255,0.04);
  color: var(--text-soft);
}
.nav-item.active {
  background: rgba(107,215,255,0.07);
  color: var(--cyan);
  border-right: 2px solid var(--cyan);
}
.nav-section-label {
  padding: 0.85rem 1rem 0.2rem;
  font-size: 0.66rem;
  letter-spacing: 0.2em;
  text-transform: uppercase;
  color: var(--text-muted);
  opacity: 0.45;
}

/* Finding detail drawer */
.finding-drawer {
  position: fixed;
  right: 0;
  top: 48px;
  width: 420px;
  height: calc(100vh - 48px);
  background: var(--panel-strong);
  border-left: 1px solid var(--line);
  overflow-y: auto;
  transform: translateX(100%);
  transition: transform 0.25s cubic-bezier(0.4, 0, 0.2, 1);
  z-index: 150;
}
.finding-drawer.open {
  transform: translateX(0);
}

/* Mission grid — 3 columns */
.mission-grid {
  display: grid;
  grid-template-columns: minmax(280px, 1fr) minmax(240px, 1fr) 300px;
  gap: 1rem;
  padding: 1.25rem;
  align-items: start;
}

/* Report cards grid */
.report-cards-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(260px, 1fr));
  gap: 1rem;
}
```

---

## 5. JavaScript Changes

### 5.1 Navigation — Free and Flat

Replace the `PHASE_SUBNAV` phase-locked model with a flat nav list:

```javascript
const NAV_ITEMS = [
  { screen: "wizard",           label: "Intake",          group: "OPERATE" },
  { screen: "mission-control",  label: "Mission Control", group: "OPERATE" },
  { screen: "surface-map",      label: "Attack Map",      group: "OPERATE" },
  { screen: "findings-theater", label: "Findings",        group: "ANALYZE" },
  { screen: "report-center",    label: "Reports",         group: "ANALYZE" },
  { screen: "history",          label: "History",         group: "ANALYZE" },
  { screen: "pack-forge",       label: "Packs",           group: "BUILD"   },
  { screen: "settings",         label: "Settings",        group: "BOTTOM"  },
];
```

`navigateToScreen(screen)` works for all of them at all times. No phase checks.

### 5.2 Wizard — Remove Right Panel

```javascript
// DELETE: wizardSummaryPanel rendering
// REPLACE: inline context strip at bottom of wizard-main panel
// Shows confirmed items as pills only when context.confirmedCount > 0
function renderInlineContextStrip(wizard) {
  const confirmed = getConfirmedItems(wizard);
  if (confirmed.length === 0) return '';
  return `<div class="context-pills">
    ${confirmed.map(item => `<span class="chip">${item.label}: ${item.value}</span>`).join('')}
  </div>`;
}
```

### 5.3 Findings — Drawer Instead of Split Panel

```javascript
function openFindingDetail(findingId) {
  // Populate drawer content
  dom.findingDrawer.innerHTML = renderFindingDetail(finding);
  // Slide in
  dom.findingDrawer.classList.add('open');
  // Shrink list area (optional: add 'drawer-open' class to parent)
}
function closeFindingDetail() {
  dom.findingDrawer.classList.remove('open');
}
```

### 5.4 Remove Hero and Context Strip

Remove all DOM refs to:
- `dom.hero`, `dom.heroMetrics`
- `dom.flowOverview`, `dom.contextStrip`
- `dom.selectedEngagementSummary` (move to topbar engagement label)

---

## 6. What the UI Feels Like After

**Before navigating anywhere:**
```
[topbar: AegisPT | engagement | ⚙ | actor]
[sidebar: all screens listed]
[content: Intake screen — full width conversation]
```

**During an active run:**
```
[topbar: AegisPT | engagement | ● 3 tasks running | ⚙]
[sidebar: Mission Control highlighted]
[content: 3-column — scan map | task list + findings | AI signal]
```

**Reviewing a critical finding:**
```
[topbar: AegisPT | engagement | ⚙]
[sidebar: Findings highlighted]
[content: finding list | drawer open → risk gauge, evidence, remediation]
```

**Downloading a report:**
```
[topbar: AegisPT | engagement | ⚙]
[sidebar: Reports highlighted]
[content: run context strip + 2-col report cards, each with download buttons]
```

**Changing AI provider:**
```
[topbar: AegisPT | engagement | ⚙ highlighted]
[content: Settings → AI Provider section → Connect ChatGPT button]
```

---

## 7. Screens After Redesign

| # | Screen | Access | Notes |
|---|--------|--------|-------|
| 1 | Intake | Sidebar: Intake | Full width, inline context strip |
| 2 | Mission Control | Sidebar: Mission Control | 3-col: scan map / tasks / AI |
| 3 | Attack Map | Sidebar: Attack Map | SVG attack graph, asset browser |
| 4 | Findings | Sidebar: Findings | List + drawer detail |
| 5 | Reports | Sidebar: Reports | 2-col card grid |
| 6 | History | Sidebar: History | Comparison view |
| 7 | Packs | Sidebar: Packs | Pack forge and status |
| ⚙ | Settings | Topbar gear icon | Always accessible, not a numbered screen |

**8 screens total, all always reachable.** No phases. No gates. No wizard-first mandatory flow.

Evidence Replay and Explorer are merged into Findings (evidence panel in drawer) and Reports (dossier tab) respectively. Compatibility routes redirect with a notice.

---

## 8. Implementation Order

This spec maps to the following updated backlog items:

| Backlog | What | Effort |
|---------|------|--------|
| 52 (updated) | Topbar + sidebar structure, remove hero/phase-bar/context-strip, flat nav | 3–4 days |
| 53 | Ambient animations on new structure | 1 day |
| 54 | Scan map SVG | 2–3 days |
| 55 | AI signal panel | 1 day |
| 56 | ChatGPT OAuth | 2 days |
| 57 | Settings screen (built into new layout) | 2 days |
| 58 | Wizard inline context strip, remove right panel | 1 day |
| 59 | Findings drawer, report cards, screen consolidation | 2 days |

**Total: approximately 2.5–3 weeks of focused frontend work.**

The result is a UI that reads as a professional security operations tool rather than a wizard-wrapped script runner.

---

*This document is the authoritative redesign specification. It supersedes structural notes in PRODUCT_RECOMMENDATIONS.md sections 3.1–3.5 and LIVING_SYSTEM_EXPERIENCE.md section 2 where they conflict. The animation and live-ops specifications in LIVING_SYSTEM_EXPERIENCE.md remain valid and apply to the new structure.*
