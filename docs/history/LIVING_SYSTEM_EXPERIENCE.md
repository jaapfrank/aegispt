# AegisPT — The Living System Experience

**Date:** April 2026
**Concept:** AegisPT must feel like a living, breathing intelligence — not a script runner. The operator should feel like they are watching a skilled mind work. A spider that moves through a target environment with intent, awareness, and curiosity. Every moment something is happening. Every discovery feels significant. The operator cannot look away.

**Design philosophy:** Motion is meaning. Every animation communicates state, not decoration. The system does not animate to look impressive — it animates because something real is changing. When the spider finds something, you feel it.

---

## 1. The Core Problem With "Static Script" Feeling

The current system runs tasks, saves results, and displays data. This is correct. But it *feels* like a spreadsheet that updates every 5 seconds. The operator has no sense of:

- Where the system is looking right now
- What it is thinking as it processes output
- How discoveries relate to each other spatially
- Whether something significant just happened
- Whether the system is intelligent or just executing commands

The fix is not adding more data. The fix is giving the existing data **a physical presence in time and space**. The operator should be able to glance at the screen and instantly feel: something is happening here, it found something there, and this is what it means.

---

## 2. The Spider Metaphor — Design Language

Every visual decision should reinforce one mental model: **a spider moving through a digital environment, laying threads as it goes.**

| Element | Spider Metaphor | Visual Implementation |
|---------|----------------|----------------------|
| Active tools | Spiders at the edge of the web | Tool icons on the left, animated |
| Target hosts | Nodes in the web | Pulsing circles, sized by risk |
| Scan connections | Threads extending outward | Animated SVG lines, drawing in real-time |
| Findings | Prey caught in the web | Ripple on the node, badge appears |
| Critical finding | Significant catch — the web trembles | Brief full-screen amber flash, node glows red |
| Run complete | Web is finished | All threads solid, full picture visible |
| AI reasoning | The spider's awareness | Soft text streaming in a panel |

This is not metaphor as decoration. It is metaphor as navigation. The operator learns to read the web immediately. They never need to read labels.

---

## 3. The Living Scan Map — The Central Visual

This is the most important feature in this document. Everything else is supporting. The scan map during an active run is **the reason someone pulls out their phone to show a colleague.**

### 3.1 Layout

```
┌─────────────────────────────────────────────────────────────────────────┐
│                                                                         │
│  [nmap]  ════════════════════════════▶  ◉ 10.0.20.0/24    29 hosts     │
│                                                                         │
│  [httpx] ═══════════════════▶          ◉ api.example.com  ← scanning   │
│                              ╰──────▶  ◉ shop.example.com ← queued     │
│                                                                         │
│  [nuclei]  · · · · · · ▶              ◉ www.example.com               │
│                                                                         │
│  [zap]                                 ◉ staging.example.com           │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

Tool icons on the left edge. Target nodes on the right. SVG lines connecting them. The lines tell the whole story at a glance.

### 3.2 Line States and Animations

**Queued (not yet started):**
```css
stroke-dasharray: 4 8;
stroke: rgba(120, 177, 212, 0.25);
/* No animation — it exists but is dormant */
```

**Scanning (tool actively running against this target):**
```css
/* The line draws itself from left to right */
@keyframes thread-draw {
  from { stroke-dashoffset: 100%; }
  to   { stroke-dashoffset: 0%; }
}
stroke: var(--cyan);
stroke-dasharray: 100%;
animation: thread-draw 1.2s ease-out forwards;

/* Then a pulse flows along the drawn line */
@keyframes pulse-travel {
  0%   { stroke-dashoffset: 100%; opacity: 1; }
  100% { stroke-dashoffset: -100%; opacity: 0; }
}
/* Second SVG element on same path — the traveling pulse */
stroke: rgba(107, 215, 255, 0.6);
stroke-width: 2.5;
stroke-dasharray: 12 200;
animation: pulse-travel 1.6s ease-in-out infinite;
```

**Completed — no findings:**
```css
stroke: rgba(95, 224, 163, 0.45);
stroke-dasharray: none;
/* Solid, slightly faded — done, nothing of note */
```

**Completed — findings present:**
```css
stroke: var(--amber);
stroke-width: 2;
/* Solid, bright — something was caught here */
```

**Completed — critical finding:**
```css
stroke: var(--red);
stroke-width: 2.5;
filter: drop-shadow(0 0 4px var(--red));
/* The thread glows red */
```

### 3.3 Target Node States

Each target node is a circle. The circle changes visually through the scan lifecycle:

**Undiscovered / not yet targeted:**
```css
/* Faint outline only, no fill */
stroke: rgba(120, 177, 212, 0.2);
fill: none;
r: 12;
```

**Currently being scanned:**
```css
/* Pulsing ring — expanding circle that fades out */
@keyframes sonar-ring {
  0%   { r: 14; opacity: 0.8; stroke-width: 2; }
  100% { r: 28; opacity: 0;   stroke-width: 0.5; }
}
/* Inner filled circle */
fill: rgba(107, 215, 255, 0.15);
stroke: var(--cyan);
/* Outer sonar ring — second SVG circle on same center */
animation: sonar-ring 1.8s ease-out infinite;
```

**Scan complete — clean:**
```css
fill: rgba(95, 224, 163, 0.12);
stroke: var(--green);
```

**Scan complete — findings:**
```css
fill: rgba(255, 191, 97, 0.12);
stroke: var(--amber);
/* Finding count badge appears top-right of node */
```

**Critical finding landed:**
```css
@keyframes finding-hit {
  0%   { r: 12; fill: rgba(255, 125, 145, 0.3); stroke: var(--red); }
  30%  { r: 20; fill: rgba(255, 125, 145, 0.15); }
  100% { r: 12; fill: rgba(255, 125, 145, 0.12); stroke: var(--red); }
}
animation: finding-hit 0.6s ease-out forwards;
/* Then a ripple — SVG circle expanding from the node center */
@keyframes ripple-out {
  0%   { r: 12; opacity: 0.7; stroke-width: 2; }
  100% { r: 44; opacity: 0;   stroke-width: 0.5; }
}
```

### 3.4 Finding Badge Appearance

When a finding is discovered, a badge materializes at the target node:

```css
@keyframes badge-pop {
  0%   { transform: scale(0) translateY(4px); opacity: 0; }
  60%  { transform: scale(1.15) translateY(-2px); opacity: 1; }
  100% { transform: scale(1) translateY(0); opacity: 1; }
}
animation: badge-pop 0.35s cubic-bezier(0.34, 1.56, 0.64, 1) forwards;
```

Badge shows: finding count + severity color. Critical = red, high = amber, medium = yellow. If count increases, the number flips with a brief `rotateX(360deg)` counter animation.

### 3.5 The Web Completes

When the run reaches `completed`, all remaining dormant lines draw themselves in rapidly (200ms each, staggered 50ms). The full picture resolves. A brief ambient cyan glow pulses across the whole canvas once. The operator now has the complete web.

---

## 4. The AI Narrator — The Spider's Inner Voice

During an active run, the AI should narrate what is happening. Not status messages — actual intelligent commentary that makes the operator feel they are working alongside someone who understands what the tools are finding.

### 4.1 The AI Signal Panel

A persistent panel in Mission Control labeled **"AI Signal"** — not "AI Insights", not "AI Assistant". Signal implies something is being received. The panel streams text in real-time:

```
AI Signal                                              [LIVE ●]
──────────────────────────────────────────────────────────────
14:33:01  nmap completed — 29 hosts across /24 subnet
14:33:02  Significant: Apache 2.4.49 on 10.0.20.5 — CVE-2021-41773
          in CISA KEV. Queueing targeted nuclei scan.     [Approve ✓]
14:34:12  nuclei confirmed CVE-2021-41773 — path traversal
          without mod_cgi. RCE requires confirmation.
14:34:14  Chain signal: Redis :6379 reachable from .5 —
          SSRF + Redis = potential RCE chain. [View chain →]
14:35:01  httpx found 3 admin panels — /admin, /wp-admin, /phpmyadmin
          Cross-referencing with credential weakness findings...
```

Each entry slides in from below with a 200ms ease-out animation. The panel auto-scrolls. Text appears at typing speed (15ms per character for AI-generated lines) to create the impression of live thinking.

### 4.2 Entry Types and Visual Treatment

| Type | Color | Prefix | Behaviour |
|------|-------|--------|-----------|
| Tool completion | `--text-muted` | timestamp | Appears instantly |
| AI observation | `--text-soft` | timestamp | Types in character by character |
| AI alert (KEV/critical) | `--amber` | ⚡ | Types fast, amber left border |
| Chain detection | `--cyan` | ⬡ | Types in, link button appears |
| Proposal (needs approval) | `--cyan` | → | Inline [Approve] / [Skip] buttons |
| Error / anomaly | `--red` | ✕ | Appears with subtle red flash |

### 4.3 The "Thinking" Indicator

When the AI is processing a completed tool's output (the LLM call is in flight), show a subtle indicator:

```
AI Signal                                              [THINKING ···]
```

The three dots animate: `· · ·` → `· · ·` cycling with staggered opacity. This creates the impression that something intelligent is actually working. Never leave the panel idle — if no AI calls are in flight, show the last entry with a faint timestamp.

---

## 5. Task Swimlanes — The Tool Pipeline Lives

The task swimlane view in Mission Control shows the current state of every tool run:

### 5.1 Running Task — The Shimmer

```css
@keyframes shimmer-slide {
  0%   { background-position: -200% center; }
  100% { background-position: 200% center; }
}

.task-card[data-status="running"] {
  background: linear-gradient(
    90deg,
    rgba(10, 18, 31, 0.9) 0%,
    rgba(107, 215, 255, 0.08) 40%,
    rgba(107, 215, 255, 0.16) 50%,
    rgba(107, 215, 255, 0.08) 60%,
    rgba(10, 18, 31, 0.9) 100%
  );
  background-size: 200% 100%;
  animation: shimmer-slide 1.8s ease-in-out infinite;
  border-color: rgba(107, 215, 255, 0.35);
}
```

This single animation makes "something is running" obvious at a glance. The light sweeps left to right continuously. It stops the moment the task completes.

### 5.2 Task State Transitions

```
Queued:     ◌  [tool name]  [target]
Running:    ▶  [tool name]  [target]  ~~~shimmer~~~
Completed:  ✓  [tool name]  [target]  +3 ⚠  (finding badge if any)
Failed:     ✕  [tool name]  [target]  (red border)
```

State transitions use `transition: all 0.3s ease`. The shimmer stops, the border flashes green once, the checkmark appears.

### 5.3 Finding Count Badge Pop

When a task completes with findings, the badge appears with the pop animation from section 3.4. If there are 0 findings: the badge does not appear. If findings exist, the count shows with severity color. This creates variable feedback — sometimes nothing happens, sometimes a badge pops — which makes the moments when something IS found feel significant.

---

## 6. The Finding Counter — Numbers That Mean Something

The live finding counter in Mission Control should be visceral. Not a label that says "3 findings". A counter that makes you feel 3 things were found.

### 6.1 Counter Increment Animation

```css
@keyframes count-bump {
  0%   { transform: scale(1);    color: var(--text); }
  30%  { transform: scale(1.35); color: var(--amber); }
  60%  { transform: scale(1.1); }
  100% { transform: scale(1);    color: var(--text); }
}
```

When the count goes from 5 to 6: the number scales up, flashes amber, scales back down. Takes 0.4 seconds. Happens once per new finding.

### 6.2 Critical Finding — The Moment

When a finding of severity `critical` arrives, this is the most important event in the run. The UI should treat it as such:

```css
@keyframes critical-pulse {
  0%   { box-shadow: 0 0 0 0 rgba(255, 125, 145, 0); }
  40%  { box-shadow: 0 0 0 12px rgba(255, 125, 145, 0.3); }
  100% { box-shadow: 0 0 0 24px rgba(255, 125, 145, 0); }
}
```

The finding severity bar for "critical" pulses outward once. The scan map node for that target flashes red (section 3.3). The AI Signal panel immediately shows a new amber entry. The entire Mission Control screen dims by 8% for 600ms except for the finding counter area — a subtle vignette that says "pay attention here".

### 6.3 Severity Bars — Living Growth

```css
.severity-bar-fill {
  transition: width 0.6s cubic-bezier(0.34, 1.56, 0.64, 1);
  /* Slight spring overshoot makes the bar feel alive, not mechanical */
}
```

As findings arrive between polls, bars grow with a spring animation. The number next to each bar flips with a brief `rotateX` counter flip animation (50ms).

---

## 7. The Terminal — Raw Intelligence Made Visible

The live stdout terminal panel during an active task is where the operator feels closest to the actual work. It should feel like watching a colleague's screen.

### 7.1 Visual Design

```
┌─ nuclei v3.3.1  ·  api.example.com  ·  running ─────── [copy] ─┐
│                                                                  │
│  [INF] Templates: 847 loaded, 23 matched scope                  │
│  [INF] Targets: 1                                               │
│  [CVE-2023-44487] api.example.com:443 [critical]                │ ← red
│  [http-missing-security-headers] /api [info]                    │
│  [sqli-error-based] /graphql [high]                             │ ← amber
│  _                                                              │
│                                                                  │
└──────────────────────────────────────────────────────────────────┘
```

- Background: `#0a0f1a` (slightly lighter than the main bg — visible separation)
- Font: monospace — `"JetBrains Mono", "Fira Code", "Cascadia Code", monospace`
- Tool badge in header: cyan for nuclei, amber for zap, green for nmap, violet for semgrep
- Lines matching `[critical]`, `CVE-`, `CRITICAL` → `color: var(--red)`, subtle red left border
- Lines matching `[high]`, `HIGH` → `color: var(--amber)`
- Lines matching `[INF]`, `[info]` → `color: var(--text-muted)` — less prominent

### 7.2 New Line Animation

Each new line entering the terminal:
```css
@keyframes line-appear {
  from { opacity: 0; transform: translateX(-6px); }
  to   { opacity: 1; transform: translateX(0); }
}
.terminal-line {
  animation: line-appear 0.12s ease-out forwards;
}
```

Subtle. The line slides in from the left. Fast — 120ms. Creates a typing/stream impression without being distracting.

### 7.3 The Cursor

A blinking cursor `_` at the end of the last line while the task is running. Disappears when the task completes. One line: `animation: blink 1.1s step-start infinite`.

### 7.4 Critical Line — The Flash

When a critical-severity line arrives (`[critical]`, `CRITICAL`, `CVE-` with `critical`):
```css
@keyframes critical-line-flash {
  0%   { background: rgba(255, 125, 145, 0.18); }
  100% { background: rgba(255, 125, 145, 0); }
}
.terminal-line.critical {
  animation: line-appear 0.12s ease-out, critical-line-flash 1.2s ease-out 0.12s;
  color: var(--red);
  padding-left: 0.6rem;
  border-left: 2px solid var(--red);
}
```

The entire line flashes red briefly, then fades to a subtle left border. The operator does not need to read — the colour tells them this line matters.

---

## 8. The Mission Launch Sequence

The moment between "Create Mission" and "watching it run" is the most emotionally significant transition in the entire product. Currently it is silent. It should be a ceremony.

### Step 1: Mission Created Overlay (1.2s)

When `submitWizard()` resolves:
- A full-screen overlay appears with `opacity: 0 → 1` over 200ms
- Content: large mission name, engagement label, and a brief "Mission locked. Deploying." message
- Background: semi-transparent deep navy with a single cyan glow at center
- After 1.2 seconds, the overlay fades out and navigates to Mission Control

```css
@keyframes mission-created-in {
  from { opacity: 0; transform: scale(0.96); }
  to   { opacity: 1; transform: scale(1); }
}
@keyframes mission-created-out {
  from { opacity: 1; }
  to   { opacity: 0; }
}
```

### Step 2: Run Card Materialize (Mission Control)

The new run card in Mission Control enters with:
```css
@keyframes card-materialize {
  0%   { opacity: 0; transform: scale(0.94) translateY(8px); }
  70%  { opacity: 1; transform: scale(1.02) translateY(-2px); }
  100% { transform: scale(1) translateY(0); }
}
animation: card-materialize 0.45s cubic-bezier(0.34, 1.56, 0.64, 1);
```

A brief cyan border glow on the new card: `box-shadow: 0 0 0 2px var(--cyan)`, fades over 1.5s.

### Step 3: "Start Validation" Pulse

The primary action button pulses once to draw the eye:
```css
@keyframes cta-pulse {
  0%, 100% { box-shadow: 0 0 0 0 rgba(107, 215, 255, 0); }
  50%       { box-shadow: 0 0 0 8px rgba(107, 215, 255, 0.3); }
}
animation: cta-pulse 1.4s ease-in-out 2;  /* pulses twice then stops */
```

### Step 4: Scan Map Loads

As the scan map renders, target nodes appear one by one with a staggered pop animation:
```css
/* Each node, staggered 80ms */
animation: badge-pop 0.3s cubic-bezier(0.34, 1.56, 0.64, 1) forwards;
animation-delay: calc(var(--node-index) * 80ms);
```

The operator watches their targets appear, then watches the first tool threads begin to draw.

---

## 9. Run Completion — The Full Web

When a run reaches `completed`, the system has finished its work. This deserves a visual resolution.

### 9.1 The Web Settles

All remaining animated (scanning) lines transition to their final state simultaneously:
- Shimmer stops on all task cards
- Scanning lines instantly switch to their completed style (green or amber depending on findings)
- Dormant/queued lines for tasks that didn't run fade out gently

### 9.2 The Summary Pulse

A single ambient pulse across the entire scan map canvas:
```css
@keyframes map-complete-pulse {
  0%   { background: rgba(95, 224, 163, 0); }
  30%  { background: rgba(95, 224, 163, 0.06); }
  100% { background: rgba(95, 224, 163, 0); }
}
animation: map-complete-pulse 1.0s ease-out forwards;
```

The canvas briefly takes a green tint. The run is done.

### 9.3 The Result Summary Card

A card slides up from the bottom of Mission Control (or appears above the scan map):
```
┌──────────────────────────────────────────────────────────────┐
│  Run complete  ·  12m 34s                                    │
│  3 critical  ·  6 high  ·  5 medium  ·  2 low               │
│  2 vulnerability chains detected                             │
│  [View Findings →]    [Generate Report →]                    │
└──────────────────────────────────────────────────────────────┘
```

Slide-up animation, 350ms. The critical count is in `var(--red)`. This is the transition moment — run is complete, analysis is next. The buttons do the navigation.

---

## 10. The Finding Card — An Intelligence Brief

When the operator clicks a finding, the detail panel should feel like opening a classified document.

### 10.1 Card Open Animation

```css
@keyframes brief-open {
  from { opacity: 0; transform: translateY(12px); }
  to   { opacity: 1; transform: translateY(0); }
}
animation: brief-open 0.25s ease-out;
```

### 10.2 The Risk Gauge

An SVG arc gauge at the top of the finding card. The needle/arc draws itself:
```css
@keyframes gauge-draw {
  from { stroke-dashoffset: 100%; }
  to   { stroke-dashoffset: calc(100% - (risk_score / 10) * 100%); }
}
animation: gauge-draw 0.8s ease-out forwards;
animation-delay: 0.1s;  /* Brief pause after card opens */
```

The arc color: green → yellow → amber → red based on score. The needle physically moves to the risk position. This is the first visual in the finding card and immediately conveys severity without reading.

### 10.3 Methodology Chain Animation

The PTES → WSTG → NIST → ASVS pill chain builds left to right, each pill appearing with a 60ms stagger:
```
[PTES: Exploitation] →60ms→ [WSTG-INPV-01] →60ms→ [NIST: Execution] →60ms→ [ASVS L2]
```

```css
.methodology-pill {
  opacity: 0;
  transform: translateX(-8px);
  animation: pill-appear 0.2s ease-out forwards;
}
.methodology-pill:nth-child(1) { animation-delay: 0.05s; }
.methodology-pill:nth-child(2) { animation-delay: 0.11s; }
.methodology-pill:nth-child(3) { animation-delay: 0.17s; }
.methodology-pill:nth-child(4) { animation-delay: 0.23s; }
```

### 10.4 Threat Intel Badge Flash

If the finding matches a CISA KEV entry, the KEV badge flashes amber once on appearance:
```css
@keyframes kev-alert {
  0%   { background: rgba(255, 191, 97, 0.5); }
  100% { background: rgba(255, 191, 97, 0.15); }
}
.badge-kev { animation: kev-alert 1.0s ease-out forwards; }
```

---

## 11. System Ambience — The Baseline "Alive" Feel

Even when nothing is actively running, the UI should breathe. Not constantly — only with meaning.

### 11.1 The Active Run Indicator

When a run is active, a small dot in the top context strip pulses:
```css
@keyframes live-dot {
  0%, 100% { opacity: 1;   transform: scale(1); }
  50%       { opacity: 0.5; transform: scale(0.7); }
}
.live-dot[data-active="true"] {
  background: var(--cyan);
  animation: live-dot 1.4s ease-in-out infinite;
}
```

This is the heartbeat of the system. When it pulses, something is alive.

### 11.2 The AI Signal Typing Effect

When the AI generates a new entry, it types at 12ms per character. Not instant — streaming. This is the most effective single technique for making the AI feel present and intelligent. The operator watches words appear as if the system is composing its thoughts in real time.

Implementation:
```javascript
async function typeText(element, text, delay = 12) {
  element.textContent = '';
  for (const char of text) {
    element.textContent += char;
    await new Promise(r => setTimeout(r, delay));
  }
}
```

Critical or high-urgency lines type faster (6ms/char). Normal observations type at 12ms/char. This variable speed itself communicates urgency.

### 11.3 Reduced Motion Respect

All animations must respect `prefers-reduced-motion`:
```css
@media (prefers-reduced-motion: reduce) {
  *, *::before, *::after {
    animation-duration: 0.01ms !important;
    transition-duration: 0.01ms !important;
  }
}
```

The system works without animation. Animation is enhancement, not function.

---

## 12. Micro-Interactions

Small moments that make every interaction feel physical and intentional.

### 12.1 Button Press Feedback

```css
.action:active {
  transform: scale(0.96);
  transition: transform 0.08s ease;
}
```

Buttons physically compress on click. 80ms — fast enough to feel instantaneous but perceptible.

### 12.2 Card Hover Intelligence

Finding cards in the queue show a subtle preview on hover — the severity color bleeds into the card border:
```css
.finding-card:hover {
  border-color: var(--severity-color);
  background: color-mix(in srgb, var(--severity-color) 4%, var(--panel));
  transform: translateX(3px);
  transition: all 0.15s ease;
}
```

The 3px rightward slide says "this is interactive, click to go deeper."

### 12.3 The Engagement Switch

When the operator changes the engagement dropdown, the context strip briefly dims and rebuilds:
```css
@keyframes context-reload {
  0%   { opacity: 1; }
  30%  { opacity: 0.4; }
  100% { opacity: 1; }
}
```

The main content area does the same. 400ms. Communicates that state is being loaded.

### 12.4 Empty State Breathing

Empty states should not be dead. A subtle icon pulse on empty state illustrations:
```css
@keyframes empty-breathe {
  0%, 100% { opacity: 0.35; transform: scale(1); }
  50%       { opacity: 0.5;  transform: scale(1.04); }
}
.empty-icon {
  animation: empty-breathe 3.2s ease-in-out infinite;
}
```

Slow and subtle. Says "the system is ready, waiting for you."

---

## 13. Sound Design (Optional — High Impact)

Sound is the single most underused technique in enterprise security tools. Used sparingly and purposefully, it makes discoveries visceral.

### 13.1 Sound Events

| Event | Sound | Character |
|-------|-------|-----------|
| New finding (medium/low) | Soft ping | 220Hz sine, 80ms, -18dB |
| New finding (high) | Deeper ping | 180Hz sine, 120ms, -14dB |
| Critical finding | Two-tone alert | 180Hz + 270Hz, 200ms, -10dB |
| Run complete | Resolution chord | 3-note ascending, 400ms, -16dB |
| Tool failure | Low thud | 80Hz, 150ms, -14dB |
| Chain detected | Harmonic chime | 330Hz + 495Hz, 250ms, -15dB |

All sounds are generated via Web Audio API — no audio files, no HTTP requests, no latency.

```javascript
function playFinding(severity) {
  const ctx = new AudioContext();
  const osc = ctx.createOscillator();
  const gain = ctx.createGain();
  osc.connect(gain); gain.connect(ctx.destination);
  osc.frequency.value = severity === 'critical' ? 180 : severity === 'high' ? 200 : 220;
  gain.gain.setValueAtTime(0.08, ctx.currentTime);
  gain.gain.exponentialRampToValueAtTime(0.001, ctx.currentTime + 0.25);
  osc.start(); osc.stop(ctx.currentTime + 0.25);
}
```

**Critical rule:** Sound must be opt-in. A toggle in settings: `Sound cues: Off / Subtle / Full`. Default: Off. When enabled, the first sound plays and the operator immediately understands the semantic — each subsequent sound is recognised without looking at the screen.

---

## 14. The AI Copilot Persistent Presence

The AI should never feel like a feature you navigate to. It should feel like a colleague who is always present.

### 14.1 The AI Pulse Badge

A small badge in the left rail, below the navigation items, during an active run:

```
◉ AI observing                    ← pulses with live-dot animation
```

Click → opens the AI Signal side panel. The badge shows:
- `◉ AI observing` — AI is active, analysing
- `◉ AI found something` — amber dot, a new proposal or observation exists
- `◉ 3 proposals` — cyan, proposals awaiting approval
- `○ AI disabled` — grey, deterministic mode

### 14.2 AI Annotation on Findings

In the finding list, findings that have AI enrichment show a small cyan AI badge. Findings that have a chain detection show a chain link icon. Findings that match CISA KEV show a small amber shield. These are scannable at a glance — the operator knows which findings have more depth before clicking.

### 14.3 The Proposal Inline Approval

AI proposals should not require navigating to a separate panel. In the AI Signal feed, each proposal has inline `[Approve]` / `[Skip]` buttons. Approving fires a `POST` to `/api/v1/runs/{run_id}/ai-insights/{proposal_id}/review`, then the proposal entry in the feed changes to:

```
14:34:02  → Queuing nuclei CVE-2021-41773 scan on 10.0.20.5    [✓ Approved]
```

The `[✓ Approved]` is green and fades from green to muted over 2 seconds. The operator glances, taps, and continues. The AI and operator are in rhythm.

---

## 15. Implementation Priority

These are ordered by visual impact per implementation hour.

| Priority | Feature | Effort | Impact |
|----------|---------|--------|--------|
| 1 | Task shimmer animation (running state) | 1 hour CSS | Constant visible motion — immediate "alive" feeling |
| 2 | AI Signal typing effect | 2 hours JS | Makes AI feel present and intelligent |
| 3 | Critical finding flash (node + counter + terminal) | 2 hours | Makes discoveries feel significant |
| 4 | Severity bars with spring animation | 1 hour CSS | Numbers grow as things are found |
| 5 | Scan map basic (SVG nodes + static lines) | 3 days JS | The central wow visual |
| 6 | Scan map animated threads (draw-in + pulse travel) | 1 day CSS/JS | Lines that breathe |
| 7 | Terminal panel with typed lines + cursor | 1 day JS | Raw output feels alive |
| 8 | Badge pop on finding discovery | 2 hours JS/CSS | Each finding lands with weight |
| 9 | Mission launch sequence | 1 day JS/CSS | Ceremony before the hunt begins |
| 10 | Run completion resolution | 0.5 days | Web settles — story complete |
| 11 | Sound design (opt-in) | 1 day JS | Critical findings you hear before you see |
| 12 | Finding card gauge + methodology chain | 1 day | Intelligence brief opens with purpose |
| 13 | Micro-interactions (hover, press, reload) | 0.5 days | Everything responds |
| 14 | Empty state breathing | 2 hours | System alive even at rest |

**Week 1 minimum viable "living system":** Items 1–4. Four items, approximately 6–7 hours of work. The system will feel fundamentally different. Running tasks shimmer. The AI panel types. Finding counters flash. Severity bars grow. That is enough to change the first impression entirely.

**Week 2 full experience:** Items 5–10. The scan map is the centrepiece that makes demos unforgettable.

**Week 3 polish:** Items 11–14. The system is now complete as a sensory experience.

---

## 16. What Makes This Genuinely Different

Pentera has a dark dashboard. NodeZero has a graph. Cobalt has clean cards.

None of them have:

- A live "spider web" that draws itself as the scan progresses
- An AI that types its observations in real-time as it watches tool output
- A critical finding event that briefly dims the screen and pulses the node
- A run completion animation that "settles" the web and presents a summary
- An AI copilot that is always visibly present with inline approval from the feed
- Sound cues that tell you something significant was found before you look at the screen

These are not features. They are the emotional experience of using the product. A security consultant demoing AegisPT to a CISO does not say "and here you can see the findings list." They say "watch what happens when it finds something critical" — and then something unmistakably significant happens on screen.

That is the product that wins.

---

*This document is the companion to `AI_PENTESTING_AGENT.md` and `PRODUCT_RECOMMENDATIONS.md`. The three documents together describe the complete product direction: what to build (PRODUCT_RECOMMENDATIONS), how the AI should reason (AI_PENTESTING_AGENT), and how the experience should feel (this document).*
