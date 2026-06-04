# Codex UI/Reporting UX System Audit - 2026-06-03

## Scope

This audit reviews the React v2 UI and reporting experience after the recent
Mission Control, attack-map, Live CLI, report, and evidence repairs. It is an
analysis artifact only; no product code was changed in this pass.

Codex stayed in the UI/reporting lane. Claude-owned score-lane files, active
runner/scoring files, `NEXT_TASK.md`, and `TASK_QUEUE.md` were not touched.

## Method

- Read `docs/strategy/codex-universal-execution-contract.md`,
  `CURRENT_STATE.md`, `NEXT_TASK.md`, `DECISIONS.md`, `DONE_LOG.md`, and
  `docs/strategy/codex-ui-reporting-worklist-2026-06-01.md`.
- Ran `ui-v2` locally on `http://127.0.0.1:5176/app-v2/` for screenshot
  inspection, then stopped only that audit server.
- Queried live backend state through `/api/v1/engagements` and
  `/api/v1/dashboard`.
- Captured first-viewport screenshots and DOM summaries for the primary UI
  routes using Playwright with `domcontentloaded`. `networkidle` is unsuitable
  for these live/SSE routes because polling can keep the page active.
- Simulated a light theme by overriding CSS variables in the browser to test
  feasibility and identify hardcoded dark surfaces.
- Calibrated the review against core UI principles:
  status visibility, match with the user's language, recognition over recall,
  useful error recovery, accessibility contrast/focus/reflow, semantic color
  systems, and plain-language content design.

## Overall Verdict

The UI has moved in the right direction, especially Mission Control and Live
CLI, but it is not yet a coherent product experience. It still feels like a set
of screens showing data instead of one guided assessment story that makes the
operator feel where the system is, what just happened, why it matters, and what
to do next.

The largest gap is not visual polish alone. The main issue is information
architecture: the same mission-spine idea appears everywhere, but each page does
not yet have a clear job, a single primary answer, a clear next action, and a
controlled drilldown path.

## Evidence From Route Audit

The Playwright route audit found these approximate first-viewport text volumes:

- Dashboard: 2,156 characters, 8 buttons, 7 links.
- Intake: 3,235 characters, 29 buttons.
- Mission Control: 2,935 characters, 12 buttons, 8 links.
- Live CLI: 1,953 characters, 7 buttons.
- Surface Map: 789 characters, 11 buttons.
- Evidence Replay: 8,653 characters, 13 buttons.
- Findings Theater: 9,608 characters, 36 buttons.
- Report Center: 4,252 characters, 23 buttons.
- History: 1,843 characters, 10 buttons.
- Problems Center: 19,081 characters, 11 buttons.
- Packs: 815 characters, 8 buttons.
- Custom CVE Library: 931 characters, 10 buttons.
- Research: 144 characters, 0 buttons, raw API failure shown.
- Settings: 1,850 characters, 19 buttons.

These numbers match the operator feedback: several pages still ask the user to
read too much before the product tells them what matters.

## Critical UX Findings

1. The product story is fragmented.
   Mission Control has the best direction, but Dashboard, Evidence Replay,
   Findings, Problems, Reports, and History do not consistently reuse the same
   "where are we, what happened, what changed, what do I do next" experience.

2. Too many pages lead with data instead of a decision.
   The first viewport often contains multiple panels, counters, labels, and
   repeated metadata. The user must interpret the state themselves.

3. The visuals are not yet carrying enough meaning.
   The attack map, impact donut, severity bars, and route strip are promising,
   but many charts are still summary decoration instead of explaining cause,
   time, dependency, progress, and consequence.

4. The UI does not always feel live.
   Mission Control can say a task is running, but there is limited motion,
   live command/output pulse, event sequencing, or visible state transition.
   The product needs to feel like the system is actively working, not like a
   static dashboard that occasionally refreshes.

5. Truth consistency still needs stronger product handling.
   The Report Center showed a raw AI-provider billing error in the operator UI.
   Research showed `AegisPT API request failed: 500` and no selected engagement.
   History showed an empty result after exposing many engagements in the filter.
   These states weaken trust even when backend truth is technically correct.

6. Findings and Problems are too list-heavy.
   Findings repeats similar rows and hides remediation/context in detail areas.
   Problems exposes a large cross-engagement dataset without first answering:
   what is urgent, who owns it, what changed, and what should happen today.

7. Reports are not yet management-grade as a product surface.
   Backend tests now assert standards, attack-map story, techniques, attacker
   path, and remediation sections, but the Report Center still makes generation
   failure look raw and technical. Management needs a composed story, fallback
   narrative, standards badges, evidence basis, and action plan before export.

8. Secondary/admin pages inherit too much mission cockpit weight.
   Packs, CVE Library, Settings, and similar pages need a compact context bar,
   not the same full mission experience as active assessment pages.

## Page-by-Page Verdict

### Dashboard

Good base for a portfolio view, but it should answer one thing first: "where is
my security program hurting right now?" The mission spine dominates the top of a
page that should mostly summarize portfolio risk and next work. The dashboard
needs clearer risk ranking, fewer generic empty-state panels, and a visual trend
that explains change over time.

### Intake

The guided intake direction is promising, but the page exposes too many choices
and buttons early. It should behave more like a wizard conversation: describe
the mission, see what AegisPT understood, confirm scope/ROE/depth, then launch.
The user should not have to understand every assessment family up front.

### Mission Control

This is the strongest screen and should become the emotional center of the
product. It still needs more live behavior: animated active step, command/output
preview, event beats, elapsed time, waiting reason, and click-to-open detail.
The current path and full map must always match the selected mission/run and
must show all relevant proof steps and timings, not grouped cards that obscure
what actually happened.

### Live CLI

Technically useful after the command-output repair. It now shows command-style
output and expanded stdout/stderr, but it should add a clearer command/event
timeline, line wrapping modes, copy/download, and "no output yet" explanations.
This page is for technical operators, so dense output is acceptable here.

### Surface Map

Too thin for its job. It currently reads more like an inventory table than a
surface map. It should visualize hosts, ports, endpoints, services, confidence,
and which attack-path steps touched each item.

### Evidence Replay

Rich in facts but too heavy. Evidence Replay should be a replay timeline:
what was attempted, what output was captured, which artifacts prove it, and
which finding/report statement depends on it. The current page contains useful
truth but makes the user read too much.

### Findings Theater

The page contains important information, but it is not yet a reviewer cockpit.
It needs grouping/deduplication, clear severity priority, business impact,
proof strength, remediation owner, and next action visible before raw lists.
Repeated "Hidden Endpoint Discovered" rows make it feel less intelligent than
the data probably is.

### Report Center

The truth-pipeline idea is good. The page must handle report generation failure
without exposing provider internals. It should always show a fallback management
brief based on canonical evidence, standards used, attack-map path, techniques
in plain language, engineering fixes, IT/operations fixes, and missing-evidence
warnings.

### History

Useful as an audit ledger, but the current empty-state/filter behavior is
confusing. It should explain why no runs match and provide one-click filter
reset or selected-engagement narrowing.

### Problems Center

The data volume is high. This should become a triage board: urgent now, due
soon, owner, SLA, affected systems, and fix status. The page should start with
the small set of decisions an operator or manager needs today.

### Packs and CVE Library

These are admin/build surfaces and are comparatively simple. They should use a
lighter context treatment and stronger empty states that explain what adding a
pack or custom CVE changes in the governed runtime.

### Research

Currently broken as a user experience. It shows a raw `500` and "No engagement
selected". It needs a safe failure state, selected-engagement recovery, and a
clear explanation that research is advisory and evidence-linked.

### Settings

Settings is one of the clearer pages. It already uses cards and semantic
sections reasonably well. It still needs stricter error messaging and theme
controls if light mode is added.

## Reporting and PDF Quality

The report generator has moved closer to the requested management story in
tests, but the product must prove this end to end in the UI and exported PDFs.
Management reports should not merely list findings. They need:

- A short executive answer: what is the risk, how urgent is it, who must act.
- A plain-language attack story: what the system did, what path worked, and why
  that matters.
- A visual attack map that matches the actual run evidence and findings.
- Standards used: PTES, OWASP WSTG, NIST SP 800-115, and optional ASVS mappings
  where applicable, shown as badges/icons and described in plain language.
- Techniques used in plain language, tied to the actual tasks/tools observed.
- What an attacker would need to do, without becoming a how-to exploit guide.
- What engineering should change in code/configuration.
- What IT/operations should change in deployment, monitoring, access, or
  patching.
- Evidence citations that let a reviewer verify each claim.
- Clear "tested", "not tested", and "not proven" sections.

If AI drafting is unavailable, the UI should still generate a deterministic
evidence-based fallback narrative. Raw provider errors should be hidden behind a
safe operator message and logged in diagnostics only.

## Light Mode Feasibility

Light mode is feasible, but it should not start as a simple toggle. A simulated
light theme worked on token-driven surfaces such as Settings, but Dashboard,
Mission Control, Reports, charts, SVG maps, and terminal panels kept hardcoded
dark colors.

Required work before a reliable light mode:

1. Add a real theme contract: `data-theme`, `color-scheme`, persisted user
   preference, and system preference fallback.
2. Expand semantic tokens for app background, panels, elevated panels, terminal
   surfaces, chart colors, attack-map edges, severity colors, focus rings, and
   disabled states.
3. Replace hardcoded dark colors in Mission Control, Mission Experience Spine,
   Surface Map SVG, report truth charts, terminal panels, and legacy app CSS.
4. Validate contrast, hover/focus states, selected states, and chart legibility
   in dark and light themes.
5. Capture screenshots at 1536x864, 1280x720, and browser zoom levels that
   approximate 125% and 150% user scaling.

## Recommended Work Order

1. Fix trust-breaking states first:
   Research raw `500`, Report Center raw AI billing error, confusing History
   empty state, and any Dashboard/Mission risk mismatch.

2. Define a shared page pattern:
   every route should have one primary answer, one primary action, one evidence
   summary, and progressive drilldown. Secondary/admin pages should get a
   compact context bar.

3. Make Mission Control feel alive:
   live route animation, command/output strip, event pulse, elapsed timings,
   queue reason, and real transition/replay states.

4. Rebuild Evidence and Findings around review flow:
   evidence timeline, finding groups, proof strength, remediation owner, and
   "what changed since last review".

5. Rebuild Report Center as a management workflow:
   deterministic fallback brief, standards badges, attack-map preview,
   management/engineering/IT sections, and export readiness checks.

6. Add light mode after token cleanup:
   ship dark/light as one design system, not two separate skins.

## Acceptance Gates For The Next UX Pass

- Screenshots must be reviewed for every primary route at 1536x864 and 1280x720.
- Mission Control full attack map must support pan, wheel zoom, fit, and
  selected-run truth binding.
- Attack path must show actual task order, branch/dead-end logic, proof/finding
  steps, timestamps, and elapsed durations.
- Findings count and attack-map proof nodes must not contradict each other.
- Live CLI must show commands and stdout/stderr for ordinary tasks, not only
  findings.
- Report Center must never expose raw provider billing or stack errors.
- Management PDF must include standards, attack map, techniques, plain-language
  impact, and concrete remediation for engineering and IT/operations.
- `git diff --check` must stay clean after documentation/code updates.

## Reference Principles Used

- Nielsen Norman Group, 10 usability heuristics:
  https://www.nngroup.com/articles/ten-usability-heuristics/
- WCAG 2.2 quick reference for contrast, focus, keyboard, and reflow:
  https://www.w3.org/WAI/WCAG22/quickref/
- Material Design color system and semantic color roles:
  https://m3.material.io/styles/color/overview
- GOV.UK plain-language/content design guidance:
  https://www.gov.uk/guidance/content-design/writing-for-gov-uk
