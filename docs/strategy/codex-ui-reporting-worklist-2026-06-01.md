# Codex UI + Reporting Worklist (Non-Conflicting)

Date: 2026-06-01
Owner: Codex
Status: W0 complete, not promoted to `NEXT_TASK.md`

## Purpose

This worklist is Codex's separate lane for product-truth UI, accessibility,
reporting, and evidence presentation improvements. It intentionally lives
outside the active Claude score-lane task so both agents can work without
stepping on each other's files or queue state.

This is a coordination document, not the active repo task. Do not promote it
into `NEXT_TASK.md` unless the operator explicitly asks for that handoff.

## North-star for this lane

Build an operator UI and report stack that is:

- truthful live
- accessible and calm to work in
- clear about process and validation state
- strict about canonical score/finding/report consistency
- evidence-first in both UI and exported reports
- LLM-assisted only for wording, never for inventing facts

## Non-overlap contract with Claude

### Claude-owned active lane (do not touch unless operator explicitly approves overlap)

- `NEXT_TASK.md`
- `TASK_QUEUE.md`
- `api/app/services/assessment_loop.py`
- `api/app/services/assessment_loop_internals/guards.py`
- `api/app/services/m2_verdict_gate.py`
- `workers/orchestration/tasks.py`
- `workers/runners/interactive_exploit/**`
- active score-lane validation artifacts under `docs/validation/` that are tied
  to XBEN / focused-assessment / solver throughput

### Codex-owned lane for this worklist

- `ui-v2/src/**`
- `ui-v2/tests/**`
- `ui/index.html` only if legacy UI truth gaps must be patched during the same lane
- `api/app/services/reports.py`
- `api/app/services/report_pdf.py`
- `api/app/schemas/report_center.py`
- `api/app/routers/runs.py` for report/export/read-model wiring only
- report- and evidence-centered docs under `docs/strategy/` and `docs/validation/`

### If overlap becomes necessary

If a required fix crosses into Claude-owned files:

1. stop before editing the overlapping file
2. record the exact blocker and file in `DONE_LOG.md`
3. either wait for operator approval or prepare a narrow handoff note

Do not silently merge work into the active score-lane files.

## Git hygiene rules for parallel work

Before each Codex session in this lane:

1. read `CURRENT_STATE.md`, `NEXT_TASK.md`, `DECISIONS.md`
2. run `git status --short`
3. confirm changed files stay inside the Codex-owned lane above
4. if unrelated dirty files exist, leave them alone
5. never clean up Claude's worktree by reverting or reformatting shared files

Before stopping:

1. update `DONE_LOG.md`
2. update `CURRENT_STATE.md`
3. update `DECISIONS.md` if a durable UI/reporting decision was made
4. run relevant lint/tests for touched files
5. run `git diff --check`
6. leave a narrow, understandable diff

## Canonical product rules for this lane

These rules govern every task below:

1. The UI must show one canonical truth for run status, findings, validation,
   report readiness, and score.
2. A finding shown as "verified" in the UI must be backed by the same truth
   source used by the report builder.
3. A management report may only discuss tested scope and evidence-backed
   outcomes.
4. LLM-generated report text may summarize and phrase, but may not invent
   findings, scope, business impact, tested components, or remediation facts.
5. The report stack must clearly separate:
   - management summary
   - technical detail
   - raw evidence / proof export
6. The UI must make process state obvious:
   - queued
   - running
   - observed
   - verified
   - persisted
   - blocked / failed

## Workstreams

### W0 — UI truth audit and source map

Goal:
Build a concrete truth map for current UI surfaces, report variants, and
evidence/detail views.

Deliverables:

- inventory of current UI truth gaps
- screen-by-screen mapping of which API/source drives each displayed state
- list of contradictory or stale values

Likely touched files:

- `docs/validation/*ui*`
- `docs/strategy/*ui*`
- maybe small read-only test fixtures

Proof:

- a repo artifact documenting the truth map and mismatch list

### W1 — Live run truth strip and operator state model

Goal:
Make the operator-facing run state clear, stable, and live.

Scope:

- mission/run status surfaces
- validation/proof state
- persistence state
- canonical score summary

Requirements:

- no mixed or vague statuses
- clearly show whether a solve is merely observed or fully persisted
- surface "why this is blocked" when the truth chain is incomplete

Likely touched files:

- `ui-v2/src/**`
- `ui-v2/tests/**`
- read-only API wiring if required in `api/app/routers/runs.py`

Proof:

- UI tests showing the real state progression
- screenshots or validation artifacts for the affected views

### W2 — Findings Theater truth pass

Goal:
Make Findings Theater reflect evidence, validation, and business meaning
without theater or ambiguity.

Requirements:

- finding status visible and canonical
- evidence summary separate from business impact summary
- remediation and next-step language only from supported data
- no raw exploit-runner labels as primary operator copy if a better normalized
  title exists

Likely touched files:

- `ui-v2/src/**`
- `ui-v2/tests/**`

Proof:

- theater view tests for verified vs observed vs blocked findings
- artifact demonstrating that a known finding shows the correct truth chain

### W3 — Evidence Replay clarity pass

Goal:
Turn evidence surfaces into something an operator can actually trust and scan.

Requirements:

- run-level executions, artifacts, and provenance linked clearly
- evidence state separated from conclusion state
- transcript/provenance visible without forcing the user to infer too much

Likely touched files:

- `ui-v2/src/**`
- `ui-v2/tests/**`

Proof:

- UI validation for evidence layout, live detail loading, and provenance labels

### W4 — Report Center overhaul

Goal:
Make Report Center truthful, readable, and operationally useful.

Requirements:

- clear separation between report variants
- preview tied to canonical run context
- visible "what will be included" and "what is excluded/not tested"
- no internal benchmark/lab junk in customer-facing variants
- report counts must match canonical findings truth

Likely touched files:

- `ui-v2/src/**`
- `ui-v2/tests/**`
- `api/app/services/reports.py`
- `api/app/services/report_pdf.py`
- `api/app/routers/runs.py`

Proof:

- exported report samples
- UI preview tests
- consistency checks between report contents and canonical findings

### W5 — Evidence-backed LLM report composition

Goal:
Use an LLM to draft report language only from structured, evidence-backed
report payloads.

Requirements:

- input payload contains only tested scope and supported findings
- explicit field for "not tested / not verified" content
- LLM output is review-only phrasing, not canonical fact generation
- management report and technical report use different templates and constraints
- raw proof export remains non-LLM and deterministic

Likely touched files:

- `api/app/services/reports.py`
- `api/app/schemas/report_center.py`
- `api/app/routers/runs.py`
- `ui-v2/src/**` if preview/explanation changes are needed
- `ui-v2/tests/**`

Must not do:

- no silent widening of scope in report text
- no unsupported claim generation
- no report section for untested targets

Proof:

- structured payload snapshot
- before/after report artifact
- tests showing only included tested components appear in the final draft

### W6 — Management-report rewrite rules

Goal:
Make management reports read like customer-ready management documents instead
of internal proof exports.

Requirements:

- customer/scope header must be clean
- internal run labels, benchmark IDs, loop labels, raw flags, and raw exploit
  markers stay out of the management-facing title layer
- business impact must be phrased in business language
- remediation recommendations must be cluster-specific, not generic filler

Likely touched files:

- `api/app/services/reports.py`
- `api/app/services/report_pdf.py`
- report validation artifacts

Proof:

- one before/after management-report comparison
- explicit review checklist for executive readability and truthfulness

### W7 — Accessibility and usability pass

Goal:
Make the UI accessible and calmer for actual operators.

Requirements:

- semantic labels
- keyboard navigation
- focus states
- readable hierarchy
- contrast and status clarity
- information density without chaos

Likely touched files:

- `ui-v2/src/**`
- `ui-v2/tests/**`
- `ui-v2/src/index.css`
- `ui-v2/src/App.css`

Proof:

- accessibility-focused UI checks
- screenshot proofs at key surfaces

### W8 — End-to-end report/evidence consistency validation

Goal:
Prove the UI, report preview, exported reports, and evidence surfaces all tell
the same story.

Requirements:

- one named run used as consistency fixture
- same finding counts/statuses across:
  - run summary
  - findings theater
  - evidence replay
  - report center
  - exported report
- mismatches fail the task

Likely touched files:

- `ui-v2/tests/**`
- `api/app/services/reports.py`
- `api/app/routers/runs.py`
- validation artifacts under `docs/validation/`

Proof:

- a durable validation artifact showing the cross-surface consistency check

## Working order

The recommended order for Codex in this lane is:

1. W0 — UI truth audit
2. W1 — live run truth strip
3. W2 — Findings Theater truth pass
4. W3 — Evidence Replay clarity
5. W4 — Report Center overhaul
6. W5 — evidence-backed LLM report composition
7. W6 — management-report rewrite rules
8. W7 — accessibility pass
9. W8 — end-to-end consistency validation

## Progress

### 2026-06-01 - W0 complete

Artifact:

- `docs/validation/codex-ui-reporting-truth-audit-2026-06-01.md`

Summary:

- mapped the current React v2 run, finding, evidence, and report sources
- identified the main truth split between run-local summaries and
  assessment-chain aggregate findings/tasks
- identified Report Center labels and direct fetches that can misstate evidence
  or tenant/header behavior
- set W1 as the next Codex-owned implementation target

## Safe modularization work inside the Codex lane

The repo is not yet truly modular in the UI/reporting layer. These are the
modularization tasks Codex can do safely without crossing into the active
solver/orchestration lane.

### M1 — Split `ui-v2/src/App.tsx` into route-shell modules

Current state:

- `ui-v2/src/App.tsx` is still a large composition root plus bootstrap,
  loading, command palette, nav, toast, and route-state logic in one file

Safe target:

- keep one thin `App.tsx`
- extract:
  - `AppShell`
  - navigation config / nav rendering
  - command palette
  - toast viewport
  - bootstrap hooks
  - run-selection helpers

Why safe:

- touches only the Codex-owned UI lane
- improves readability and testability without touching solver logic

### M2 — Split `ui-v2/src/store/index.ts` into state slices

Current state:

- engagement, run, finding, inventory, insights, actor, settings, loading, and
  run-stream state all live in one Zustand store file

Safe target:

- extract slices:
  - engagement/run selection
  - findings/evidence selection
  - settings/actor
  - loading/error
  - live run stream

Why safe:

- preserves current UI data model
- reduces accidental coupling across screens

### M3 — Split `ui-v2/src/api/client.ts` into domain clients

Current state:

- one large API client file mixes runs, findings, reports, settings, packs,
  research, problems, etc.

Safe target:

- extract domain clients:
  - `api/runs.ts`
  - `api/findings.ts`
  - `api/reports.ts`
  - `api/settings.ts`
  - `api/packs.ts`
  - shared transport/error helper remains central

Why safe:

- reduces UI integration confusion
- makes report/evidence work much easier without touching runtime behavior

### M4 — Add report/view-model adapters

Current state:

- screens likely consume raw API shapes too directly

Safe target:

- create UI-facing adapters/view-model builders for:
  - run truth strip
  - finding truth badge/state
  - evidence replay summary
  - report preview metadata

Why safe:

- lets UI truth become canonical at the presentation boundary
- avoids screen components each re-inventing status logic

### M5 — Split `api/app/services/reports.py` by concern

Current state:

- `reports.py` is ~7.6k lines and mixes context building, variant rendering,
  Dutch management rendering, HTML/Markdown assembly, report catalog logic,
  draft generation, and LLM drafting payload work

Safe target:

- extract modules under a report package by concern, for example:
  - context building
  - catalog / lifecycle helpers
  - management NL rendering
  - technical/evidence rendering
  - draft payload shaping
  - LLM phrasing adapters

Why safe:

- stays within the reporting lane
- directly supports the evidence-backed report overhaul

### M6 — Separate canonical report facts from LLM phrasing

Current state:

- management-report logic currently mixes factual selection and drafted wording

Safe target:

- explicit structured report payload layer
- separate deterministic fact selection from optional LLM phrasing

Why safe:

- this is one of the most important product-truth separations
- it improves correctness without touching assessment runtime logic

### M7 — Add report/evidence fixture pack for UI tests

Current state:

- UI/report tests use fixtures, but consistency-focused named scenarios should
  be made first-class

Safe target:

- add a named fixture matrix for:
  - observed but unverified
  - verified but not persisted
  - verified and persisted
  - blocked / contradictory score state
  - management-report exclusion of untested scope

Why safe:

- lets us harden truth behavior before touching broad product flows

### M8 — Build a cross-surface consistency checker

Current state:

- report, finding, evidence, and run-summary truth can drift

Safe target:

- one validation helper that compares:
  - run summary counts
  - findings list counts
  - report catalog/export counts
  - evidence-linked finding availability

Why safe:

- this is a UI/reporting invariant, not a solver/orchestration change

## Modularization order inside the Codex lane

Recommended modularization order:

1. M4 — report/view-model adapters
2. M8 — cross-surface consistency checker
3. M1 — `App.tsx` split
4. M2 — store slices
5. M3 — API domain clients
6. M6 — canonical report facts vs LLM phrasing
7. M5 — `reports.py` extraction
8. M7 — fixture matrix hardening

## Explicitly out of scope for this worklist

- XBEN score-lane execution changes
- exploit-loop planner changes
- interactive-exploit runtime heuristics
- provider bakeoffs
- focused-assessment throughput tuning
- verdict-gate persistence fixes in the active score lane
- broad architecture rewrites not tied to UI/reporting truth

## Definition of success for this Codex lane

This lane is successful when:

1. the UI shows live, canonical, operator-trustworthy truth
2. findings/evidence/report surfaces agree with each other
3. management reports only say what was actually tested and proven
4. the LLM is constrained to wording, not fact invention
5. the work stays isolated enough that Claude's score-lane can continue cleanly
