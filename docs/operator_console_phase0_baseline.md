# Operator Console Phase 0 Baseline

## Purpose

This document captures the real starting point of the operator-console operational-assurance program.

It is not a marketing summary.

It is the working baseline for:

- what currently works
- what is still confusing
- what is misleading
- what is broken
- what the next implementation slice should target first

## Baseline date

- initially recorded on 2026-04-17
- revalidated on 2026-04-18
- repository root: current AegisPT workspace
- browser validation source:
  - `ui/tests/test_operator_console_e2e.py`
  - `ui/tests/test_product_feature_matrix_e2e.py`
- operator truth source:
  - direct user feedback from Kali and browser use
  - current repo docs and UI state
  - live host and acceptance reruns on `http://127.0.0.1:8000`

## Revalidation evidence (2026-04-18)

The Phase 0 baseline has now been re-run against the current repo and the live local host instead of relying only on older claims.

Commands executed:

- `./.venv/bin/python scripts/run_product_e2e_matrix.py --lane all`
- `./.venv/bin/pytest -q -s api/tests/test_reports.py`
- `./.venv/bin/pytest -q -s ui/tests/test_product_feature_matrix_e2e.py::test_report_download_actions_create_real_browser_files ui/tests/test_operator_console_e2e.py::test_authenticated_webapp_flow_supports_reports_and_secret_binding`
- `./.venv/bin/python scripts/run_acceptance_matrix.py --base-url http://127.0.0.1:8000 --scenario-id local-app-smoke`
- live host export checks for:
  - HTML report body
  - PDF content-type and `%PDF` signature

Observed result:

- composite API/UI matrix: passing
- composite API/UI matrix after the host-lane fix: still passing
- targeted report/API regressions: passing
- targeted report/browser regressions: passing
- live `local-app-smoke` acceptance: passing
- live host HTML export: passing
- live host PDF export: initially failed with `503`, then passed after a host-lane fix in the restart/install helpers

Current evidence files:

- `codex/results/acceptance-local-app-smoke-20260418-184034.json`
- `codex/results/acceptance-local-app-smoke-20260418-183713.json`

## Baseline summary

The operator console has meaningful structure, a broad automated matrix, and a live-host acceptance lane, but it is still not good enough to be called exhaustively validated or fully signoff-complete.

The biggest current gap is not raw absence of screens.

The biggest gap is that:

- several flows are operationally stronger than before but not yet exhaustively signed off across supported combinations
- the UI still asks the operator to infer too much in some places
- some results are technically present but not yet as obvious or calm as they should be
- human-factor trust and supported-combination truth still lag behind the current automated baseline

## Current operator path inventory

| Area | Current state | Evidence |
| --- | --- | --- |
| Conversational intake | validated for supported-path browser matrix | `scripts/run_product_e2e_matrix.py --lane all` |
| Mission Control dispatch and run truth | validated on current browser/API matrix plus live local acceptance | matrix run plus `acceptance-local-app-smoke-20260418-184034.json` |
| Surface / Attack Map | validated in browser matrix for discovery review and follow-up continuity | browser matrix |
| Findings Theater | validated for supported-path UI states, including zero-finding context | browser matrix |
| Evidence Replay | validated for run-level evidence posture and follow-up lineage | browser matrix |
| Report Center | validated in API/browser matrix; live host HTML/PDF export rechecked on 2026-04-18 | API tests, browser tests, live export fetch |
| Explorer / History | validated in browser matrix for dossier and comparison behavior | browser matrix |
| Safe acceptance harness | validated on live host with `local-app-smoke` | `acceptance-local-app-smoke-20260418-184034.json` |

## What currently works

### Structural positives

- the UI has a real shell and phase model:
  - Intake
  - Run
  - Analysis
- the wizard can create deterministic runs
- the advanced drawer remains available
- Mission Control, Surface Map, Findings, Evidence, Reports, Explorer, and History all exist as real product surfaces
- Playwright browser tests exist and are isolated per test host
- LAN discovery support and follow-up flows exist in the product model

### Operational positives

- discovery-oriented LAN runs can be created
- inventory snapshots can be surfaced into Surface / Attack Map
- discovery-first runs now explain zero findings better than before
- report export paths for markdown, HTML, and PDF are validated again in the current baseline
- the app can be deployed and exercised on Kali and the local transient host path

## Shared issue inventory

| ID | Area | Status | Severity | Reproduction | Notes |
| --- | --- | --- | --- | --- | --- |
| PH0-001 | Live host PDF export | fixed during Phase 0 revalidation | high | `GET /api/v1/runs/{run_id}/report?format=pdf&variant=technical` on the live transient host returned `503` | Root cause was `PLAYWRIGHT_BROWSERS_PATH=/opt/aegispt/ms-playwright` in the host service while the local restart path did not ensure Chromium at that path. Fixed by adding `scripts/ensure_playwright_chromium.sh` and wiring it into the install/restart helpers. |
| PH0-002 | Supported-path signoff breadth | open | medium | compare current matrix to the supported-option and supported-combination ambitions in the assurance plan | The current matrix is strong, but it is still not the same as exhaustive supported-combination signoff. |
| PH0-003 | Human operator calmness review | open | medium | requires direct operator walkthrough beyond automated green tests | The UI baseline is materially better, but human-factor review on calmness and trust still matters. |
| PH0-004 | Broader lab breadth | open | low | WebGoat/crAPI scenarios depend on those labs being live where the harness runs | This is a breadth gap, not a currently reproduced blocker in the refreshed local baseline. |

## What is currently broken or not yet trustworthy enough

### 1. Wizard trust and completion still need hard review

Status: functional but incomplete

Observed issues:

- the conversational wizard has improved, but it still needs full path-by-path completion review across all assessment types
- the operator can still end up relying too much on implied intent rather than explicit step clarity
- the amount of explanatory copy is lower than before, but not yet consistently calm

Why this matters:

- if the wizard does not feel fully trustworthy, every later product surface inherits that distrust

### 2. Run dispatch and live state still need stronger truthfulness

Status: functional but incomplete

Observed issues:

- the product now lands more cleanly in Mission Control after run creation, but the overall run-truth model still needs live operator validation against more combinations
- some flows are still request/response style rather than visibly “live”
- the operator can still wonder whether work is actually happening or just queued invisibly

Why this matters:

- a mission console must make activity obvious, not merely queryable

### 3. LAN/internal operator flow is improved but still not done

Status: improved but still a high-priority stabilization area

Observed issues:

- LAN discovery is no longer the same dead end it was before, but this area still deserves focused stabilization
- follow-up actions exist, but the full estate-to-follow-up journey still needs exhaustive verification
- internal validation messaging must remain honest and staged

Why this matters:

- the user explicitly expects internal/LAN work to be a first-class use case

### 4. Findings / Evidence / Reports consistency still needs review

Status: functional but incomplete

Observed issues:

- zero-finding discovery runs are explained better, but the overall analysis experience still needs a full consistency pass
- it must remain impossible for reports to feel empty or misleading when inventory output exists
- PDF output is now repaired again on the live host, but broader report readability and confidence still need stricter human review

Why this matters:

- if evidence and reports do not line up tightly with run reality, the platform loses credibility

### 5. Surface / Explorer / History usability still needs work

Status: functional but too noisy / partially incomplete

Observed issues:

- large-inventory usability has improved, but browsing, scanning, and comparing still need stronger human-centered review
- click affordances and next actions are better than before, but still not yet consistently obvious enough

Why this matters:

- these screens should help an operator think, not force them to hunt

### 6. Overall visual calmness is still below target

Status: functional but too noisy

Observed issues:

- the phase shell is better than the older multi-surface layout
- however, the product still does not yet feel calm enough for serious operator use
- there is still too much competing structure, too much text weight, and not enough strong hierarchy

Why this matters:

- a cluttered interface actively reduces operator confidence and speed

## Current category assessment

### Broken

- no currently reproduced supported-path blocker remains in the refreshed local baseline after the live host PDF defect was fixed
- this does not mean the product is “done”; it means the current main issues are now more about signoff breadth, trust, clarity, and full-flow completeness than about a newly reproduced hard crash in the current baseline

### Misleading

- discovery-first output can still feel weaker than it should if the operator expects immediate deeper security conclusions
- some live states still read as less active than the operator likely expects
- some surfaces still require the operator to infer how one result leads to the next screen or next action

### Functional but incomplete

- wizard coverage across every path plus broader host-level trust review
- Mission Control truth under more run combinations
- internal/LAN follow-through breadth
- evidence/report consistency review
- explorer/history comparison usability
- supported-combination signoff breadth beyond the current supported-path matrix

### Functional but too noisy

- overall shell calmness
- hierarchy and emphasis
- copy density and competing panels

## Current validation baseline

Known validated baseline after the 2026-04-18 rerun:

- composite API/UI matrix is green
- targeted report/API/browser checks are green
- direct-host local acceptance is green
- live host HTML export is green
- live host PDF export is green again after the browser-path fix

Current limitations:

- passing automated browser tests do not yet equal “good operator UX”
- passing the current supported-path matrix does not yet equal exhaustive supported-combination signoff

## Phase 0 output from this baseline

The first implementation slice should focus on:

1. wizard completion and trust
2. run dispatch truth
3. LAN/internal follow-through visibility

This means the next repair slice should not start with cosmetic polish.

It should start with:

- making every wizard path obviously completable
- making post-create and post-dispatch state unmistakable
- making discovery-to-follow-up progression explicit

Phase 0 is now considered revalidated because:

- a current shared issue inventory exists
- the baseline distinguishes fixed, open, and still-incomplete areas
- the live host layer was rechecked instead of assumed
- one real live-host reporting defect was reproduced and fixed during the baseline pass

## Next implementation slice recommendation

### Target

Phase 1 from `docs/operator_console_stabilization_plan.md`

### Immediate objectives

- verify and harden all wizard completion paths
- reduce ambiguity in current question / next action language
- tighten confirmation summaries
- verify advanced-drawer synchronization across all supported mission types

### Entry check

Before Phase 1 changes start, the following should be prepared:

- assessment-type-by-assessment-type checklist
- profile checklist
- access/auth checklist
- safety/boundary checklist

## Documentation follow-up required after each stabilization slice

- update `CURRENT_STATE.md`
- append to `DONE_LOG.md`
- update the affected UI docs
- keep this baseline document truthful if the category assessment changes
