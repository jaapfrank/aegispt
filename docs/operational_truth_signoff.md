# Operational Truth and Release Signoff Standard

## Purpose

This document defines the rule set AegisPT must follow before it is allowed to claim that a scoped part of the product is complete, operational, or release-ready.

Its job is simple:

- stop premature "done" claims
- make release truth evidence-based
- force multiple independent validation methods
- keep documentation, code, runtime behavior, and reports aligned

## Core truth rule

AegisPT may only say that a scoped feature set is done when the claim is backed by recorded evidence.

That means:

- no memory-based signoff
- no "it worked once on my machine"
- no "the tests probably cover it"
- no "the UI looked fine in a screenshot"

Instead, a completion claim must be backed by a signoff packet containing:

- test evidence
- run evidence
- browser evidence
- host/Kali evidence
- documentation evidence
- known limitation record

## Important honesty rule

No software team can honestly promise the absence of all future defects.

So AegisPT must not use "100% works" to mean "mathematically no bug can exist".

For this project, "100% true" means:

- every supported path we are claiming is covered by evidence
- every supported option we are claiming is covered by evidence or explicitly blocked and documented
- every unsupported path is marked unsupported instead of silently breaking
- no known blocker is hidden behind optimistic wording

## Release gate model

Every scoped release candidate must pass all gates below before it can be called complete.

### Gate 1: Code health

Required:

- import/build/startup path works
- migrations apply cleanly where relevant
- no broken static asset references
- `git diff --check` is clean

Evidence:

- command output logs
- startup health response

### Gate 2: API and model contract validation

Required:

- unit/API regressions pass for the touched scope
- no contract break against existing findings, reports, packs, or run models
- old records remain backward-compatible

Evidence:

- pytest output
- migration/test notes

### Gate 3: Browser and operator flow validation

Required:

- Playwright passes for the touched paths
- the operator can complete the intended flow in the browser
- error, blocked, empty, and success states are visible and truthful

Evidence:

- Playwright results
- screenshots/traces on failures
- updated coverage references in `docs/ui_browser_validation.md`

### Gate 4: Real-run safe validation

Required:

- the feature is exercised against a safe target or safe fixture if the feature depends on real execution
- generated findings, evidence, inventory, pack state, and reports line up with what actually happened

Evidence:

- acceptance result JSON under `codex/results/`
- run IDs and report artifacts
- notes in `docs/acceptance_runbook.md`

### Gate 5: Kali or real host reproducibility

Required:

- the validated behavior can be reproduced on the actual host path we support
- service restart, asset refresh, and report export work on the live host

Evidence:

- health response
- host restart notes
- manual browser verification on the supported host

### Gate 6: Documentation truth

Required:

- the docs match the current behavior
- the plan reflects what is still open
- the repo truth files do not overclaim completion

Minimum files to update when relevant:

- `CURRENT_STATE.md`
- `DONE_LOG.md`
- `NEXT_TASK.md`
- `docs/product_test_matrix.md`
- `docs/ui_browser_validation.md`
- `docs/acceptance_runbook.md`

### Gate 7: Known-risk disclosure

Required:

- remaining risks are written down
- blocked combinations are written down
- unsupported combinations are written down
- no customer-facing or operator-facing copy implies stronger guarantees than the evidence supports

## Triple-validation rule

Before a scoped feature or flow is called done, it must be tested at least three different ways when applicable:

1. code-level or API-level tests
2. browser-level operator tests
3. real-run or host-level validation

If one of those layers does not apply, the signoff must say why.

## Combination coverage rule

Testing only happy paths is not enough.

For every claimed supported area, AegisPT must track:

- supported combinations
- blocked combinations
- intentionally unsupported combinations

Each combination must have:

- a status
- a validation method
- a last validation date
- evidence reference

This rule must stay aligned with:

- `docs/product_test_matrix.md`
- `docs/operator_product_operational_assurance.md`
- `codex/tasks/product_acceptance_matrix.json`
- `codex/tasks/ui_acceptance_matrix.json`
- `codex/tasks/target_lab_matrix.json`

The canonical status labels for product-combination truth are:

- `supported-and-tested`
- `supported-with-gap`
- `blocked`
- `intentionally-unsupported`

These labels are defined and applied in `docs/operator_product_operational_assurance.md`.

## Required signoff packet

No scoped milestone is complete unless the repo can point to all of the following:

- the active plan section that was being executed
- the code changes
- the updated tests
- the validation commands that were run
- any resulting acceptance JSON or report evidence
- the updated truth docs
- the remaining known risks

## Allowed and forbidden completion language

Allowed:

- "the currently supported path is validated"
- "the scoped milestone is complete with these known limits"
- "the following combinations pass"
- "the following combinations remain blocked"

Forbidden:

- "everything works perfectly" without evidence
- "fully tested" when only a subset was tested
- "enterprise-ready" without signoff artifacts
- "hack-proof" or "guaranteed secure"

## Assurance package wording rule

Evidence-backed assurance and compliance packages may summarize a selected run, but they must remain scoped to
recorded evidence and must not become certification, attestation, registrar-audit, QSA-assessment, Report-on-Compliance, or Attestation-of-Compliance copy.

Required:

- state the tested scope and time window
- state the evidence basis, methodology basis, finding state, remediation state, and retest state
- show unresolved, unverified, and accepted-risk findings
- show out-of-scope limits
- say the package is not a certification, attestation, or guarantee of security
- for ISO 27001 and PCI DSS packages, show unmapped findings and controls or requirements without mapped run findings

Forbidden:

- "hack-proof"
- "guaranteed secure"
- "fully secure"
- "certified compliant"
- "SOC 2 attested"
- "ISO 27001 certified"
- "PCI certified"
- "QSA validated"
- "Report on Compliance issued"
- "Attestation of Compliance issued"
- "all risk removed"
- "all vulnerabilities found"
- "all findings fixed" unless every referenced finding is resolved and backed by verification evidence

## Recommended testing stack direction

Based on current market and testing-practice review, AegisPT should continue using a layered model:

- pytest for API/model/service regression
- Playwright for browser/operator truth
- safe target acceptance harness for live run validation
- matrix runner for composite signoff
- optional future orchestration layer for distributed and scheduled test execution

Relevant external references reviewed:

- Playwright testing practices: https://playwright.dev/
- Cypress E2E and component-testing approach: https://www.cypress.io/app
- Testkube orchestration model: https://docs.testkube.io/
- Testkube execution/orchestration direction: https://testkube.io/features
- GitHub Actions matrix-testing guidance: https://docs.github.com/actions

Inference:

- AegisPT should not rely on one test framework alone
- the winning model is coordinated test orchestration with centralized evidence, logs, artifacts, and coverage truth

## Future strengthening recommendations

- add component-level UI tests for complex rendering/state modules
- add scheduled composite signoff runs on dedicated validation hosts
- add richer test artifact cataloging and dashboarding
- add mutation/failure-mode testing around orchestration and stale-state handling
- add cross-browser expansion beyond Chromium when the scoped operator path is stable enough

## Bottom line

AegisPT is only allowed to say "done" for a scoped slice when the repo can prove it.

If the proof is missing, the claim is not allowed.
