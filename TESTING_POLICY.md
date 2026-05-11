# Testing Policy

## Purpose

This repository keeps production hardening grounded in repeatable validation. Browser behavior, report export, and API contracts should be verified through the same repo-driven workflows that AGENTS.md points to.

## Required test lanes

- API and service regression: `python -m pytest api/tests -q`
- Browser validation: `cd ui-v2 && npm run test:e2e`
- Acceptance harness regression: `python -m pytest api/tests/test_acceptance_harness.py -q`
- Targeted report export validation:
  - included in `api/tests/test_reports.py`
  - covers markdown, HTML, and PDF report output
- Bytecode / import sanity:
  - `python -m compileall api workers scripts`

## Browser validation rules

- Use React v2 Playwright coverage in `ui-v2/tests/` for the active operator console.
- Legacy `ui/tests/` coverage targets the retired FastAPI-served `/app/` route and is diagnostic only until migrated or removed.
- Prefer stable `data-testid` selectors over text-only selectors where practical.
- Capture traces and screenshots on failure under `ui/test-results/`.
- Chromium is the default hardening browser. Firefox/WebKit expansion is a later additive step.

## PDF validation rules

- PDF export must reuse the existing report service semantics.
- Validation should prove the exported bytes are a readable PDF and contain expected report text.
- Renderer prerequisites must be documented and reproducible.

## Secret-handling validation rules

- Direct secrets entered through the wizard must not come back in the normal run configuration response.
- Tests should verify protected indirection or encrypted local storage instead of plaintext persistence.

## Scan tooling gate categories

Run `python3 scripts/check_tooling_readiness.py` to generate a current
readiness report. Gates are categorised as follows:

- **active_gate** — Required green for release. CI blocks on failure.
  - Playwright (`cd ui-v2 && npm run test:e2e`)
- **diagnostic_gate** — Operator-reviewed output; does not block release.
  - ZAP (daemon API preferred; avoid racing the home directory)
  - Semgrep (run with proxy vars unset: `env -u HTTP_PROXY -u HTTPS_PROXY semgrep ...`)
  - npm audit (`npm audit --audit-level=high`; moderate Vite/esbuild advisories are tracked as planned future work — do not apply `npm audit fix --force`)
- **future_optional** — Planned addition; not yet wired.
  - Schemathesis (local FastAPI only: `http://localhost:8000`)
  - Trivy, Gitleaks, pip-audit, Lighthouse CI

## Operator-facing regression focus

- Wizard completion path
- Mission Control loading
- Mission Control task-focus truth before and after dispatch
- Discovery-to-follow-up continuity for LAN/internal runs
- Surface Map search/filter behavior for discovery-confirmed inventories
- Zero-finding run-level Evidence Replay context
- Findings / Evidence / Pack / Report / Explorer / History navigation
- Explorer dossier-summary behavior and actionable next-review guidance
- History search plus finding/inventory delta clarity
- Follow-up lineage visibility in Explorer, History, and Report Center
- Discovery-only and follow-up report integrity without synthetic findings
- Empty and loading states for major screens
- Report preview and export actions
- Safe-target acceptance scenario selection and result recording
