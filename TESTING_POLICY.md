# Testing Policy

## Purpose

This repository keeps production hardening grounded in repeatable validation. Browser behavior, report export, and API contracts should be verified through the same repo-driven workflows that AGENTS.md points to.

## Required test lanes

- API and service regression: `python -m pytest api/tests -q`
- Browser validation: `python -m pytest ui/tests -q`
- Targeted report export validation:
  - included in `api/tests/test_reports.py`
  - covers markdown, HTML, and PDF report output
- Bytecode / import sanity:
  - `python -m compileall api/app api/tests ui/tests`

## Browser validation rules

- Use Playwright against the real FastAPI-served `/app/` route.
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

## Operator-facing regression focus

- Wizard completion path
- Mission Control loading
- Findings / Evidence / Pack / Report / Explorer / History navigation
- Empty and loading states for major screens
- Report preview and export actions
