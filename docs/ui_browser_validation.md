# UI Browser Validation

## Purpose

The operator console now has browser-level validation through Playwright so the mandatory wizard, Mission Control flow, drilldowns, and report workflows are checked in a real Chromium session instead of only through static/API tests.

## Scope

The current browser suite covers:

- app load at `/app/`
- mandatory wizard rendering
- inline wizard validation feedback
- run creation with representative operator data
- Mission Control landing after wizard completion
- navigation to Findings Theater, Evidence Replay, Pack Forge, Report Center, Explorer, and History
- report preview actions
- empty-state rendering for major screens

## Test structure

- tests live under `ui/tests/`
- `ui/tests/conftest.py` starts a temporary FastAPI instance backed by SQLite
- Playwright traces and screenshots are written to `ui/test-results/` on failure

## How to run

1. Activate the repo virtual environment.
2. Install the browser runtime once:

```bash
python -m playwright install chromium
```

3. Run the browser suite:

```bash
python -m pytest ui/tests -q
```

## Selector policy

- prefer `data-testid` selectors for cross-screen actions and key workflow elements
- use stable IDs for wizard fields where the DOM is already explicit
- avoid brittle selectors tied only to decorative text or panel order

## Current renderer assumptions

- Chromium is the required first browser
- the test server uses the same FastAPI app served in development
- the runtime remains deterministic; browser tests do not mutate active assessment logic beyond the normal operator flows they exercise
