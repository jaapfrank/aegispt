# Operator Console Phase 6 Checklist

## Purpose

This document tracks the sixth stabilization slice for the operator console.

Phase 6 focuses on calmness, hierarchy, and readability without removing product information:

- Intake should feel guided instead of noisy
- Mission Control should show one operational story instead of many equal-weight cards
- supporting context should stay available through quieter disclosures and grouped panels
- the shell should keep phase focus without repeating the same summary in multiple places

## Validation status

- prepared on 2026-04-17
- completed on 2026-04-17
- manual browser walkthrough captured in:
  - `ui/test-results/phase6-intake.png`
  - `ui/test-results/phase6-mission-control.png`
- current automation focus:
  - `ui/tests/test_operator_console_e2e.py`
  - `ui/tests/test_product_feature_matrix_e2e.py`

## Control checklist

| Area | Expected behavior | Current status |
| --- | --- | --- |
| Intake conversation calmness | only the active question and the most recent context stay prominent, while older context and revision controls move into disclosures | covered |
| Intake summary hierarchy | the right rail leads with current essentials, what still needs confirmation, and a compact mission brief before deeper disclosures | covered |
| Shell calmness | the hero, top strip, rail, and screen chrome use less visual weight and stop competing with the primary task | covered |
| Phase feed discipline | the recent feed remains available for execution, but no longer acts like a persistent wall during Intake or Analysis | covered |
| Mission Control hierarchy | secondary execution detail is grouped into `Operational Snapshot` and `Supporting Context` instead of many equally loud standalone cards | covered |
| CTA hierarchy | only current-phase actions stay in the top action row, and repetitive shell copy is reduced | covered |
| Browser validation | calmer intake disclosures, phase-feed visibility rules, and grouped Mission Control panels are exercised in the browser suite | covered |

## Commands used for this slice

```bash
./.venv/bin/pytest -q -s ui/tests/test_operator_console_e2e.py
./.venv/bin/pytest -q -s ui/tests/test_product_feature_matrix_e2e.py
git diff --check
```

## Exit criteria

Phase 6 can only be treated as complete when:

1. Intake shows one clear next step without dropping confirmed/inferred/still-needed context
2. Mission Control reads as one live operational screen with grouped secondary context
3. the shell stops showing the same level of visual urgency everywhere at once
4. browser validation and repo truth both reflect the calmer hierarchy

## Remaining follow-up after this slice

- Phase 7 remains responsible for the broader full acceptance matrix across every meaningful product path
- richer live telemetry can still deepen Execution later without reintroducing card overload
- a later visual pass can still refine typography and spacing details, but the hierarchy is now in the right shape
