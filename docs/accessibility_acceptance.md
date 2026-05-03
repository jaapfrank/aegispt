# Accessibility Acceptance Gate

## Purpose

AegisPT treats keyboard-only operation and assistive-technology compatibility as enterprise product requirements. This gate is the repo-owned minimum for operator-console changes that affect navigation, controls, dialogs, drawers, animated surfaces, or error/empty states.

## Current Gate

Run from the repository root:

```bash
source .venv/bin/activate
python -m pytest ui/tests/test_accessibility_e2e.py -q
```

The gate verifies:

- primary screens are reachable by keyboard activation
- focused primary navigation controls have a visible focus outline
- visible buttons and visible form controls have accessible names
- Cinema Mode traps focus, closes with Escape, and returns focus to the launcher
- cleanup dialogs trap focus, close with Escape, and return focus to the launcher
- reduced-motion mode disables live animation surfaces

## Operator Standard

- Do not rely on color alone for status or action meaning; visible text, badges, or labels must carry the meaning.
- Icon-only controls need `aria-label` or equivalent text.
- Dialogs and modal surfaces must use `role="dialog"`, `aria-modal="true"`, a programmatic name, Escape close behavior, focus trapping, and focus return.
- Form controls need an accessible name from a label, `aria-label`, or `aria-labelledby`; placeholders are examples, not labels.
- Animated surfaces must honor `prefers-reduced-motion: reduce`.

## Evidence

When this gate changes, record the result under `codex/results/` with the exact commands, pass/fail outcome, and any known manual residual risk. Screenshots or DOM evidence from Playwright traces are acceptable supporting evidence; do not commit generated screenshots or trace archives unless a task explicitly requests them.
