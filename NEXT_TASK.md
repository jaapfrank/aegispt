# Active Task

## Title

AI Exploit Chaining & Post-Exploitation Pivot Engine

## Promoted From

`codex/tasks/backlog-301-ai-exploit-chaining-and-pivot-engine.json`

## Goal

Move beyond 'flat' scanning. When the AI confirms a vulnerability that yields access (e.g., SSRF, RCE, or stolen credentials via XSS), it must automatically generate a 'Pivot Context'. It then restarts the assessment loop from this new vantage point (e.g., routing a network scan through the SSRF, or launching an authenticated web scan using the stolen cookie) to find the vulnerabilities hidden behind the initial entry point.

## Scope

AI post-exploitation and multi-step reasoning.

## Constraints

- Do not implement until this package is the single active task in NEXT_TASK.md.
- Ensure the pivoting mechanism stays strictly within the authorized Rules of Engagement (ROE) boundaries.
- Do not create runtime self-modification or uncontrolled plugin installation.
- Do not automate lateral movement outside the approved target scope.

## Validation

- `python3 scripts/validate_backlog_tasks.py`
- `pytest api/tests/`

## Acceptance

- AI can extract a token and pass it to a subsequent authenticated scan.
- AI identifies a pivot point (like SSRF) and generates a sub-plan.
- The Gruyere benchmark passes by successfully chaining 3+ vulnerabilities.
