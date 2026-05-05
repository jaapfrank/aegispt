# Active Task

## Title

AI Security Research Lab screen: let AI invent new Nuclei templates, scripts, and test ideas from CVEs and findings

## Promoted From

`codex/tasks/backlog-207-ai-security-research-lab-screen.json`

## Goal

Create a dedicated `Research` screen accessible from the BUILD section of the sidebar. The screen exposes AegisPT's AI-driven capability creation without bypassing safety validation or Pack Forge approval/deployment gates.

## Scope

Implement the active backlog package `codex/tasks/backlog-207-ai-security-research-lab-screen.json`.

Expected slice:

- add a Research screen entry under BUILD navigation
- expose a CVE-to-template workflow where an operator selects a CVE from threat intelligence and requests a detection-only Nuclei YAML through the existing `cve_template_generator.py` flow
- show generated template output with preview and safety summary
- allow reviewed generated templates to be submitted into Pack Forge staging/review rather than deployed directly
- add a Custom Script Ideas panel for plain-language detection ideas using the same safety posture
- show a Research Proposals log with generated templates/ideas and statuses

## Constraints

- Do not implement until this file is the single active task.
- Do not change safety validation in `cve_template_generator.py`.
- Do not bypass Pack Forge approval gates.
- Do not bypass pack registry, validation, approval, deployment, runtime binding, scope, ROE, credentials, or kill switch.
- No runtime self-modification.
- No uncontrolled plugin installation.
- No active exploit generation or external template downloads.

## Validation

- `python3 scripts/validate_backlog_tasks.py`
- `source .venv/bin/activate && python -m pytest api/tests/test_health.py -q`
- `git diff --check`

## Acceptance

- Research screen is accessible from the sidebar.
- CVE template generation flow works end-to-end.
- Generated templates show YAML preview with safety summary.
- Generated templates go to Pack Forge staging/review, not direct deployment.
- Custom script idea input returns a detection script or safe blocked state.
- Research Proposals log shows generated templates/ideas with status.
- E2E tests pass.
