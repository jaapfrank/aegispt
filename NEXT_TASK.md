# Active Task

## Title

CVE-to-Test auto-queue: when discovery matches a CVE, automatically queue a Nuclei test proposal for operator approval

## Promoted From

`codex/tasks/backlog-206-cve-to-test-auto-queue.json`

## Goal

The system already runs discovery, extracts product versions, matches local CVE intelligence, and stores matched CVEs, but matched CVEs still do not create actionable test proposals. Implement the missing bridge so matched CVEs with available Nuclei templates create run-scoped pending `AgentProposal` records that appear in the AI Proposals Inbox.

## Scope

Implement the active backlog package `codex/tasks/backlog-206-cve-to-test-auto-queue.json`.

Expected slice:

- when discovery/CVE refresh finds a CVE with an existing Nuclei template, create a pending run-scoped `AgentProposal`
- set `proposed_tool` to `nuclei`
- set `proposed_target` to the matched host/target
- include the matching template identifier/path in proposal params
- set risk tier to `active`
- include reasoning that names the CVE, matched product/version, and target
- proposals must appear in the backlog-205 Mission Control AI Proposals Inbox
- do not create proposals when no matching Nuclei template exists

## Constraints

- Do not implement until this file is the single active task.
- Do not auto-dispatch tests.
- Do not modify CVE matching logic.
- Do not weaken Nuclei template safety validation.
- Do not bypass approval gates for intrusive tools.
- Do not bypass scope, ROE, approval, validation, deployment, runtime binding, credentials, or kill switch.
- No runtime self-modification.
- No uncontrolled plugin installation.

## Validation

- `python3 scripts/validate_backlog_tasks.py`
- `source .venv/bin/activate && python -m pytest api/tests/ -q`
- `git diff --check`

## Acceptance

- CVE match with an existing template creates a pending `AgentProposal`.
- CVE match without a template creates no proposal.
- Proposal is run-scoped and visible only for the run that triggered discovery.
- Proposal never auto-dispatches before operator approval.
- Operator approval queues the targeted Nuclei task through the existing backlog-205 approval path.
- E2E tests pass.
