# Backlog 205 AI Proposals Inbox Evidence

## Result

Backlog-205 is complete. Mission Control now exposes pending standard `AgentProposal` records for the selected run as a Suggested Next Steps inbox with tool, target, risk tier, confidence, one-line reasoning, and approve/reject actions. Approving a standard in-scope proposal creates a queued task through the existing task model; dispatch remains an explicit operator action. Rejected proposals are marked rejected and removed from the pending inbox.

## Validation

- `python3 scripts/validate_backlog_tasks.py` passed before implementation with 250 queued task packages mapped one-to-one and exactly one active task.
- `python3 -m py_compile api/app/services/ai_agent.py api/app/routers/runs.py api/tests/test_ai_agent_reasoning.py` passed.
- `node --input-type=module --check < ui/assets/app.js` passed.
- `node --input-type=module --check < ui/assets/modules/mission-control.js` passed.
- `source .venv/bin/activate && python -m pytest api/tests/test_ai_agent_reasoning.py -q` passed.
- `source .venv/bin/activate && python -m pytest ui/tests/test_operator_console_smoke_e2e.py::test_mission_control_ai_proposals_inbox_badge_and_review_actions -q` passed.
- Required `python3 scripts/validate_backlog_tasks.py` passed.
- Required `source .venv/bin/activate && python -m pytest api/tests/test_health.py -q` passed.
- Full `source .venv/bin/activate && python -m pytest ui/tests/test_operator_console_smoke_e2e.py -q` passed.
- `git diff --check` passed before task-close documentation and again after task-close updates.
- Post-promotion `python3 scripts/validate_backlog_tasks.py` passed with exactly one active task, backlog-206, and `source_context.queue_index=229` matching `TASK_QUEUE.md`.

## Current-Code Acceptance

`http://127.0.0.1:8000` was relevant and was checked directly. `/health/live` returned healthy, and the served Mission Control module contained the backlog-205 strings `Suggested Next Steps`, `Approve & Queue`, and `ai-proposals-inbox`, proving the service was not stale for this slice.

Browser acceptance against `http://127.0.0.1:8000/app/` passed with synthetic in-scope proposal data:

- pending inbox rendered with `Suggested Next Steps`
- Mission Control nav badge showed `2` pending proposals
- `Approve & Queue` posted an approval review and reflected a queued follow-up without dispatching execution
- `Reject` posted a rejection review, removed the pending row, and cleared the inbox/nav badge when none remained

Captured review calls:

```json
[
  {"proposal_id": "proposal-one", "decision": "approved"},
  {"proposal_id": "proposal-two", "decision": "rejected"}
]
```

## Boundary Proof

- No AI proposal generation logic or confidence scoring was changed.
- Approval does not auto-run tools; it creates a queued task only after server-side scope, supported-tool, risk-tier, pending-approval, and duplicate-task guards pass.
- Repair and Tool Library manual proposals remain review-only.
- Existing scope, ROE, approval, validation, deployment, runtime binding, credentials, and kill-switch boundaries remain authoritative.
- No live Gruyere, customer, public internet, or third-party target was scanned.
