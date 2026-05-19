# Backlog 209 Tool Capability Guide Evidence

## Outcome

Backlog-209 is complete. Pack Forge now includes an operator-facing Tool Library with 33 existing capabilities. Each catalog item shows a category, one-sentence description, typical findings, authorization tier, prerequisites, and assessment-mode membership. The detail panel includes a review-only `Add to current run` path.

## Safety Boundary

The Tool Library does not add tools, change runner dispatch, queue tasks, grant approvals, expand scope, validate/deploy packs, bind runtime packs, bypass credentials, or bypass the kill switch.

`Add to current run` posts to a new review-only proposal endpoint that records an `AgentReasoning` and `AgentProposal` with `proposal_kind=tool_library_manual_task`, `dispatches_work=false`, and `creates_tasks=false`. Proposal approval continues to record review intent only.

## Files Changed

- `api/app/routers/runs.py`
- `api/app/schemas/runs.py`
- `api/app/services/ai_agent.py`
- `api/tests/test_ai_agent_reasoning.py`
- `ui/index.html`
- `ui/assets/app.js`
- `ui/assets/modules/packs.js`
- `ui/assets/styles.css`
- `ui/tests/test_operator_console_smoke_e2e.py`
- `CURRENT_STATE.md`
- `DONE_LOG.md`
- `NEXT_TASK.md`

## Validation

- `python3 scripts/validate_backlog_tasks.py` passed before implementation with exactly one active task.
- `source .venv/bin/activate && python -m pytest api/tests/test_ai_agent_reasoning.py::test_tool_library_manual_proposal_is_review_only_and_auditable api/tests/test_health.py -q` passed.
- `source .venv/bin/activate && python -m pytest ui/tests/test_operator_console_smoke_e2e.py::test_pack_forge_tool_library_catalogue_and_manual_proposal -q` passed.
- `source .venv/bin/activate && python -m pytest api/tests/test_ai_agent_reasoning.py -q` passed.
- `source .venv/bin/activate && python -m pytest api/tests/test_health.py -q` passed.
- `source .venv/bin/activate && python -m pytest ui/tests/test_operator_console_smoke_e2e.py -q` passed.
- `curl --fail --silent --show-error --max-time 5 http://127.0.0.1:8000/health/live` passed.
- Safe live browser acceptance on `http://127.0.0.1:8000/app/` passed with `33 tools` visible and the Metasploit detail showing `exploitation` plus `Controlled session proof`.
- `git diff --check` passed before administration.

## Remaining Risk

- This is a catalogue and proposal-transparency slice only. It does not prove real target coverage for any tool.
- `hashcat` and `ssh-audit` are shown as existing supporting capabilities that route proposals through their implemented backend runner paths (`credential-attacks` and `external-infra`) rather than standalone runner IDs.
- Manual proposal approval still does not queue work by design; future tasks must implement any operator-approved task materialization through existing approval/scope/runtime gates.
