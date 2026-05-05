# Backlog 219 - AI Attack Chain Reasoning

Date: 2026-05-06

## Outcome

Completed backlog-219 `AI attack chain reasoning: teach the AI agent to chain web vulnerabilities across tools and recognize compound attack paths`.

AegisPT now refreshes additive `FindingChain` records during post-task AI analysis, builds an engagement-scoped finding context window, and emits review-gated compound-chain `AgentProposal` records when current-engagement evidence supports either:

- unrestricted or unsafe file upload plus stored XSS / uploaded HTML execution evidence
- path traversal plus writable filesystem or code-execution prerequisite evidence

The proposals are stored in the existing AI Proposals inbox data model. They do not dispatch tools, approve work, mutate component findings, expand scope, write files, execute code, steal credentials, hijack sessions, impersonate admins, or bypass pack/runtime approval gates.

## Files Changed

- `api/app/services/finding_chains.py`
- `api/app/services/ai_agent.py`
- `api/app/services/chatgpt_oauth.py`
- `api/tests/test_ai_agent_reasoning.py`
- `CURRENT_STATE.md`
- `DONE_LOG.md`
- `NEXT_TASK.md`

## Validation

- `python3 scripts/validate_backlog_tasks.py` passed before implementation with exactly one active task.
- `source .venv/bin/activate && python -m py_compile api/app/services/ai_agent.py api/app/services/finding_chains.py api/app/services/chatgpt_oauth.py api/tests/test_ai_agent_reasoning.py` passed.
- Focused compound-chain tests passed:
  - `test_post_task_analysis_creates_engagement_scoped_upload_xss_chain_proposal`
  - `test_post_task_analysis_creates_path_traversal_execution_chain_proposal`
  - existing `api/tests/test_ai_chain_detection.py`
- `source .venv/bin/activate && python -m pytest api/tests/test_ai_agent_reasoning.py api/tests/test_ai_chain_detection.py api/tests/test_chatgpt_oauth.py -q` passed.
- Required `source .venv/bin/activate && python -m pytest api/tests/ -q` passed with existing Alembic deprecation warnings only.
- The required full API suite was rerun after documentation and task promotion and passed again with exit code 0 and the same existing Alembic deprecation warnings.
- Post-promotion `python3 scripts/validate_backlog_tasks.py` passed after `NEXT_TASK.md` was promoted to backlog-232.
- Final `git diff --check` passed.

## Local Acceptance

`http://127.0.0.1:8000` was relevant for safe API acceptance because the changed behavior is exposed through the existing run AI-insights endpoint used by Mission Control.

The initially running local service was stale relative to the current working tree. It was stopped, two background restart attempts did not leave a listener, and current-code acceptance was then performed against a current Uvicorn process on `127.0.0.1:8000` running the edited repo code.

Synthetic local-only acceptance data used engagement `b2fb87a6-b8ef-4ec1-897d-70dcffdcc58c`, run `47fe4db1-44a2-40c2-a761-a6b318a1257b`, and task `67df3281-b674-426f-9057-b893ebe2978b`. The seeded evidence used `https://backlog-219.local` only; no live Gruyere, customer, public internet, or third-party target was contacted.

Local service acceptance produced:

```json
{
  "chain_pattern_id": "web-file-upload-plus-stored-xss",
  "chain_record_type": "compound_attack_chain",
  "engagement_id": "b2fb87a6-b8ef-4ec1-897d-70dcffdcc58c",
  "outcome_status": "succeeded",
  "proposal_kind": "compound_attack_chain",
  "proposal_status": "pending_review",
  "proposal_tool": "xss-extended",
  "run_id": "47fe4db1-44a2-40c2-a761-a6b318a1257b",
  "stored_proposal_count": 1,
  "task_count_after": 25,
  "task_count_before": 25,
  "task_id": "67df3281-b674-426f-9057-b893ebe2978b"
}
```

The API endpoint `GET /api/v1/runs/47fe4db1-44a2-40c2-a761-a6b318a1257b/ai-insights` returned a pending compound-chain proposal:

```json
{
  "chain_pattern_id": "web-file-upload-plus-stored-xss",
  "dispatches_work": false,
  "proposal_count": 1,
  "proposal_kind": "compound_attack_chain",
  "proposal_status": "pending_review",
  "proposal_tool": "xss-extended",
  "run_id": "47fe4db1-44a2-40c2-a761-a6b318a1257b",
  "safe_boundaries": {
    "admin_impersonation": false,
    "credential_theft": false,
    "exploit_chaining": false,
    "operator_review_required": true,
    "session_hijacking": false
  }
}
```

A malformed curl/heredoc pipeline caused a local broken-pipe/JSON decode error during acceptance scripting and was not counted as green. The corrected API read above passed and is the accepted evidence.

## Boundaries

- Pack registry, validation, approval, deployment, runtime binding, scope, ROE, credentials, and kill-switch boundaries were not bypassed.
- Autonomous dispatch logic was not changed.
- Proposals are review-gated and stored only; no tool execution is started by chain reasoning.
- Component findings are not mutated or severity-escalated by chain detection.
- ChatGPT OAuth guidance was tightened to keep provider-generated chain proposals bounded to current-engagement evidence and review-only next steps.
- Transient Codex/planner-generated `codex/tasks/task-20260505...pack-refinement...json` files appeared during validation/health checks and were removed because they were not active tasks and were not queue-backed `backlog-*.json` packages.

## Remaining Risks

- AI provider quality depends on the configured provider/session; deterministic tests cover the safe local fallback path.
- Compound-chain coverage is template-based for the two requested web patterns, not a full attack graph engine.
- Operators still need to explicitly review, approve, and dispatch any follow-up work through existing gates.
