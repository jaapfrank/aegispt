# backlog-436 — ChatGPT-OAuth picker provider path

Date: 2026-05-21

## Scope

Enabled a provider branch in `api/app/services/assessment_loop.py` so runs
configured with `configuration_json.llm_provider = "chatgpt_oauth"` or
`"gpt-5.4"` can request picker decisions through the existing governed
ChatGPT OAuth streaming JSON helper.

This is provider-path enablement only. It does not claim ChatGPT-OAuth makes
better choices than Anthropic.

## Behavior

- Anthropic picker behavior remains on the existing `messages.create` path
  with `tools=` and `output_config.format.type = "json_schema"`.
- ChatGPT-OAuth picker behavior routes through
  `send_chatgpt_backend_streaming_json_request`.
- The same dynamic picker schema is reused for both branches.
- The ChatGPT-OAuth branch embeds the schema into the structured-output
  instructions and parses the streamed JSON object returned by the existing
  helper.
- No runner execution, approval gate, scope gate, finding schema, capability
  pack flow, deployment flow, or runtime binding behavior changed.

## Validation

- `python3 scripts/validate_backlog_tasks.py` passed.
- `python3 -m compileall -q api` passed.
- `python3 -m compileall -q api/app/services/assessment_loop.py api/app/services/llm_provider.py` passed.
- `.venv/bin/ruff check api/app/services/assessment_loop.py api/app/services/chatgpt_oauth.py` passed.
- `.venv/bin/ruff check api/app/services/assessment_loop.py api/app/services/chatgpt_oauth.py api/app/services/llm_provider.py api/tests/test_assessment_loop_picker_chatgpt_oauth.py api/tests/test_llm_provider.py` passed.
- `.venv/bin/pytest api/tests/test_assessment_loop_picker_chatgpt_oauth.py api/tests/test_llm_provider.py -q` passed with 17 tests.
- `git diff --check` passed.

## Evidence

- `api/tests/test_assessment_loop_picker_chatgpt_oauth.py::test_picker_uses_chatgpt_oauth_streaming_json_branch` proves a ChatGPT-OAuth configured picker run calls the OAuth streaming JSON helper instead of returning `None` because it is non-Anthropic.
- `api/tests/test_assessment_loop_picker_chatgpt_oauth.py::test_picker_keeps_anthropic_messages_create_branch` proves the Anthropic branch still calls `messages.create` with `output_config.format.type = "json_schema"` and `tools`.
- `api/tests/test_llm_provider.py::test_for_run_picks_chatgpt_oauth_provider_from_run_configuration` proves run configuration now resolves ChatGPT-OAuth to the provider branch.

## Remaining gap

The branch is structurally enabled and fixture-tested. The next task
(`backlog-437`) must measure Claude vs ChatGPT-OAuth on matched evidence before
any capability or quality claim is made.
