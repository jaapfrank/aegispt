"""Focused picker provider routing tests for backlog-436."""
from __future__ import annotations

import json
import sys
import uuid
from types import ModuleType, SimpleNamespace
from typing import Any

from api.app.services import assessment_loop as al


def _stub_run(configuration_json: dict[str, Any]) -> SimpleNamespace:
    return SimpleNamespace(
        id=uuid.uuid4(),
        engagement_id=uuid.uuid4(),
        configuration_json=configuration_json,
        findings=[],
        tasks=[],
        engagement=SimpleNamespace(scope_definition_json={}, engagement_token=""),
        scope_id=None,
        autonomous_intrusive_allowed=False,
    )


def test_picker_uses_chatgpt_oauth_streaming_json_branch(monkeypatch) -> None:
    calls: list[dict[str, Any]] = []

    def fake_send_chatgpt_backend_streaming_json_request(**kwargs: Any) -> dict[str, Any]:
        calls.append(kwargs)
        return {
            "action": "stop",
            "stop_reason": "exhausted",
            "summary": "oauth branch made a structured decision",
            "confidence": 0.62,
        }

    monkeypatch.setattr(
        "api.app.services.chatgpt_oauth.send_chatgpt_backend_streaming_json_request",
        fake_send_chatgpt_backend_streaming_json_request,
    )

    run = _stub_run({"llm_provider": "chatgpt_oauth"})
    decision = al._claude_select_next_action(
        run=run,
        tested_keys={"target-intel|https://example.test"},
        available_tools=["target-intel", "exec-plan"],
        targets=[{"value": "https://example.test"}],
        session=object(),
    )

    assert decision == {
        "action": "stop",
        "stop_reason": "exhausted",
        "summary": "oauth branch made a structured decision",
        "confidence": 0.62,
    }
    assert len(calls) == 1
    assert calls[0]["engagement_id"] == run.engagement_id
    assert calls[0]["model"] == "gpt-5.4"
    assert "CHATGPT OAUTH PICKER MODE" in calls[0]["instructions"]
    assert "anyOf" in calls[0]["instructions"]
    assert calls[0]["input_items"][0]["content"][0]["type"] == "input_text"
    assert "Available tools: target-intel, exec-plan" in calls[0]["input_items"][0]["content"][0]["text"]


def test_picker_keeps_anthropic_messages_create_branch(monkeypatch) -> None:
    captured: list[dict[str, Any]] = []
    decision_text = json.dumps({
        "action": "stop",
        "stop_reason": "exhausted",
        "summary": "anthropic branch stayed intact",
        "confidence": 0.7,
    })

    class FakeMessages:
        def create(self, **kwargs: Any) -> SimpleNamespace:
            captured.append(kwargs)
            return SimpleNamespace(
                content=[SimpleNamespace(type="text", text=decision_text)],
                stop_reason="end_turn",
                usage=SimpleNamespace(
                    input_tokens=1,
                    cache_read_input_tokens=0,
                    cache_creation_input_tokens=0,
                    output_tokens=1,
                ),
            )

    fake_anthropic = ModuleType("anthropic")
    fake_anthropic.Anthropic = lambda api_key=None: SimpleNamespace(messages=FakeMessages())  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "anthropic", fake_anthropic)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")

    run = _stub_run({"llm_provider": "claude-opus-4-7"})
    decision = al._claude_select_next_action(
        run=run,
        tested_keys={"target-intel|https://example.test"},
        available_tools=["target-intel", "exec-plan"],
        targets=[{"value": "https://example.test"}],
        session=None,
    )

    assert decision["summary"] == "anthropic branch stayed intact"
    assert len(captured) == 1
    assert captured[0]["model"] == "claude-opus-4-7"
    assert captured[0]["output_config"]["format"]["type"] == "json_schema"
    assert captured[0]["tools"]
