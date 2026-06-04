"""Local-qwen picker thinking-mode wiring (2026-06-04).

Qwen3.6 is a *thinking* variant: it streams chain-of-thought into a separate
`reasoning_content` field and, left unchecked, exhausts max_tokens before ever
emitting the JSON decision in `content` — so the picker would silently return
None and the loop would fall back to the hardcoded sequence. These tests lock in
the fix: the picker request disables thinking, and the parser falls back to
`reasoning_content` for any build that ignores the kwarg.
"""
from __future__ import annotations

import uuid
from types import SimpleNamespace
from typing import Any

import httpx

from api.app.services import assessment_loop as al


def _stub_run() -> SimpleNamespace:
    return SimpleNamespace(
        id=uuid.uuid4(),
        engagement_id=uuid.uuid4(),
        configuration_json={"llm_provider": "local-qwen"},
        findings=[],
        tasks=[],
        engagement=SimpleNamespace(scope_definition_json={}, engagement_token=""),
        scope_id=None,
        autonomous_intrusive_allowed=False,
    )


class _FakeResp:
    status_code = 200

    def __init__(self, payload: dict[str, Any]) -> None:
        self._payload = payload

    def json(self) -> dict[str, Any]:
        return self._payload


class _FakeClient:
    """Captures the posted body and returns a canned chat-completions payload."""

    captured: dict[str, Any] = {}

    def __init__(self, payload: dict[str, Any]) -> None:
        self._payload = payload

    def __enter__(self) -> "_FakeClient":
        return self

    def __exit__(self, *exc: Any) -> None:
        return None

    def post(self, _url: str, json: dict[str, Any], headers: dict[str, Any]) -> _FakeResp:
        _FakeClient.captured = json
        return _FakeResp(self._payload)


def _wire(monkeypatch, payload: dict[str, Any]) -> None:
    monkeypatch.setenv("AEGISPT_LOCAL_LLM_URL", "http://127.0.0.1:8801")
    # Isolate the body+parse logic from the heavy prompt/plan helpers.
    monkeypatch.setattr(al, "_picker_schema_for_current_state", lambda **_: {"type": "object"})
    monkeypatch.setattr(al, "_picker_prompt_with_skills", lambda: "PICKER")
    monkeypatch.setattr(al, "_decode_picker_plan", lambda payload: payload)

    def _client(*_a: Any, **_k: Any) -> _FakeClient:
        return _FakeClient(payload)

    monkeypatch.setattr(httpx, "Client", _client)


def test_picker_disables_thinking_in_request_body(monkeypatch) -> None:
    payload = {"choices": [{"message": {"content": '{"action":"stop"}'}}]}
    _wire(monkeypatch, payload)

    decision = al._local_qwen_select_next_action(
        run=_stub_run(), session=object(), user_content="state",
        tested_keys=set(), available_tools=["target-intel"],
    )

    assert decision == {"action": "stop"}
    # The fix: thinking is disabled so the JSON lands in `content`.
    assert _FakeClient.captured.get("chat_template_kwargs") == {"enable_thinking": False}


def test_picker_falls_back_to_reasoning_content(monkeypatch) -> None:
    # A build that ignored enable_thinking: content empty, decision in reasoning_content.
    payload = {"choices": [{"message": {"content": "", "reasoning_content": '{"action":"continue"}'}}]}
    _wire(monkeypatch, payload)

    decision = al._local_qwen_select_next_action(
        run=_stub_run(), session=object(), user_content="state",
        tested_keys=set(), available_tools=["target-intel"],
    )

    assert decision == {"action": "continue"}
