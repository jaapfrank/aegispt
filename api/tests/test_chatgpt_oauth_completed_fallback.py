from __future__ import annotations

from api.app.services.chatgpt_oauth import _extract_text_from_completed_event


def test_extract_text_from_codex_responses_completed_event_shape() -> None:
    event = {
        "type": "response.completed",
        "response": {
            "output": [
                {
                    "type": "message",
                    "content": [
                        {"type": "output_text", "text": '{"action": "pick", '},
                        {"type": "output_text", "text": '"tool": "target-intel"}'},
                    ],
                }
            ],
        },
    }
    assert _extract_text_from_completed_event(event) == '{"action": "pick", "tool": "target-intel"}'


def test_extract_text_skips_reasoning_items() -> None:
    event = {
        "type": "response.completed",
        "response": {
            "output": [
                {"type": "reasoning", "summary": [{"text": "thinking..."}]},
                {
                    "type": "message",
                    "content": [{"type": "output_text", "text": "final"}],
                },
            ],
        },
    }
    assert _extract_text_from_completed_event(event) == "final"


def test_extract_returns_empty_when_no_message_items() -> None:
    event = {"type": "response.completed", "response": {"output": []}}
    assert _extract_text_from_completed_event(event) == ""


def test_extract_handles_missing_response_field() -> None:
    assert _extract_text_from_completed_event({"type": "response.completed"}) == ""


def test_format_oauth_error_payload_from_response_failed_event() -> None:
    from api.app.services.chatgpt_oauth import _format_oauth_error_payload

    event = {
        "type": "response.failed",
        "response": {
            "error": {"code": "context_length_exceeded", "message": "prompt too large"}
        },
    }
    formatted = _format_oauth_error_payload(event)
    assert "context_length_exceeded" in formatted
    assert "prompt too large" in formatted


def test_format_oauth_error_payload_from_inline_error_event() -> None:
    from api.app.services.chatgpt_oauth import _format_oauth_error_payload

    event = {"type": "error", "error": {"code": "server_error", "message": "boom"}}
    assert "server_error" in _format_oauth_error_payload(event)
    assert "boom" in _format_oauth_error_payload(event)


def test_format_oauth_error_payload_none_returns_none_marker() -> None:
    from api.app.services.chatgpt_oauth import _format_oauth_error_payload

    assert _format_oauth_error_payload(None) == "none"
