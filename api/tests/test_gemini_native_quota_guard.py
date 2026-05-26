from __future__ import annotations

from typing import Any
from unittest.mock import patch

import httpx
import pytest

from api.app.services import gemini_native


class _Resp:
    def __init__(self, status_code: int, body: str = "") -> None:
        self.status_code = status_code
        self.text = body

    def json(self) -> dict[str, Any]:
        return {}


class _FakeClient:
    def __init__(self, status_code: int, calls: list[str]) -> None:
        self._status = status_code
        self._calls = calls

    def __enter__(self) -> "_FakeClient":
        return self

    def __exit__(self, *_: Any) -> None:
        return None

    def post(self, url: str, json: dict[str, Any], headers: dict[str, str]) -> _Resp:
        self._calls.append(url)
        return _Resp(self._status, body="quota exceeded")


@pytest.fixture(autouse=True)
def _isolate_quota_state(monkeypatch: pytest.MonkeyPatch) -> None:
    gemini_native.reset_quota_state()
    monkeypatch.setenv("GEMINI_API_KEY", "test-key-not-real")


def test_first_429_marks_quota_and_returns_none() -> None:
    calls: list[str] = []
    with patch.object(httpx, "Client", lambda **_: _FakeClient(429, calls)):
        result = gemini_native.send_gemini_picker_request(
            model="gemini-3.1-pro-preview",
            instructions="sys",
            user_content="user",
        )

    assert result is None
    assert len(calls) == 1, "first call should have hit the HTTP path"
    assert gemini_native._quota_blocked("gemini-3.1-pro-preview") is True


def test_subsequent_calls_after_429_skip_http_round_trip() -> None:
    calls: list[str] = []
    with patch.object(httpx, "Client", lambda **_: _FakeClient(429, calls)):
        first = gemini_native.send_gemini_picker_request(
            model="gemini-3.1-pro-preview",
            instructions="sys",
            user_content="user-1",
        )
        second = gemini_native.send_gemini_picker_request(
            model="gemini-3.1-pro-preview",
            instructions="sys",
            user_content="user-2",
        )
        third = gemini_native.send_gemini_picker_request(
            model="gemini-3.1-pro-preview",
            instructions="sys",
            user_content="user-3",
        )

    assert first is None
    assert second is None
    assert third is None
    # Only the first call should have made an HTTP request; the next two
    # are short-circuited by the quota guard. This is the wall-clock
    # savings smoke-40 demonstrated we need.
    assert len(calls) == 1


def test_quota_state_is_per_model() -> None:
    calls: list[str] = []
    with patch.object(httpx, "Client", lambda **_: _FakeClient(429, calls)):
        gemini_native.send_gemini_picker_request(
            model="gemini-3.1-pro-preview",
            instructions="sys",
            user_content="user",
        )

    # Different model should NOT be blocked by another model's 429.
    assert gemini_native._quota_blocked("gemini-3.1-pro-preview") is True
    assert gemini_native._quota_blocked("gemini-3.5-flash") is False


def test_backoff_expires_after_quota_window(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[str] = []
    with patch.object(httpx, "Client", lambda **_: _FakeClient(429, calls)):
        gemini_native.send_gemini_picker_request(
            model="gemini-3.1-pro-preview",
            instructions="sys",
            user_content="user",
        )

    assert gemini_native._quota_blocked("gemini-3.1-pro-preview") is True

    fake_now = gemini_native._quota_exhausted_at[
        "gemini-3.1-pro-preview"
    ] + gemini_native.QUOTA_BACKOFF_SECONDS + 1.0
    monkeypatch.setattr(gemini_native.time, "time", lambda: fake_now)

    assert gemini_native._quota_blocked("gemini-3.1-pro-preview") is False
