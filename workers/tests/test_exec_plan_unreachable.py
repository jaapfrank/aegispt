"""exec-plan retry-on-unreachable + honest status (operator-reported 2026-06-04).

The queue was flooded with red FAILED exec-plan tasks whose every step errored
with "[Errno 111] Connection refused" — i.e. the target container was simply
down/starting. A target that is unreachable for every step is an availability
condition, not a runner failure. These tests lock in:
  - a transiently-down target is retried, and if still down the task is SKIPPED
    (exit 78), not FAILED;
  - once the target is confirmed down, later steps are not re-retried (latch);
  - a plan that got at least one real response COMPLETES (exit 0) even if a
    later step was unreachable.
"""
from __future__ import annotations

from typing import Any, Callable

import httpx

from workers.runners.exec_plan import runner as ep


class _FakeResp:
    def __init__(self, status: int = 200, text: str = "ok") -> None:
        self.status_code = status
        self.text = text
        self.content = text.encode()
        self.headers: dict[str, str] = {}
        self.cookies: dict[str, str] = {}


class _FakeClient:
    """Drives each .request() call through `on_call(index)` which returns a
    response or raises. Counts calls so we can assert the retry/latch budget."""

    def __init__(self, on_call: Callable[[int], Any]) -> None:
        self._on_call = on_call
        self.calls = 0

    def __enter__(self) -> "_FakeClient":
        return self

    def __exit__(self, *exc: Any) -> bool:
        return False

    def request(self, **_kw: Any) -> Any:
        idx = self.calls
        self.calls += 1
        result = self._on_call(idx)
        if isinstance(result, Exception):
            raise result
        return result


_REFUSED = httpx.ConnectError("[Errno 111] Connection refused")


def _plan(n_steps: int) -> dict[str, Any]:
    return {"name": "probe", "steps": [
        {"name": f"s{i}", "method": "GET", "url": f"http://t.test/p{i}"}
        for i in range(n_steps)
    ]}


def _run(monkeypatch, on_call: Callable[[int], Any], n_steps: int):
    monkeypatch.setattr("time.sleep", lambda *_a, **_k: None)   # no real backoff
    monkeypatch.setattr(ep, "_scope_check", lambda *_a, **_k: True)
    client = _FakeClient(on_call)
    execution = ep.execute_exec_plan(
        ["http://t.test"], plan=_plan(n_steps),
        scope_allowlist={}, client_factory=lambda **_k: client,
    )
    return execution, client


def test_target_down_is_skipped_not_failed(monkeypatch) -> None:
    # Every request refused: step1 retries then latches target_down; later steps
    # are skipped without re-retrying.
    execution, client = _run(monkeypatch, lambda _i: _REFUSED, n_steps=3)

    assert execution.exit_code == 78  # EX_CONFIG -> "skipped", NOT failed
    assert execution.metadata["status"] == "target_unreachable"
    # 1 initial + _MAX_PROBE_RETRIES on the FIRST step only (latch stops the rest).
    assert client.calls == 1 + ep._MAX_PROBE_RETRIES


def test_partial_success_completes(monkeypatch) -> None:
    # Step 1 responds; step 2 is unreachable. Got data => completed (exit 0).
    def on_call(idx: int) -> Any:
        return _FakeResp(200) if idx == 0 else _REFUSED

    execution, _client = _run(monkeypatch, on_call, n_steps=2)

    assert execution.exit_code == 0
    assert execution.metadata["status"] == "ok"
