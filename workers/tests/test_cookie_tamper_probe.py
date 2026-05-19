"""Parity test for cookie_tamper_probe after #328 migration."""

from __future__ import annotations

import json

import httpx
import pytest

from workers.runners.cookie_tamper_probe import runner as probe


def _patch_discovery_and_httpx(monkeypatch: pytest.MonkeyPatch, handler) -> None:
    def fake_discover(base: str, scope):
        return {
            "action": f"{base.rstrip('/')}/saveprofile",
            "method": "GET",
            "user_field": "uid",
            "pass_field": "pw",
            "hidden_fields": {"action": "new"},
        }

    monkeypatch.setattr(probe, "_discover_register_form", fake_discover)

    transport = httpx.MockTransport(handler)
    original_client = probe.httpx_client.Client

    def _factory(*args, **kwargs):
        kwargs.pop("transport", None)
        return original_client(*args, transport=transport, **kwargs)

    monkeypatch.setattr(probe.httpx_client, "Client", _factory)


def test_cookie_tamper_flags_pipe_delimiter_injection(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Username containing a pipe delimiter breaks cookie format and
    yields admin context — critical identity-forgery finding."""

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        params = dict(request.url.params)
        if path == "/saveprofile":
            uid = params.get("uid", "")
            if "|admin" in uid:
                # Server returns a session-cookie that grants admin context.
                return httpx.Response(
                    200,
                    headers={"set-cookie": "session=fake_admin; Path=/"},
                    text="ok",
                )
            return httpx.Response(200, headers={"set-cookie": "session=user; Path=/"}, text="ok")
        if path == "/manage":
            if "fake_admin" in request.headers.get("cookie", ""):
                return httpx.Response(
                    200,
                    text="<html>Manage this server — administrator panel</html>",
                )
            return httpx.Response(403)
        return httpx.Response(404)

    _patch_discovery_and_httpx(monkeypatch, handler)

    execution = probe.execute_cookie_tamper_probe(
        ["http://target.test/"], scope_allowlist=None
    )
    payload = json.loads(execution.stdout)
    assert payload["findings"], f"expected identity-forgery finding: {payload}"
    finding = payload["findings"][0]
    assert finding["severity"] == "critical"
    assert finding["category"] == "authentication"
    assert "Pipe" in finding["title"] or "pipe" in finding["title"].lower()


def test_cookie_tamper_no_register_endpoints_list() -> None:
    """Migration #328 removed the hardcoded REGISTER_ENDPOINTS tuple
    definition. The constant name may still appear in docstrings
    historically; check for the actual tuple definition."""
    src = open(probe.__file__, encoding="utf-8").read()
    assert "REGISTER_ENDPOINTS: tuple[str, ...] = (" not in src
    assert '"saveprofile",' not in src


def test_cookie_tamper_skips_when_no_form_found(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(probe, "_discover_register_form", lambda b, s: None)
    execution = probe.execute_cookie_tamper_probe(
        ["http://noform.test/"], scope_allowlist=None
    )
    payload = json.loads(execution.stdout)
    assert payload["findings"] == []
