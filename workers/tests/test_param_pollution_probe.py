"""Parity test for param_pollution_probe after #328 migration.

Mocks `_discover_register_form` so we exercise the migrated probe's
mass-assignment attack against a Gruyere-style mock target.
"""

from __future__ import annotations

import json

import httpx
import pytest

from workers.runners.param_pollution_probe import runner as probe


def _patch_discovery_and_httpx(monkeypatch: pytest.MonkeyPatch, handler) -> None:
    """Mock _discover_register_form + httpx.Client."""

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


def test_param_pollution_flags_admin_flag_at_registration(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Registering with `is_admin=True` and then reaching an admin
    endpoint yields a critical privilege-escalation finding."""

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        params = dict(request.url.params)
        if path == "/saveprofile" and params.get("action") == "new":
            # Server accepts the polluted param and sets a session cookie.
            headers = {}
            if params.get("is_admin") in ("True", "true", "1"):
                headers["set-cookie"] = "session=admin_abc; Path=/"
            else:
                headers["set-cookie"] = "session=user_xyz; Path=/"
            return httpx.Response(200, headers=headers, text="ok")
        if path == "/manage":
            cookie = request.headers.get("cookie", "")
            if "admin_abc" in cookie:
                return httpx.Response(
                    200,
                    text="<html><body>Manage this server: admin-only panel</body></html>",
                )
            return httpx.Response(403)
        return httpx.Response(404)

    _patch_discovery_and_httpx(monkeypatch, handler)

    execution = probe.execute_param_pollution_probe(
        ["http://target.test/"], scope_allowlist=None
    )
    payload = json.loads(execution.stdout)
    assert payload["findings"], f"expected priv-esc finding: {payload}"
    finding = payload["findings"][0]
    assert finding["severity"] == "critical"
    assert finding["category"] == "broken-access-control"
    assert "Mass Assignment" in finding["title"]


def test_param_pollution_no_local_register_helper() -> None:
    """Migration #328 removed `_try_register` and the hardcoded
    saveprofile URL list."""
    src = open(probe.__file__, encoding="utf-8").read()
    assert "_try_register(" not in src
    assert "f\"{base}saveprofile\"" not in src
    assert "UPDATE_ENDPOINTS" not in src


def test_param_pollution_skips_when_no_form_found(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(probe, "_discover_register_form", lambda b, s: None)
    execution = probe.execute_param_pollution_probe(
        ["http://noform.test/"], scope_allowlist=None
    )
    payload = json.loads(execution.stdout)
    assert payload["findings"] == []
    assert any(
        step.get("result") == "no_form_found"
        for t in payload["trace"]
        for step in t.get("steps", [])
    )
