"""Parity test for stored_xss_probe after #328 migration.

Mocks `acquire_session` so we exercise the migrated probe's
vuln-detection logic against a Gruyere-style mock target without
running the full auth_discoverer pipeline.
"""

from __future__ import annotations

import json

import httpx
import pytest

from workers.runners.stored_xss_probe import runner as probe


def _patch_session(monkeypatch: pytest.MonkeyPatch, handler) -> None:
    """Replace _acquire_session_for_target with a mock that returns a
    MockTransport-backed client + canned username."""
    transport = httpx.MockTransport(handler)

    def fake_acquire(base: str, scope_allowlist):
        client = httpx.Client(transport=transport, follow_redirects=False)
        return client, "aegispt_test"

    monkeypatch.setattr(probe, "_acquire_session_for_target", fake_acquire)


def test_stored_xss_confirms_reflection_on_render(monkeypatch: pytest.MonkeyPatch) -> None:
    """After authenticated submit of a script payload, render endpoint
    serves it back verbatim -> critical stored-XSS finding."""

    captured: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path.endswith("/newsnippet2") or path.endswith("/snippet/new"):
            captured["payload"] = dict(request.url.params)
            return httpx.Response(200, text="ok")
        if path.endswith("/snippets.gtl") or path.endswith("/snippets"):
            # Echo any submitted payload — unsanitised.
            payload = captured.get("payload", {})
            content = next(iter(payload.values()), "")
            return httpx.Response(200, text=f"<html>{content}</html>")
        return httpx.Response(404)

    _patch_session(monkeypatch, handler)

    execution = probe.execute_stored_xss_probe(
        ["http://target.test/"],
        scope_allowlist=None,
    )
    payload = json.loads(execution.stdout)
    assert payload["findings"], f"expected stored-XSS finding, got: {payload}"
    finding = payload["findings"][0]
    assert finding["category"] == "xss"
    assert finding["severity"] == "critical"
    assert "Stored XSS" in finding["title"]


def test_stored_xss_no_register_helper_in_module() -> None:
    """Migration #328 removed the local `_register_as_author` function
    and the hardcoded `saveprofile` URL list. Docstrings may still
    reference these names historically, so check for the function
    definition / URL string specifically."""
    src = open(probe.__file__, encoding="utf-8").read()
    assert "def _register_as_author" not in src
    assert '"saveprofile"' not in src
    assert "'saveprofile'" not in src


def test_stored_xss_skips_when_auth_unavailable(monkeypatch: pytest.MonkeyPatch) -> None:
    """Probe records an `auth_unavailable` trace and produces no
    findings when acquire_session fails."""
    monkeypatch.setattr(probe, "_acquire_session_for_target", lambda base, scope: (None, None))
    execution = probe.execute_stored_xss_probe(
        ["http://noauth.test/"],
        scope_allowlist=None,
    )
    payload = json.loads(execution.stdout)
    assert payload["findings"] == []
    assert any(
        a.get("result") == "auth_unavailable"
        for t in payload["trace"]
        for a in t.get("attempts", [])
    )
