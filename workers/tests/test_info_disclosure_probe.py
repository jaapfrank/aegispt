"""Parity test for info_disclosure_probe after #328 migration.

Verifies that with `.gtl` paths removed and the generic catalog
preserved, the probe still flags sensitive-content disclosure on a
Gruyere-style target. No live HTTP.
"""

from __future__ import annotations

import json

import httpx
import pytest

from workers.runners.info_disclosure_probe import runner as probe


def _patch_httpx(monkeypatch: pytest.MonkeyPatch, handler) -> None:
    transport = httpx.MockTransport(handler)
    original_client = httpx.Client

    def _factory(*args, **kwargs):
        kwargs.pop("transport", None)
        return original_client(*args, transport=transport, **kwargs)

    monkeypatch.setattr(probe.httpx_client, "Client", _factory)


def test_info_disclosure_flags_dump_endpoint(monkeypatch: pytest.MonkeyPatch) -> None:
    """Generic /dump path on a target that leaks cleartext passwords is
    flagged as critical info-disclosure."""

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path == "/dump":
            # Simulate a Gruyere-style dict-dump that contains a
            # quoted password value (matches `password_leak` regex).
            return httpx.Response(
                200,
                text=(
                    "Server state dump:\n"
                    "{'name': 'alice', 'password': 'secret123', 'is_admin': true}\n"
                    "{'name': 'bob', 'password': 'hunter2', 'is_admin': false}\n"
                ),
                headers={"content-type": "text/plain"},
            )
        return httpx.Response(404)

    _patch_httpx(monkeypatch, handler)

    execution = probe.execute_info_disclosure_probe(
        ["http://target.test/"],
        scope_allowlist=None,
    )
    payload = json.loads(execution.stdout)
    assert payload["findings"], f"expected findings, got: {payload}"
    leak = payload["findings"][0]
    assert leak["severity"] == "critical"
    assert leak["category"] == "info-disclosure"
    assert "dump" in leak["title"].lower()
    assert any(
        pat["type"] == "password_leak"
        for pat in leak["evidence"]["leak_patterns"]
    )


def test_info_disclosure_no_gtl_paths_in_probe_list() -> None:
    """Migration #328 must remove Gruyere-specific `.gtl` paths."""
    paths = {p for p, _ in probe.PROBE_PATHS}
    assert "/dump.gtl" not in paths
    assert "/debug.gtl" not in paths


def test_info_disclosure_skips_unleaky_responses(monkeypatch: pytest.MonkeyPatch) -> None:
    """Empty / non-sensitive responses do not produce findings."""

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="OK")

    _patch_httpx(monkeypatch, handler)
    execution = probe.execute_info_disclosure_probe(
        ["http://clean.test/"],
        scope_allowlist=None,
    )
    payload = json.loads(execution.stdout)
    assert payload["findings"] == []
