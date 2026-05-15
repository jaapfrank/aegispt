"""Parity test for file_upload_probe after #328 migration."""

from __future__ import annotations

import json

import httpx
import pytest

from workers.runners.file_upload_probe import runner as probe


def _patch_session(monkeypatch: pytest.MonkeyPatch, handler) -> None:
    transport = httpx.MockTransport(handler)

    def fake_acquire(base: str, scope_allowlist):
        client = httpx.Client(transport=transport, follow_redirects=False)
        return client, "aegispt_test"

    monkeypatch.setattr(probe, "_acquire_session_for_target", fake_acquire)


def test_file_upload_flags_xss_via_uploaded_html(monkeypatch: pytest.MonkeyPatch) -> None:
    """Uploaded HTML served back as text/html with payload reflected ->
    critical XSS finding."""
    uploaded_marker: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        import re
        path = request.url.path
        if path.endswith("/upload2") or path.endswith("/upload"):
            # Capture the marker from the uploaded file body. Use a
            # strict regex so multipart-boundary `--` prefixes don't
            # contaminate the match.
            body = request.content.decode("utf-8", errors="replace")
            match = re.search(r"AEGISFU_([A-Z0-9]{10})", body)
            if match:
                uploaded_marker["marker"] = "AEGISFU_" + match.group(1)
            served_path = f"/aegispt_test/{uploaded_marker.get('marker', 'x')}.html"
            return httpx.Response(
                200,
                text=f'File accessible at: {served_path}',
            )
        if "/aegispt_test/" in path or "AEGISFU_" in path:
            marker = uploaded_marker.get("marker", "")
            return httpx.Response(
                200,
                headers={"content-type": "text/html"},
                text=f"<script>document.title='{marker}'</script><h1>{marker}</h1>",
            )
        return httpx.Response(404)

    _patch_session(monkeypatch, handler)
    execution = probe.execute_file_upload_probe(
        ["http://target.test/"], scope_allowlist=None
    )
    payload = json.loads(execution.stdout)
    assert payload["findings"], f"expected file-upload finding: {payload}"
    upload_finding = next(
        (f for f in payload["findings"] if "Upload XSS" in f["title"]),
        None,
    )
    assert upload_finding is not None
    assert upload_finding["severity"] == "critical"
    assert upload_finding["category"] == "xss"


def test_file_upload_no_register_helper_in_module() -> None:
    src = open(probe.__file__, encoding="utf-8").read()
    assert "def _register_as_author" not in src
    assert '"saveprofile"' not in src
    assert "'saveprofile'" not in src


def test_file_upload_skips_when_auth_unavailable(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(probe, "_acquire_session_for_target", lambda base, scope: (None, None))
    execution = probe.execute_file_upload_probe(
        ["http://noauth.test/"], scope_allowlist=None
    )
    payload = json.loads(execution.stdout)
    assert payload["findings"] == []
