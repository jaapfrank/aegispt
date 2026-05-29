"""Regression tests for the topology facts that unblocked the autonomous
SSRF solve (2026-05-28): manual-dispatch route extraction + internal
listen-port extraction. Without these the agent guessed wrong routes (404)
and pointed SSRF self-fetches at the external port (502 fetch_failed)."""
from __future__ import annotations

from workers.runners.pre_recon_source.runner import _scan_file


def _write(tmp_path, name, body):
    p = tmp_path / name
    p.write_text(body, encoding="utf-8")
    return p


def test_manual_dispatch_routes_extracted(tmp_path):
    """BaseHTTPRequestHandler `parsed.path == "/x"` dispatch routes must be
    surfaced (they were invisible before, so the agent kept guessing)."""
    src = _write(
        tmp_path,
        "app.py",
        'def do_POST(self):\n'
        '    parsed = urllib.parse.urlparse(self.path)\n'
        '    if parsed.path == "/tools/webhook-tester":\n'
        '        self._handle_webhook_tester()\n'
        '    elif parsed.path == "/internal/metadata":\n'
        '        self._handle_internal_metadata()\n'
        '    elif self.path.startswith("/api/v1"):\n'
        '        self._handle_api()\n',
    )
    hits = _scan_file(src, tmp_path)
    paths = {r["path"] for r in hits.get("routes", [])}
    assert "/tools/webhook-tester" in paths
    assert "/internal/metadata" in paths
    assert "/api/v1" in paths


def test_internal_listen_port_extracted_from_source(tmp_path):
    """The internal listen port (env default / HTTPServer bind) must be
    surfaced so SSRF self-fetch targets the internal port, not the external."""
    src = _write(
        tmp_path,
        "app.py",
        'port = int(os.environ.get("AEGISPT_LAB_PORT", "8080"))\n'
        'server = ThreadingHTTPServer((host, port), LabRequestHandler)\n',
    )
    hits = _scan_file(src, tmp_path)
    ports = {p["port"] for p in hits.get("listen_ports", [])}
    assert "8080" in ports


def test_internal_listen_port_extracted_from_dockerfile(tmp_path):
    """EXPOSE / ENV *PORT* in a Dockerfile must also surface the internal port."""
    df = _write(
        tmp_path,
        "Dockerfile",
        "FROM python:3.12-slim\n"
        "ENV AEGISPT_LAB_PORT=8080\n"
        "EXPOSE 8080\n",
    )
    hits = _scan_file(df, tmp_path)
    ports = {p["port"] for p in hits.get("listen_ports", [])}
    assert "8080" in ports


def test_gate_tokens_extracted(tmp_path):
    """Source-defined magic constants that gate sensitive branches must be
    surfaced verbatim — the class-B unblock (log-lookup token, cgi grammar,
    binder key, custom headers). CVE-canonical payloads never hit these."""
    src = _write(
        tmp_path,
        "app.py",
        'def handle(self):\n'
        '    if self.headers.get("X-Lab-Function", "").startswith("fn:") and "|print_flag" in self.headers.get("X-Lab-Function", ""):\n'
        '        return self.flag()\n'
        '    msg = body.get("message", "").replace("${lab:lookup:flag}", self.flag())\n'
        '    if body.get("profile.class.module.loader.resource") == "flag":\n'
        '        return self.flag()\n'
        '    if self.headers.get("X-Frontend-Trust") != "trusted-autodiscover":\n'
        '        return self.forbidden()\n',
    )
    hits = _scan_file(src, tmp_path)
    toks = {t["token"] for t in hits.get("gate_tokens", [])}
    assert "${lab:lookup:flag}" in toks  # interpolation token
    assert "profile.class.module.loader.resource" in toks  # nested binder key
    assert "X-Lab-Function" in toks  # custom header name
    assert "X-Frontend-Trust" in toks
    # grammar prefix / substring captured
    assert any("fn:" in t for t in toks)


def test_flask_run_and_node_listen_ports(tmp_path):
    src = _write(
        tmp_path,
        "server.py",
        'app.run(host="0.0.0.0", port=5000)\n'
        'httpServer.listen(3000)\n',
    )
    hits = _scan_file(src, tmp_path)
    ports = {p["port"] for p in hits.get("listen_ports", [])}
    assert "5000" in ports
    assert "3000" in ports
