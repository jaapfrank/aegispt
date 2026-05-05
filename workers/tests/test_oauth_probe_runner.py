from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread
from types import SimpleNamespace
from urllib.parse import parse_qs, urlparse

import httpx

from workers.orchestration.findings import extract_findings
from workers.orchestration.tasks import SUPPORTED_TOOLS
from workers.runners.base.contracts import EvidenceArtifact
from workers.runners.oauth_probe.runner import (
    OAUTH_PROBE_RESULTS_ARTIFACT_NAME,
    execute_oauth_probe,
)


class ArtifactRecord:
    uri = "artifact://oauth-probe/results"


def _client_factory(handler):
    transport = httpx.MockTransport(handler)

    def factory(**kwargs):
        return httpx.Client(transport=transport, **kwargs)

    return factory


def test_oauth_probe_detects_common_oidc_misconfigurations_against_local_fixture() -> None:
    class Handler(BaseHTTPRequestHandler):
        def _base_url(self) -> str:
            return f"http://{self.headers.get('Host')}"

        def _send(self, status: int, body: bytes = b"", *, content_type: str = "text/html") -> None:
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self) -> None:  # noqa: N802
            parsed = urlparse(self.path)
            base_url = self._base_url()
            if parsed.path == "/.well-known/openid-configuration":
                self._send(
                    200,
                    json.dumps(
                        {
                            "issuer": base_url,
                            "authorization_endpoint": f"{base_url}/oauth/authorize",
                            "token_endpoint": f"{base_url}/oauth/token",
                            "response_types_supported": ["code", "token", "id_token"],
                        }
                    ).encode("utf-8"),
                    content_type="application/json",
                )
                return
            if parsed.path == "/app/":
                body = (
                    '<html><head><script src="/app/app.js"></script></head>'
                    '<body data-framework="React SPA">'
                    f'<a href="/oauth/authorize?response_type=code&client_id=spa-client&redirect_uri={base_url}/app/callback">Login</a>'
                    '<a href="/app/callback#access_token=leaky-page-token">Callback</a>'
                    "</body></html>"
                ).encode("utf-8")
                self._send(200, body)
                return
            if parsed.path == "/app/app.js":
                body = (
                    'window.__framework="React"; '
                    f'const authUrl="{base_url}/oauth/authorize?response_type=code&client_id=spa-client&redirect_uri={base_url}/app/callback";'
                ).encode("utf-8")
                self._send(200, body, content_type="application/javascript")
                return
            if parsed.path == "/oauth/authorize":
                params = parse_qs(parsed.query)
                redirect_uri = params.get("redirect_uri", [""])[-1]
                response_type = params.get("response_type", [""])[-1]
                if not redirect_uri:
                    self._send(400, b"missing redirect_uri")
                    return
                location = (
                    f"{redirect_uri}#access_token=implicit-secret&state=aegispt-state"
                    if response_type == "token"
                    else f"{redirect_uri}?code=lab-code&state=aegispt-state"
                )
                self.send_response(302)
                self.send_header("Location", location)
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            self._send(404, b"not found")

        def log_message(self, format: str, *args) -> None:  # noqa: A003
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = server.server_address
    base_url = f"http://{host}:{port}"
    try:
        execution = execute_oauth_probe(
            [f"{base_url}/app/"],
            scope_allowlist={"urls": [f"{base_url}/"]},
            token_evidence=[
                {
                    "source_url": f"{base_url}/app/callback",
                    "requested_scope": "openid",
                    "granted_scope": "openid profile email",
                }
            ],
        )
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)

    assert execution.tool == "oauth-probe"
    assert execution.exit_code == 0
    assert execution.artifacts[0].name == OAUTH_PROBE_RESULTS_ARTIFACT_NAME
    decoded_artifact = execution.artifacts[0].data.decode("utf-8")
    assert "implicit-secret" not in decoded_artifact
    assert "leaky-page-token" not in decoded_artifact

    payload = json.loads(decoded_artifact)
    titles = {finding["title"] for finding in payload["findings"]}
    assert "OAuth2 Redirect URI Bypass - Account Takeover Possible" in titles
    assert "OAuth2 State Parameter Missing" in titles
    assert "OAuth2 Authorization Code Flow Without PKCE" in titles
    assert "OAuth2/OIDC Token Leaked in URL" in titles
    assert "OAuth2 Token Scope Over-Provisioning" in titles
    assert "OAuth2 Implicit Flow Still Supported" in titles
    assert payload["safety"]["third_party_idp_requests_attempted"] is False
    assert payload["safety"]["raw_tokens_stored"] is False

    task = SimpleNamespace(
        tool="oauth-probe",
        target_id=f"{base_url}/app/",
        params_json={},
    )
    findings = extract_findings(
        task=task,
        artifact=EvidenceArtifact(
            name=OAUTH_PROBE_RESULTS_ARTIFACT_NAME,
            content_type="application/json",
            data=execution.artifacts[0].data,
            kind="runner-results",
        ),
        artifact_record=ArtifactRecord(),
    )

    assert len(findings) >= 5
    assert "oauth-oidc-validation" in findings[0].methodology_tags


def test_oauth_probe_skips_third_party_idp_authorization_endpoint() -> None:
    requested_hosts: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requested_hosts.append(str(request.url.host))
        if request.url.path == "/.well-known/openid-configuration":
            return httpx.Response(
                200,
                json={
                    "authorization_endpoint": "https://accounts.google.com/o/oauth2/v2/auth",
                    "response_types_supported": ["code"],
                },
            )
        return httpx.Response(200, text="<html>ok</html>")

    execution = execute_oauth_probe(
        ["https://portal.example.test/app/"],
        scope_allowlist={"urls": ["https://portal.example.test/"]},
        client_factory=_client_factory(handler),
    )

    payload = json.loads(execution.artifacts[0].data.decode("utf-8"))
    assert "accounts.google.com" not in requested_hosts
    assert payload["summary"]["skipped_third_party_idp_count"] == 1
    assert any(
        check.get("skip_reason") == "authorization endpoint outside approved scope or third-party IdP"
        for check in payload["checks"]
    )


def test_oauth_probe_is_supported() -> None:
    assert "oauth-probe" in SUPPORTED_TOOLS
