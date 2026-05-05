from __future__ import annotations

import base64
import hashlib
import hmac
import json
import subprocess
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from threading import Thread
from typing import Any

import pytest

from workers.orchestration.tasks import SUPPORTED_TOOLS, dispatch_runner
from workers.runners.base.contracts import RunnerRequest
from workers.runners.web_depth.runner import (
    CONTENT_DISCOVERY_RESULTS_ARTIFACT_NAME,
    EXTERNAL_OSINT_RESULTS_ARTIFACT_NAME,
    JWT_RESULTS_ARTIFACT_NAME,
    NIKTO_RESULTS_ARTIFACT_NAME,
    SQLMAP_RESULTS_ARTIFACT_NAME,
    VULN_COMPONENTS_RESULTS_ARTIFACT_NAME,
    XXE_RESULTS_ARTIFACT_NAME,
    execute_content_discovery,
    execute_external_osint_recon,
    execute_jwt_probe,
    execute_nikto_scan,
    execute_sqlmap_confirmation,
    execute_vuln_components_scan,
    execute_xxe_probe,
)


def test_web_depth_tools_are_supported() -> None:
    assert {
        "content-discovery",
        "nikto",
        "sqlmap",
        "external-osint",
        "xxe-probe",
        "jwt-probe",
        "ssrf-probe",
        "deserialization-probe",
        "session-security",
        "auth-flow",
        "client-state",
        "headers-security",
        "graphql-probe",
        "ssti-probe",
        "http-smuggling",
        "oauth-probe",
        "vuln-components",
    }.issubset(SUPPORTED_TOOLS)


def _b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _test_jwt(payload: dict[str, Any], *, secret: str = "secret", alg: str = "HS256") -> str:
    header = {"alg": alg, "typ": "JWT"}
    encoded_header = _b64url(json.dumps(header, separators=(",", ":"), sort_keys=True).encode())
    encoded_payload = _b64url(json.dumps(payload, separators=(",", ":"), sort_keys=True).encode())
    signing_input = f"{encoded_header}.{encoded_payload}".encode("ascii")
    digest = hmac.new(secret.encode("utf-8"), signing_input, hashlib.sha256).digest()
    return f"{encoded_header}.{encoded_payload}.{_b64url(digest)}"


def test_content_discovery_produces_hidden_endpoint_finding(tmp_path: Path) -> None:
    wordlist = tmp_path / "words.txt"
    wordlist.write_text("admin\n", encoding="utf-8")

    def fake_runner(command: list[str], **_: Any) -> subprocess.CompletedProcess[str]:
        output_path = Path(command[command.index("-o") + 1])
        output_path.write_text(
            json.dumps(
                {
                    "results": [
                        {
                            "url": "https://example.com/app/admin",
                            "status": 403,
                            "length": 120,
                        }
                    ]
                }
            ),
            encoding="utf-8",
        )
        return subprocess.CompletedProcess(command, 0, stdout="", stderr="")

    execution = execute_content_discovery(
        ["https://example.com/app/"],
        scope_allowlist={"urls": ["https://example.com/app/"]},
        wordlist_path=str(wordlist),
        command_runner=fake_runner,
    )

    assert execution.tool == "content-discovery"
    assert execution.exit_code == 0
    assert execution.artifacts[0].name == CONTENT_DISCOVERY_RESULTS_ARTIFACT_NAME
    payload = json.loads(execution.artifacts[0].data.decode("utf-8"))
    assert payload["findings"][0]["title"] == "Hidden Endpoint Discovered"
    assert payload["findings"][0]["target"] == "https://example.com/app/admin"


def test_nikto_produces_web_configuration_finding() -> None:
    def fake_runner(command: list[str], **_: Any) -> subprocess.CompletedProcess[str]:
        output_path = Path(command[command.index("-output") + 1])
        output_path.write_text(
            json.dumps(
                {
                    "vulnerabilities": [
                        {
                            "msg": "The X-Frame-Options header is not present.",
                            "url": "https://example.com/app/",
                        }
                    ]
                }
            ),
            encoding="utf-8",
        )
        return subprocess.CompletedProcess(command, 0, stdout="", stderr="")

    execution = execute_nikto_scan(
        ["https://example.com/app/"],
        scope_allowlist={"urls": ["https://example.com/app/"]},
        command_runner=fake_runner,
    )

    assert execution.artifacts[0].name == NIKTO_RESULTS_ARTIFACT_NAME
    payload = json.loads(execution.artifacts[0].data.decode("utf-8"))
    assert payload["findings"][0]["title"] == "Web Server Configuration Finding"
    assert payload["findings"][0]["severity"] == "low"


def test_sqlmap_requires_explicit_or_zap_flagged_parameter() -> None:
    with pytest.raises(ValueError, match="explicit parameter target"):
        execute_sqlmap_confirmation(
            ["https://example.com/app/"],
            scope_allowlist={"urls": ["https://example.com/app/"]},
        )


def test_sqlmap_confirms_only_explicit_parameter_target() -> None:
    def fake_runner(command: list[str], **_: Any) -> subprocess.CompletedProcess[str]:
        assert command[command.index("-p") + 1] == "id"
        return subprocess.CompletedProcess(
            command,
            0,
            stdout="Parameter: id (GET) is vulnerable",
            stderr="",
        )

    execution = execute_sqlmap_confirmation(
        ["https://example.com/app/"],
        scope_allowlist={"urls": ["https://example.com/app/"]},
        injectable_parameters=[{"url": "https://example.com/app/item?id=1", "parameter": "id"}],
        command_runner=fake_runner,
    )

    assert execution.artifacts[0].name == SQLMAP_RESULTS_ARTIFACT_NAME
    payload = json.loads(execution.artifacts[0].data.decode("utf-8"))
    assert payload["findings"][0]["title"] == "Confirmed SQL Injection"


@pytest.fixture
def xxe_fixture_server() -> str:
    class Handler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:  # noqa: N802
            body = self.rfile.read(int(self.headers.get("Content-Length", "0") or "0"))
            if b"file:///etc/passwd" in body and b"&xxe;" in body:
                payload = b"<result>root:x:0:0:root:/root:/bin/bash</result>"
            else:
                payload = b"<result>ok</result>"
            self.send_response(200)
            self.send_header("Content-Type", "application/xml")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def log_message(self, format: str, *args: Any) -> None:  # noqa: A003
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = server.server_address
    try:
        yield f"http://{host}:{port}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def test_xxe_probe_detects_direct_file_read_against_local_fixture(xxe_fixture_server: str) -> None:
    endpoint = f"{xxe_fixture_server}/app/xml"
    execution = execute_xxe_probe(
        [endpoint],
        scope_allowlist={"urls": [f"{xxe_fixture_server}/app/"]},
        xml_endpoints=[{"url": endpoint, "content_type": "application/xml"}],
    )

    assert execution.tool == "xxe-probe"
    assert execution.exit_code == 0
    assert execution.artifacts[0].name == XXE_RESULTS_ARTIFACT_NAME
    payload = json.loads(execution.artifacts[0].data.decode("utf-8"))
    assert payload["summary"]["dos_payloads_sent"] == 0
    assert payload["safety"]["payload_family"] == "read-only-file-uri"
    assert payload["findings"][0]["title"] == "XXE - File Read Possible (Direct)"
    assert payload["findings"][0]["severity"] == "critical"
    assert payload["findings"][0]["evidence"]["file_uri"] == "file:///etc/passwd"


def test_xxe_probe_blocks_xml_endpoint_outside_scope(xxe_fixture_server: str) -> None:
    endpoint = f"{xxe_fixture_server}/app/xml"
    outside = f"{xxe_fixture_server}/admin/xml"
    with pytest.raises(ValueError, match="XML endpoint outside scope"):
        execute_xxe_probe(
            [endpoint],
            scope_allowlist={"urls": [f"{xxe_fixture_server}/app/"]},
            xml_endpoints=[{"url": outside, "content_type": "application/xml"}],
        )


@pytest.fixture
def jwt_fixture_server() -> str:
    captured_token = _test_jwt({"sub": "2", "role": "user", "admin": False})

    class Handler(BaseHTTPRequestHandler):
        def _read_token(self) -> str:
            auth_header = self.headers.get("Authorization", "")
            if auth_header.startswith("Bearer "):
                return auth_header.removeprefix("Bearer ").strip()
            return ""

        def do_GET(self) -> None:  # noqa: N802
            if self.path == "/app/":
                payload = (
                    "<html><script src=\"/app/app.js\"></script>"
                    f"<body data-token=\"{captured_token}\">ok</body></html>"
                ).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)
                return
            if self.path == "/app/app.js":
                payload = f"window.jwt='{captured_token}';".encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/javascript")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)
                return
            if self.path == "/app/none":
                token = self._read_token()
                parts = token.split(".")
                header = json.loads(base64.urlsafe_b64decode(parts[0] + "==").decode()) if len(parts) == 3 else {}
                if header.get("alg") == "none" and len(parts) == 3 and parts[2] == "":
                    payload = b"jwt-accepted-none"
                else:
                    payload = b"jwt-rejected"
                self.send_response(200)
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)
                return
            if self.path == "/app/admin":
                token = self._read_token()
                parts = token.split(".")
                payload = json.loads(base64.urlsafe_b64decode(parts[1] + "==").decode())
                if payload.get("role") == "admin" or payload.get("admin") is True:
                    body = b"admin-panel-ready"
                else:
                    body = b"not-admin"
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return
            self.send_response(404)
            self.end_headers()

        def log_message(self, format: str, *args: Any) -> None:  # noqa: A003
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = server.server_address
    try:
        yield f"http://{host}:{port}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def test_jwt_probe_detects_weak_secret_none_and_claims_against_local_fixture(
    jwt_fixture_server: str,
) -> None:
    execution = execute_jwt_probe(
        [f"{jwt_fixture_server}/app/"],
        scope_allowlist={"urls": [f"{jwt_fixture_server}/app/"]},
        replay_contexts=[
            {
                "url": f"{jwt_fixture_server}/app/none",
                "method": "GET",
                "placement": "authorization_bearer",
                "success_markers": ["jwt-accepted-none"],
            },
            {
                "url": f"{jwt_fixture_server}/app/admin",
                "method": "GET",
                "placement": "authorization_bearer",
                "success_markers": ["admin-panel-ready"],
            },
        ],
    )

    assert execution.tool == "jwt-probe"
    assert execution.exit_code == 0
    assert execution.artifacts[0].name == JWT_RESULTS_ARTIFACT_NAME
    payload = json.loads(execution.artifacts[0].data.decode("utf-8"))
    titles = {finding["title"] for finding in payload["findings"]}
    assert "JWT Weak Secret Cracked" in titles
    assert "JWT None Algorithm Accepted" in titles
    assert "JWT Claims Manipulation Possible" in titles
    assert payload["summary"]["token_count"] == 1
    assert payload["safety"]["raw_tokens_stored"] is False
    assert payload["safety"]["replay_requires_explicit_context"] is True


def test_jwt_probe_blocks_replay_endpoint_outside_scope(jwt_fixture_server: str) -> None:
    with pytest.raises(ValueError, match="JWT replay endpoint outside scope"):
        execute_jwt_probe(
            [f"{jwt_fixture_server}/app/"],
            scope_allowlist={"urls": [f"{jwt_fixture_server}/app/"]},
            replay_contexts=[
                {
                    "url": f"{jwt_fixture_server}/admin",
                    "success_markers": ["accepted"],
                }
            ],
        )


@pytest.fixture
def vulnerable_components_fixture_server() -> str:
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802
            path = self.path.split("?", 1)[0]
            if path == "/app/":
                payload = (
                    "<html><!-- Spring 4.3.18.RELEASE --><head>"
                    "<script src=\"/app/static/jquery.min.js?v=1.6.4\"></script>"
                    "</head><body>ok</body></html>"
                ).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.send_header("X-Powered-By", "Express/4.16.0")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)
                return
            if path == "/app/static/jquery.min.js":
                payload = b"/*! jQuery v1.6.4 */ window.$ = function(){};"
                self.send_response(200)
                self.send_header("Content-Type", "application/javascript")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)
                return
            if path == "/app/package.json":
                payload = json.dumps({"dependencies": {"jquery": "1.6.4"}}).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)
                return
            if path == "/app/pom.xml":
                payload = (
                    "<project><dependencies><dependency>"
                    "<artifactId>spring-web</artifactId><version>4.3.18.RELEASE</version>"
                    "</dependency></dependencies></project>"
                ).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/xml")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)
                return
            self.send_response(404)
            self.end_headers()

        def log_message(self, format: str, *args: Any) -> None:  # noqa: A003
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = server.server_address
    try:
        yield f"http://{host}:{port}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def test_vulnerable_components_scan_matches_local_cve_fixture(
    vulnerable_components_fixture_server: str,
) -> None:
    root = f"{vulnerable_components_fixture_server}/app/"
    execution = execute_vuln_components_scan(
        [root],
        scope_allowlist={"urls": [root]},
        local_cve_records=[
            {
                "source": "cve-cvss",
                "advisory_id": "CVE-2019-11358",
                "title": "jQuery prototype pollution",
                "summary": "jQuery before 3.4.0 has prototype pollution risk.",
                "affected_products": ["jquery"],
                "affected_versions": ["1.6.4"],
                "product_match_hints": ["jquery"],
                "severity": "high",
                "references": ["https://nvd.nist.gov/vuln/detail/CVE-2019-11358"],
            },
            {
                "source": "cve-cvss",
                "advisory_id": "CVE-2022-22965",
                "title": "Spring Framework RCE",
                "summary": "Spring Framework vulnerable versions include 4.3.18.RELEASE.",
                "affected_products": ["spring", "spring-web"],
                "affected_versions": ["4.3.18.RELEASE"],
                "product_match_hints": ["spring"],
                "severity": "critical",
                "references": ["https://nvd.nist.gov/vuln/detail/CVE-2022-22965"],
            },
        ],
    )

    assert execution.tool == "vuln-components"
    assert execution.exit_code == 0
    assert execution.artifacts[0].name == VULN_COMPONENTS_RESULTS_ARTIFACT_NAME
    payload = json.loads(execution.artifacts[0].data.decode("utf-8"))
    products = {(item["product"], item["version"]) for item in payload["components"]}
    assert ("jquery", "1.6.4") in products
    assert ("spring", "4.3.18.RELEASE") in products
    cve_ids = {
        cve_id
        for finding in payload["findings"]
        for cve_id in finding["evidence"]["cve_ids"]
    }
    assert {"CVE-2019-11358", "CVE-2022-22965"}.issubset(cve_ids)
    assert payload["methodology"]["cve_matching"] == "local-cache-only"
    assert payload["safety"]["read_only"] is True
    assert payload["safety"]["exploitation"] is False


def test_external_osint_requires_api_credentials() -> None:
    with pytest.raises(ValueError, match="requires SHODAN_API_KEY"):
        execute_external_osint_recon(
            ["example.com"],
            scope_allowlist={"domains": ["example.com"]},
        )


class _FakeResponse:
    status_code = 200

    def __init__(self, payload: dict[str, Any]) -> None:
        self._payload = payload

    def raise_for_status(self) -> None:
        return None

    def json(self) -> dict[str, Any]:
        return self._payload


class _FakeClient:
    def __init__(self, *args: Any, **kwargs: Any) -> None:
        pass

    def __enter__(self) -> "_FakeClient":
        return self

    def __exit__(self, *args: Any) -> None:
        return None

    def get(self, url: str, **kwargs: Any) -> _FakeResponse:
        assert "api.shodan.io" in url
        return _FakeResponse({"data": [{"port": 443, "product": "nginx"}], "vulns": {}})


def test_external_osint_passive_lookup_produces_structured_findings() -> None:
    execution = execute_external_osint_recon(
        ["example.com"],
        scope_allowlist={"domains": ["example.com"]},
        shodan_api_key="test-key",
        client_factory=_FakeClient,
    )

    assert execution.tool == "external-osint"
    assert execution.artifacts[0].name == EXTERNAL_OSINT_RESULTS_ARTIFACT_NAME
    payload = json.loads(execution.artifacts[0].data.decode("utf-8"))
    assert payload["findings"][0]["title"] == "Public Service Exposure"


def test_dispatch_sqlmap_guard_surfaces_before_execution() -> None:
    with pytest.raises(ValueError, match="explicit parameter target"):
        dispatch_runner(
            RunnerRequest(
                tool="sqlmap",
                targets=["https://example.com/app/"],
                scope_allowlist={"urls": ["https://example.com/app/"]},
            )
        )
