from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread
from urllib.parse import parse_qs, urlparse

import pytest


@pytest.fixture
def fake_zap_server(monkeypatch: pytest.MonkeyPatch) -> str:
    expected_api_key = "test-zap-key"

    class ZapHandler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802
            parsed = urlparse(self.path)
            params = parse_qs(parsed.query)
            api_key = params.get("apikey", [""])[0]

            if api_key != expected_api_key:
                self._send_json({"error": "forbidden"}, status_code=403)
                return

            if parsed.path == "/JSON/core/view/version/":
                self._send_json({"version": "2.16.1"})
                return
            if parsed.path == "/JSON/core/action/newSession/":
                self._send_json({"Result": "OK"})
                return
            if parsed.path == "/JSON/core/action/accessUrl/":
                self._send_json({"Result": "OK"})
                return
            if parsed.path == "/JSON/spider/action/scan/":
                self._send_json({"scan": "1"})
                return
            if parsed.path == "/JSON/spider/view/status/":
                self._send_json({"status": "100"})
                return
            if parsed.path == "/JSON/pscan/view/recordsToScan/":
                self._send_json({"recordsToScan": "0"})
                return
            if parsed.path == "/JSON/core/view/urls/":
                baseurl = params.get("baseurl", [""])[0]
                self._send_json({"urls": [baseurl, f"{baseurl}/login"]})
                return
            if parsed.path == "/JSON/core/view/alerts/":
                baseurl = params.get("baseurl", [""])[0]
                self._send_json(
                    {
                        "alerts": [
                            {
                                "alert": "Missing X-Frame-Options Header",
                                "risk": "Low",
                                "url": baseurl,
                            }
                        ]
                    }
                )
                return

            self._send_json({"error": parsed.path}, status_code=404)

        def log_message(self, format: str, *args) -> None:  # noqa: A003
            return

        def _send_json(self, payload: dict[str, object], status_code: int = 200) -> None:
            body = (json.dumps(payload) + "\n").encode("utf-8")
            self.send_response(status_code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    server = ThreadingHTTPServer(("127.0.0.1", 0), ZapHandler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = server.server_address
    base_url = f"http://{host}:{port}"

    monkeypatch.setenv("ZAP_BASE_URL", base_url)
    monkeypatch.setenv("ZAP_API_KEY", expected_api_key)

    try:
        yield base_url
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def test_run_report_exports_markdown_and_html(
    inline_client,
    fake_zap_server: str,
) -> None:
    engagement_response = inline_client.post(
        "/api/v1/engagements",
        headers={"X-Actor": "tester"},
        json={
            "name": "Report Validation",
            "client": "Acme Corp",
            "roe_ref": "ROE-2026-008",
        },
    )
    engagement_id = engagement_response.json()["id"]

    inline_client.post(
        f"/api/v1/engagements/{engagement_id}/scope",
        headers={"X-Actor": "tester"},
        json={"allowlist_json": {"urls": ["https://example.com"]}, "denylist_json": {}},
    )

    run_response = inline_client.post(
        f"/api/v1/engagements/{engagement_id}/runs",
        headers={"X-Actor": "tester"},
        json={"profile_name": "active-web-safe"},
    )
    run_id = run_response.json()["id"]

    inline_client.post(
        f"/api/v1/runs/{run_id}/approvals",
        headers={"X-Actor": "approver-1"},
        json={"decision": "approved"},
    )
    inline_client.post(
        f"/api/v1/runs/{run_id}/dispatch",
        headers={"X-Actor": "dispatcher"},
    )

    markdown_response = inline_client.get(f"/api/v1/runs/{run_id}/report?format=markdown")
    html_response = inline_client.get(f"/api/v1/runs/{run_id}/report?format=html")

    assert fake_zap_server.startswith("http://127.0.0.1:")
    assert markdown_response.status_code == 200
    assert markdown_response.headers["content-type"].startswith("text/markdown")
    assert "# AegisPT Run Report:" in markdown_response.text
    assert "## Methodology" in markdown_response.text
    assert "## Scope" in markdown_response.text
    assert "## Confirmed Findings" in markdown_response.text
    assert "WSTG-CLNT-09" in markdown_response.text
    assert "PTES Phase: Exploitation" in markdown_response.text
    assert "Missing X-Frame-Options Header" in markdown_response.text
    assert "/api/v1/artifacts/" in markdown_response.text

    assert html_response.status_code == 200
    assert html_response.headers["content-type"].startswith("text/html")
    assert "<h1>AegisPT Run Report</h1>" in html_response.text
    assert "Methodology Summary" in html_response.text
    assert "Coverage Summary" in html_response.text
    assert "Confirmed Findings" in html_response.text
    assert "WSTG-CLNT-09" in html_response.text
    assert "Missing X-Frame-Options Header" in html_response.text
    assert "/api/v1/artifacts/" in html_response.text
