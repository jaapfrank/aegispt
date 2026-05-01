from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread

import pytest

from api.app.config import get_settings


@pytest.fixture
def fake_burp_server(monkeypatch: pytest.MonkeyPatch) -> str:
    expected_api_key = "test-burp-key"
    state = {"scan_requests": []}

    class BurpHandler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802
            if self.path == f"/api/{expected_api_key}/version":
                self._send_json({"version": "Burp Suite DAST 2026.4"})
                return
            if self.path == f"/api/{expected_api_key}/scan/scan-1":
                self._send_json({"scan_id": "scan-1", "status": "succeeded"})
                return
            if self.path == f"/api/{expected_api_key}/scan/scan-1/issues":
                self._send_json(
                    {
                        "issues": [
                            {
                                "name": "Cross-site scripting (reflected)",
                                "severity": "low",
                                "url": "https://example.com/search?q=test",
                                "description": "Burp observed reflected script execution in a query parameter.",
                            }
                        ]
                    }
                )
                return
            self._send_json({"error": self.path}, status_code=404)

        def do_POST(self) -> None:  # noqa: N802
            if self.path == f"/api/{expected_api_key}/scan":
                content_length = int(self.headers.get("Content-Length", "0"))
                payload = json.loads(self.rfile.read(content_length).decode("utf-8"))
                state["scan_requests"].append(payload)
                self._send_json({"scan_id": "scan-1", "status": "queued"})
                return
            self._send_json({"error": self.path}, status_code=404)

        def log_message(self, format: str, *args) -> None:  # noqa: A003
            return

        def _send_json(self, payload: dict[str, object], status_code: int = 200) -> None:
            body = (json.dumps(payload) + "\n").encode("utf-8")
            self.send_response(status_code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    server = ThreadingHTTPServer(("127.0.0.1", 0), BurpHandler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = server.server_address
    base_url = f"http://{host}:{port}"
    monkeypatch.setenv("BURP_API_URL", base_url)
    monkeypatch.setenv("BURP_API_KEY", expected_api_key)
    get_settings.cache_clear()

    try:
        yield base_url
    finally:
        get_settings.cache_clear()
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def test_inline_dispatch_executes_burp_task(
    inline_client,
    fake_burp_server: str,
) -> None:
    engagement_response = inline_client.post(
        "/api/v1/engagements",
        headers={"X-Actor": "tester"},
        json={
            "name": "Inline Burp Validation",
            "client": "Acme Corp",
            "roe_ref": "ROE-2026-BURP",
        },
    )
    engagement_id = engagement_response.json()["id"]

    inline_client.post(
        f"/api/v1/engagements/{engagement_id}/scope",
        headers={"X-Actor": "tester"},
        json={
            "allowlist_json": {
                "urls": ["https://example.com"],
            },
            "denylist_json": {},
        },
    )

    run_response = inline_client.post(
        f"/api/v1/engagements/{engagement_id}/runs",
        headers={"X-Actor": "tester"},
        json={"profile_name": "passive-web-burp"},
    )
    created_payload = run_response.json()
    task_id = created_payload["tasks"][0]["id"]

    dispatch_response = inline_client.post(
        f"/api/v1/runs/{created_payload['id']}/dispatch",
        headers={"X-Actor": "dispatcher"},
    )

    assert fake_burp_server.startswith("http://127.0.0.1:")
    assert dispatch_response.status_code == 200
    dispatch_payload = dispatch_response.json()
    assert dispatch_payload["dispatch_mode"] == "inline"
    assert dispatch_payload["run"]["status"] == "completed"
    assert dispatch_payload["run"]["tasks"][0]["tool"] == "burp"
    assert dispatch_payload["run"]["tasks"][0]["status"] == "completed"
    assert dispatch_payload["run"]["findings"]["finding_count"] == 1
    assert dispatch_payload["run"]["findings"]["findings_by_severity"] == {"low": 1}

    task_response = inline_client.get(f"/api/v1/tasks/{task_id}")

    assert task_response.status_code == 200
    task_payload = task_response.json()
    assert task_payload["status"] == "completed"
    assert task_payload["executions"][0]["tool_version"] == "Burp Suite DAST 2026.4"
    assert task_payload["executions"][0]["exit_code"] == 0
    assert task_payload["executions"][0]["artifacts"][0]["metadata_json"]["name"] == "burp-results.json"

    findings_response = inline_client.get(f"/api/v1/runs/{created_payload['id']}/findings")
    findings_payload = findings_response.json()

    assert findings_response.status_code == 200
    assert len(findings_payload) == 1
    assert findings_payload[0]["title"] == "Cross-site scripting (reflected)"
    assert findings_payload[0]["severity"] == "low"
    assert findings_payload[0]["status"] == "open"
    assert findings_payload[0]["evidence_ref"] == task_payload["executions"][0]["artifacts"][0]["uri"]
    assert findings_payload[0]["wstg_id"] == "WSTG-INPV-01"
    assert findings_payload[0]["wstg_version"] == "v4.2"
    assert "owasp-wstg" in findings_payload[0]["methodology_tags"]


def test_inline_dispatch_marks_burp_runner_unavailable_when_not_configured(
    inline_client,
) -> None:
    engagement_response = inline_client.post(
        "/api/v1/engagements",
        headers={"X-Actor": "tester"},
        json={
            "name": "Inline Burp Unavailable",
            "client": "Acme Corp",
            "roe_ref": "ROE-2026-BURP-UNAVAILABLE",
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
        json={"profile_name": "passive-web-burp"},
    )
    run_id = run_response.json()["id"]
    task_id = run_response.json()["tasks"][0]["id"]

    dispatch_response = inline_client.post(
        f"/api/v1/runs/{run_id}/dispatch",
        headers={"X-Actor": "dispatcher"},
    )

    assert dispatch_response.status_code == 200
    dispatch_payload = dispatch_response.json()
    assert dispatch_payload["run"]["status"] == "completed_with_errors"
    assert dispatch_payload["run"]["tasks"][0]["status"] == "failed"

    task_response = inline_client.get(f"/api/v1/tasks/{task_id}")
    task_payload = task_response.json()

    assert task_response.status_code == 200
    assert task_payload["status"] == "failed"
    assert task_payload["executions"][0]["stderr_text"] == "BURP_API_URL is not configured"
