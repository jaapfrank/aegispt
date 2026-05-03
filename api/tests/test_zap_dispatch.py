from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread
from urllib.parse import parse_qs, urlparse

import pytest


@pytest.fixture
def fake_zap_server(monkeypatch: pytest.MonkeyPatch) -> str:
    expected_api_key = "test-zap-key"
    state = {"sessions": [], "scan_requests": [], "active_scan_requests": []}

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
                state["sessions"].append(params.get("name", [""])[0])
                self._send_json({"Result": "OK"})
                return
            if parsed.path == "/JSON/core/action/accessUrl/":
                self._send_json({"Result": "OK"})
                return
            if parsed.path == "/JSON/spider/action/scan/":
                state["scan_requests"].append(params.get("url", [""])[0])
                self._send_json({"scan": "1"})
                return
            if parsed.path == "/JSON/spider/view/status/":
                self._send_json({"status": "100"})
                return
            if parsed.path == "/JSON/ascan/action/scan/":
                state["active_scan_requests"].append(params.get("url", [""])[0])
                self._send_json({"scan": "2"})
                return
            if parsed.path == "/JSON/ascan/view/status/":
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


def test_inline_dispatch_executes_zap_task(
    inline_client,
    fake_zap_server: str,
) -> None:
    engagement_response = inline_client.post(
        "/api/v1/engagements",
        headers={"X-Actor": "tester"},
        json={
            "name": "Inline ZAP Validation",
            "client": "Acme Corp",
            "roe_ref": "ROE-2026-005",
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
        json={"profile_name": "active-web-safe"},
    )
    created_payload = run_response.json()

    approval_response = inline_client.post(
        f"/api/v1/runs/{created_payload['id']}/approvals",
        headers={"X-Actor": "approver-1"},
        json={"decision": "approved"},
    )
    approval_payload = approval_response.json()
    task_id = approval_payload["tasks"][0]["id"]

    dispatch_response = inline_client.post(
        f"/api/v1/runs/{created_payload['id']}/dispatch",
        headers={"X-Actor": "dispatcher"},
    )

    assert fake_zap_server.startswith("http://127.0.0.1:")
    assert dispatch_response.status_code == 200
    dispatch_payload = dispatch_response.json()
    assert dispatch_payload["dispatch_mode"] == "inline"
    assert dispatch_payload["run"]["status"] == "completed"
    assert dispatch_payload["run"]["started_at"] is not None
    assert dispatch_payload["run"]["tasks"][0]["tool"] == "zap"
    assert dispatch_payload["run"]["tasks"][0]["status"] == "completed"
    assert dispatch_payload["run"]["findings"]["finding_count"] == 1
    assert dispatch_payload["run"]["findings"]["findings_by_severity"] == {"low": 1}

    task_response = inline_client.get(f"/api/v1/tasks/{task_id}")

    assert task_response.status_code == 200
    task_payload = task_response.json()
    assert task_payload["status"] == "completed"
    assert task_payload["executions"][0]["tool_version"] == "2.16.1"
    assert task_payload["executions"][0]["exit_code"] == 0
    assert task_payload["executions"][0]["artifacts"][0]["metadata_json"]["name"] == "zap-results.json"

    findings_response = inline_client.get(f"/api/v1/runs/{created_payload['id']}/findings")
    findings_payload = findings_response.json()

    assert findings_response.status_code == 200
    assert len(findings_payload) == 1
    assert findings_payload[0]["title"] == "Missing X-Frame-Options Header"
    assert findings_payload[0]["severity"] == "low"
    assert findings_payload[0]["status"] == "open"
    assert findings_payload[0]["evidence_ref"] == task_payload["executions"][0]["artifacts"][0]["uri"]
    assert findings_payload[0]["ptes_phase"] == "exploitation"
    assert findings_payload[0]["nist_phase"] == "attack"
    assert findings_payload[0]["wstg_id"] == "WSTG-CLNT-09"
    assert findings_payload[0]["wstg_version"] == "v4.2"
    assert findings_payload[0]["control_family"] == "client_security"
    assert "owasp-wstg" in findings_payload[0]["methodology_tags"]


def test_findings_can_be_updated_and_reloaded(
    inline_client,
    fake_zap_server: str,
) -> None:
    engagement_response = inline_client.post(
        "/api/v1/engagements",
        headers={"X-Actor": "tester"},
        json={
            "name": "Finding Update Validation",
            "client": "Acme Corp",
            "roe_ref": "ROE-2026-007",
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

    findings_response = inline_client.get(f"/api/v1/runs/{run_id}/findings")
    finding_id = findings_response.json()[0]["id"]

    update_response = inline_client.patch(
        f"/api/v1/findings/{finding_id}",
        headers={"X-Actor": "analyst-1"},
        json={"status": "resolved"},
    )

    assert fake_zap_server.startswith("http://127.0.0.1:")
    assert update_response.status_code == 200
    assert update_response.json()["status"] == "resolved"


def test_active_web_safe_collapses_duplicate_targets_and_completes(
    inline_client,
    fake_zap_server: str,
) -> None:
    engagement_response = inline_client.post(
        "/api/v1/engagements",
        headers={"X-Actor": "tester"},
        json={
            "name": "Duplicate Target Validation",
            "client": "Acme Corp",
            "roe_ref": "ROE-2026-009",
        },
    )
    engagement_id = engagement_response.json()["id"]

    inline_client.post(
        f"/api/v1/engagements/{engagement_id}/scope",
        headers={"X-Actor": "tester"},
        json={
            "allowlist_json": {
                "domains": ["example.com"],
                "urls": ["https://example.com"],
            },
            "denylist_json": {},
        },
    )

    run_response = inline_client.post(
        f"/api/v1/engagements/{engagement_id}/runs",
        headers={"X-Actor": "tester"},
        json={"profile_name": "active-web-safe"},
    )
    run_id = run_response.json()["id"]

    approval_response = inline_client.post(
        f"/api/v1/runs/{run_id}/approvals",
        headers={"X-Actor": "approver-1"},
        json={"decision": "approved"},
    )
    approval_payload = approval_response.json()

    assert len(approval_payload["tasks"]) == 1
    assert approval_payload["tasks"][0]["params_json"]["targets"] == ["https://example.com"]

    dispatch_response = inline_client.post(
        f"/api/v1/runs/{run_id}/dispatch",
        headers={"X-Actor": "dispatcher"},
    )

    assert fake_zap_server.startswith("http://127.0.0.1:")
    assert dispatch_response.status_code == 200
    dispatch_payload = dispatch_response.json()
    assert dispatch_payload["run"]["status"] == "completed"
    assert dispatch_payload["run"]["findings"]["finding_count"] == 1


def test_inline_dispatch_executes_active_zap_profile(
    inline_client,
    fake_zap_server: str,
) -> None:
    engagement_response = inline_client.post(
        "/api/v1/engagements",
        headers={"X-Actor": "tester"},
        json={
            "name": "Inline Active ZAP Validation",
            "client": "Acme Corp",
            "roe_ref": "ROE-2026-011",
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
        json={"profile_name": "active-web-zap-active"},
    )
    run_id = run_response.json()["id"]

    inline_client.post(
        f"/api/v1/runs/{run_id}/approvals",
        headers={"X-Actor": "approver-1"},
        json={"decision": "approved"},
    )

    dispatch_response = inline_client.post(
        f"/api/v1/runs/{run_id}/dispatch",
        headers={"X-Actor": "dispatcher"},
    )

    assert fake_zap_server.startswith("http://127.0.0.1:")
    assert dispatch_response.status_code == 200
    dispatch_payload = dispatch_response.json()
    task_id = dispatch_payload["run"]["tasks"][0]["id"]
    assert dispatch_payload["run"]["status"] == "completed"
    assert dispatch_payload["run"]["tasks"][0]["status"] == "completed"

    task_response = inline_client.get(f"/api/v1/tasks/{task_id}")
    execution_payload = task_response.json()["executions"][0]

    assert '"scan_mode": "spider-active-passive"' in (execution_payload["stdout_text"] or "")
