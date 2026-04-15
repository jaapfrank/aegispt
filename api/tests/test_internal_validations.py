from __future__ import annotations

import json
from pathlib import Path
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread
from urllib.parse import parse_qs, urlparse

import pytest


@pytest.fixture
def internal_validation_semgrep_target_dir(tmp_path: Path) -> str:
    target_dir = tmp_path / "internal-validation-repo"
    target_dir.mkdir()
    (target_dir / "app.py").write_text(
        'password = "super-secret-token"\nprint(password)\n',
        encoding="utf-8",
    )
    return str(target_dir)


@pytest.fixture
def fake_semgrep_binary(tmp_path: Path) -> str:
    binary_path = tmp_path / "fake-semgrep"
    binary_path.write_text(
        """#!/usr/bin/env python3
import json
import sys
from pathlib import Path

args = sys.argv[1:]
if "--version" in args:
    print("semgrep 1.test")
    raise SystemExit(0)

output_path = Path(args[args.index("--output") + 1])
target_path = Path(args[-1])
target_file = target_path / "app.py"
payload = {
    "version": "1.test",
    "results": [
        {
            "check_id": "tmp.aegispt-semgrep-rule.aegispt.python.hardcoded-secret",
            "path": str(target_file),
            "start": {"line": 1, "col": 1},
            "end": {"line": 1, "col": 31},
            "extra": {
                "message": "Hardcoded secret assignment",
                "severity": "ERROR",
                "lines": "password = \\"super-secret-token\\"",
            },
        }
    ],
    "errors": [],
    "paths": {"scanned": [str(target_path)], "skipped": []},
}
output_path.write_text(json.dumps(payload), encoding="utf-8")
""",
        encoding="utf-8",
    )
    binary_path.chmod(0o755)
    return str(binary_path)


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
            if parsed.path == "/JSON/ascan/action/scan/":
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


def test_internal_validation_code_scenario_executes_step_and_links_run(
    inline_client,
    monkeypatch: pytest.MonkeyPatch,
    internal_validation_semgrep_target_dir: str,
    fake_semgrep_binary: str,
) -> None:
    monkeypatch.setenv("SEMGREP_BINARY", fake_semgrep_binary)

    engagement_response = inline_client.post(
        "/api/v1/engagements",
        headers={"X-Actor": "tester"},
        json={
            "name": "Internal Code Validation",
            "client": "Acme Corp",
            "roe_ref": "ROE-2026-021",
        },
    )
    engagement_id = engagement_response.json()["id"]

    inline_client.post(
        f"/api/v1/engagements/{engagement_id}/scope",
        headers={"X-Actor": "tester"},
        json={"allowlist_json": {"paths": [internal_validation_semgrep_target_dir]}, "denylist_json": {}},
    )

    create_response = inline_client.post(
        f"/api/v1/engagements/{engagement_id}/internal-validations",
        headers={"X-Actor": "operator"},
        json={"scenario_id": "curated-code-validation"},
    )

    assert create_response.status_code == 201
    session_payload = create_response.json()
    assert session_payload["preflight_state"] == "passed"
    assert session_payload["status"] == "pending_approval"
    assert session_payload["steps"][0]["status"] == "pending_approval"

    approval_response = inline_client.post(
        f"/api/v1/internal-validations/{session_payload['id']}/steps/semgrep-baseline/approvals",
        headers={"X-Actor": "approver-1"},
        json={"decision": "approved"},
    )

    assert approval_response.status_code == 200
    assert approval_response.json()["steps"][0]["status"] == "ready"

    execute_response = inline_client.post(
        f"/api/v1/internal-validations/{session_payload['id']}/steps/semgrep-baseline/execute",
        headers={"X-Actor": "operator"},
    )

    assert execute_response.status_code == 200
    execute_payload = execute_response.json()
    launched_run_id = execute_payload["launched_run_id"]
    assert execute_payload["dispatch_mode"] == "inline"
    assert execute_payload["session"]["status"] == "completed"
    assert execute_payload["session"]["steps"][0]["status"] == "completed"
    assert execute_payload["session"]["steps"][0]["launched_run_id"] == launched_run_id
    assert execute_payload["session"]["steps"][0]["launched_run_status"] == "completed"
    assert len(execute_payload["session"]["steps"][0]["approvals"]) == 1

    run_response = inline_client.get(f"/api/v1/runs/{launched_run_id}")
    run_payload = run_response.json()

    assert run_response.status_code == 200
    assert run_payload["status"] == "completed"
    assert run_payload["findings"]["finding_count"] == 1

    task_id = run_payload["tasks"][0]["id"]
    task_response = inline_client.get(f"/api/v1/tasks/{task_id}")
    task_payload = task_response.json()

    assert task_response.status_code == 200
    assert task_payload["executions"][0]["artifacts"][0]["metadata_json"]["name"] == "semgrep-results.json"


def test_internal_validation_web_scenario_advances_step_by_step(
    inline_client,
    probe_server: str,
    fake_zap_server: str,
) -> None:
    engagement_response = inline_client.post(
        "/api/v1/engagements",
        headers={"X-Actor": "tester"},
        json={
            "name": "Internal Web Validation",
            "client": "Acme Corp",
            "roe_ref": "ROE-2026-022",
        },
    )
    engagement_id = engagement_response.json()["id"]

    inline_client.post(
        f"/api/v1/engagements/{engagement_id}/scope",
        headers={"X-Actor": "tester"},
        json={"allowlist_json": {"urls": [probe_server]}, "denylist_json": {}},
    )

    create_response = inline_client.post(
        f"/api/v1/engagements/{engagement_id}/internal-validations",
        headers={"X-Actor": "operator"},
        json={"scenario_id": "curated-web-validation"},
    )

    assert fake_zap_server.startswith("http://127.0.0.1:")
    assert create_response.status_code == 201
    session_payload = create_response.json()
    assert session_payload["preflight_state"] == "passed"
    assert [step["status"] for step in session_payload["steps"]] == [
        "pending_approval",
        "pending_prerequisite",
        "pending_prerequisite",
    ]

    early_execute_response = inline_client.post(
        f"/api/v1/internal-validations/{session_payload['id']}/steps/zap-passive-review/execute",
        headers={"X-Actor": "operator"},
    )

    assert early_execute_response.status_code == 409

    inline_client.post(
        f"/api/v1/internal-validations/{session_payload['id']}/steps/baseline-httpx/approvals",
        headers={"X-Actor": "approver-1"},
        json={"decision": "approved"},
    )
    first_execute_response = inline_client.post(
        f"/api/v1/internal-validations/{session_payload['id']}/steps/baseline-httpx/execute",
        headers={"X-Actor": "operator"},
    )

    assert first_execute_response.status_code == 200
    first_session_payload = first_execute_response.json()["session"]
    assert first_session_payload["steps"][0]["status"] == "completed"
    assert first_session_payload["steps"][1]["status"] == "pending_approval"
    assert first_session_payload["steps"][2]["status"] == "pending_prerequisite"

    inline_client.post(
        f"/api/v1/internal-validations/{session_payload['id']}/steps/zap-passive-review/approvals",
        headers={"X-Actor": "approver-2"},
        json={"decision": "approved"},
    )
    second_execute_response = inline_client.post(
        f"/api/v1/internal-validations/{session_payload['id']}/steps/zap-passive-review/execute",
        headers={"X-Actor": "operator"},
    )

    assert second_execute_response.status_code == 200
    second_session_payload = second_execute_response.json()["session"]
    assert second_session_payload["steps"][1]["status"] == "completed"
    assert second_session_payload["steps"][2]["status"] == "pending_approval"

    rejection_response = inline_client.post(
        f"/api/v1/internal-validations/{session_payload['id']}/steps/zap-active-validation/approvals",
        headers={"X-Actor": "approver-3"},
        json={"decision": "rejected"},
    )

    assert rejection_response.status_code == 200
    rejected_payload = rejection_response.json()
    assert rejected_payload["status"] == "rejected"
    assert rejected_payload["steps"][2]["status"] == "rejected"
