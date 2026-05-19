from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread

import pytest

from workers.orchestration.findings import extract_findings
from workers.runners.base.contracts import EvidenceArtifact
from workers.runners.burp.runner import BURP_RESULTS_ARTIFACT_NAME, execute_burp_scan


class ArtifactRecord:
    uri = "artifact://burp/results"


@pytest.fixture
def fake_burp_server() -> str:
    state = {"scan_requests": []}

    class BurpHandler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802
            if self.path == "/api/test-burp-key/version":
                self._send_json({"version": "Burp Suite DAST 2026.4"})
                return
            if self.path == "/api/test-burp-key/scan/scan-1":
                self._send_json({"scan_id": "scan-1", "status": "succeeded"})
                return
            if self.path == "/api/test-burp-key/scan/scan-1/issues":
                self._send_json(
                    {
                        "issues": [
                            {
                                "name": "Cross-site scripting (reflected)",
                                "severity": "low",
                                "url": "https://example.test/search?q=test",
                                "description": "Burp observed reflected script execution in a query parameter.",
                            }
                        ]
                    }
                )
                return
            self._send_json({"error": self.path}, status_code=404)

        def do_POST(self) -> None:  # noqa: N802
            if self.path == "/api/test-burp-key/scan":
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

    try:
        yield f"http://{host}:{port}", state
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def test_burp_runner_skips_gracefully_when_unconfigured() -> None:
    result = execute_burp_scan(
        ["https://example.test"],
        base_url="",
        api_key=None,
        scope_allowlist={"urls": ["https://example.test"]},
    )
    assert result.exit_code == 0
    assert result.metadata.get("skipped") is True


def test_burp_runner_executes_scan_and_normalizes_findings(fake_burp_server) -> None:
    base_url, state = fake_burp_server

    execution = execute_burp_scan(
        ["https://example.test"],
        base_url=base_url,
        api_key="test-burp-key",
        named_scan_configurations=["Audit checks - light"],
        scope_allowlist={"urls": ["https://example.test"]},
    )

    assert execution.tool == "burp"
    assert execution.exit_code == 0
    assert execution.metadata["issue_count"] == 1
    assert execution.metadata["tool_version"] == "Burp Suite DAST 2026.4"
    assert state["scan_requests"] == [
        {
            "urls": ["https://example.test"],
            "named_scan_configurations": ["Audit checks - light"],
        }
    ]

    task = type(
        "TaskStub",
        (),
        {
            "tool": "burp",
            "target_id": "https://example.test",
            "params_json": {"run_class": "passive"},
        },
    )()
    findings = extract_findings(
        task=task,
        artifact=EvidenceArtifact(
            name=BURP_RESULTS_ARTIFACT_NAME,
            content_type="application/json",
            data=execution.artifacts[0].data,
            kind="scan-results",
        ),
        artifact_record=ArtifactRecord(),
    )

    assert len(findings) == 1
    assert findings[0].title == "Cross-site scripting (reflected)"
    assert findings[0].severity == "low"
    assert findings[0].evidence_ref == ArtifactRecord.uri


def test_burp_runner_rejects_targets_outside_scope(fake_burp_server) -> None:
    base_url, _state = fake_burp_server

    with pytest.raises(ValueError, match="target outside scope"):
        execute_burp_scan(
            ["https://outside.example.test"],
            base_url=base_url,
            api_key="test-burp-key",
            scope_allowlist={"urls": ["https://example.test"]},
        )
