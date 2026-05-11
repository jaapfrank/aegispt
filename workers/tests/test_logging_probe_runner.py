from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread
from types import SimpleNamespace
from urllib.parse import parse_qs, urlparse

import pytest

from workers.orchestration.findings import extract_standard_json_findings
from workers.orchestration.tasks import SUPPORTED_TOOLS, dispatch_runner
from workers.runners.base.contracts import RunnerRequest
from workers.runners.logging_probe.runner import (
    LOGGING_PROBE_RESULTS_ARTIFACT_NAME,
    execute_logging_probe,
)


class _LoggingFixtureHandler(BaseHTTPRequestHandler):
    def log_message(self, *_: object) -> None:
        return

    def _send(self, status: int, body: str, *, content_type: str = "text/plain") -> None:
        data = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        query = parse_qs(parsed.query, keep_blank_values=True)
        if "aegispt_error_probe" in query:
            self._send(
                500,
                "Traceback (most recent call last): File \"/var/www/app.py\", line 10, "
                "in handler sqlite3.OperationalError: near \"aegispt\": SQL syntax error "
                "backend=10.10.1.7",
            )
            return
        if "aegispt_log_probe" in query:
            self._send(200, f"reflected={query['aegispt_log_probe'][0]}")
            return
        if parsed.path == "/actuator/env":
            self._send(
                200,
                json.dumps({"propertySources": [{"name": "systemProperties"}]}),
                content_type="application/json",
            )
            return
        if parsed.path == "/debug/vars":
            self._send(200, json.dumps({"cmdline": ["app"], "memstats": {}}), content_type="application/json")
            return
        if parsed.path == "/.env":
            self._send(200, "DB_PASSWORD=super-secret\nJWT_SECRET=also-secret\n")
            return
        if parsed.path == "/admin":
            self._send(200, "<html><title>Admin console</title><body>admin dashboard login</body></html>", content_type="text/html")
            return
        self._send(404, "missing")

    def do_POST(self) -> None:
        _ = self.rfile.read(int(self.headers.get("Content-Length") or "0"))
        self._send(
            500,
            "java.lang.IllegalArgumentException: invalid JSON\n"
            "at com.example.LoggingController.parse(LoggingController.java:42)\n"
            "/usr/src/app/config.yml",
        )


@pytest.fixture
def logging_fixture_url() -> str:
    server = ThreadingHTTPServer(("127.0.0.1", 0), _LoggingFixtureHandler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}/"
    finally:
        server.shutdown()
        thread.join(timeout=2)
        server.server_close()


def _artifact_payload(execution) -> dict:
    artifact = next(item for item in execution.artifacts if item.name == LOGGING_PROBE_RESULTS_ARTIFACT_NAME)
    return json.loads(artifact.data.decode("utf-8"))


def test_logging_probe_detects_error_leakage_exposed_paths_and_safe_log_markers(logging_fixture_url: str) -> None:
    execution = execute_logging_probe(
        [logging_fixture_url],
        scope_allowlist={"urls": [logging_fixture_url]},
        timeout_seconds=5,
    )

    assert execution.tool == "logging-probe"
    assert execution.exit_code == 0
    payload = _artifact_payload(execution)
    titles = {finding["title"] for finding in payload["findings"]}
    assert "Error Information Disclosure - Stack Trace/Internal Path Exposed" in titles
    assert "Spring Actuator Endpoint Exposed" in titles
    assert "Debug Configuration File Exposed" in titles
    assert "Exposed Debug Endpoint" in titles
    assert "Exposed Admin or Management Endpoint" in titles
    assert "Log Injection Possible" in titles
    assert "Log4Shell-Style Injection Pattern Accepted" in titles
    assert payload["safety"]["jndi_exploitation_attempted"] is False
    assert payload["safety"]["callback_chain_attempted"] is False
    assert payload["safety"]["admin_panel_login_attempted"] is False
    assert "super-secret" not in json.dumps(payload)
    probe_types = {
        check.get("probe_type")
        for check in payload["checks"]
        if check.get("check_type") == "log_injection_reflection_probe"
    }
    assert {"crlf", "format-string", "log4shell-pattern"}.issubset(probe_types)


def test_logging_probe_scope_rejects_out_of_scope_target(logging_fixture_url: str) -> None:
    with pytest.raises(ValueError, match="outside approved logging probe"):
        execute_logging_probe(
            [logging_fixture_url],
            scope_allowlist={"urls": ["https://example.test/"]},
        )


def test_logging_probe_dispatch_and_standard_finding_extraction(logging_fixture_url: str) -> None:
    assert "logging-probe" in SUPPORTED_TOOLS

    execution = dispatch_runner(
        RunnerRequest(
            tool="logging-probe",
            targets=[logging_fixture_url],
            params={"timeout_seconds": 5},
            scope_allowlist={"urls": [logging_fixture_url]},
        )
    )
    artifact = next(item for item in execution.artifacts if item.name == LOGGING_PROBE_RESULTS_ARTIFACT_NAME)

    findings = extract_standard_json_findings(
        target_id=logging_fixture_url,
        artifact=artifact,
        artifact_record=SimpleNamespace(uri="artifact://logging-probe/results"),
        accepted_artifact_names={LOGGING_PROBE_RESULTS_ARTIFACT_NAME},
        default_title="logging-probe finding",
    )

    assert findings
    assert any(finding.title == "Spring Actuator Endpoint Exposed" for finding in findings)
    assert all("logging-probe-validation" in finding.methodology_tags for finding in findings)
