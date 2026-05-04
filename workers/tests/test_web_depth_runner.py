from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any

import pytest

from workers.orchestration.tasks import SUPPORTED_TOOLS, dispatch_runner
from workers.runners.base.contracts import RunnerRequest
from workers.runners.web_depth.runner import (
    CONTENT_DISCOVERY_RESULTS_ARTIFACT_NAME,
    EXTERNAL_OSINT_RESULTS_ARTIFACT_NAME,
    NIKTO_RESULTS_ARTIFACT_NAME,
    SQLMAP_RESULTS_ARTIFACT_NAME,
    execute_content_discovery,
    execute_external_osint_recon,
    execute_nikto_scan,
    execute_sqlmap_confirmation,
)


def test_web_depth_tools_are_supported() -> None:
    assert {"content-discovery", "nikto", "sqlmap", "external-osint"}.issubset(SUPPORTED_TOOLS)


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
