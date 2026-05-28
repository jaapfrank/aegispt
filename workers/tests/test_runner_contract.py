from __future__ import annotations

import json
from pathlib import Path

from workers.orchestration.tasks import _runner_command_preview
from workers.runners.base.contracts import EvidenceArtifact
from workers.runners.burp.runner import build_burp_api_url
from workers.runners.httpx.runner import build_httpx_command, execute_httpx_probe
from workers.runners.nmap.runner import (
    ACTIVE_DEFAULT_CREDENTIAL_NSE_SCRIPTS,
    IOT_NSE_DISCOVERY_SCRIPTS,
    PASSIVE_LAN_NSE_DISCOVERY_SCRIPTS,
    build_nmap_command,
    execute_nmap_scan,
)
from workers.runners.nuclei.runner import build_nuclei_command
from workers.runners.responder.runner import build_responder_command
from workers.runners.semgrep.runner import (
    _semgrep_env,
    build_semgrep_command,
    normalize_semgrep_rule_id,
)
from workers.runners.zap.runner import build_zap_api_url


def test_evidence_artifact_hash_is_stable() -> None:
    artifact = EvidenceArtifact(
        name="stdout.json",
        content_type="application/json",
        data=b'{"status":"ok"}',
    )

    assert artifact.digest == "a29ee2b15c494311c52521766e44af56a3ad2248e7a8ab465e5206463c13d288"


def test_httpx_command_is_structured() -> None:
    command = build_httpx_command(["https://example.com"], rate_limit=10)

    assert command == [
        "httpx-toolkit",
        "-silent",
        "-json",
        "-rl",
        "10",
        "-u",
        "https://example.com",
    ]


def test_httpx_probe_accepts_untrusted_internal_tls(monkeypatch) -> None:
    captured: dict[str, object] = {}

    class FakeResponse:
        status_code = 200
        reason_phrase = "OK"
        headers = {"content-type": "text/html"}
        content = b"<html>internal service</html>"

        def __init__(self, url: str) -> None:
            self.url = url

    class FakeClient:
        def __init__(self, **kwargs) -> None:
            captured.update(kwargs)

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb) -> None:
            return None

        def get(self, request_url: str) -> FakeResponse:
            return FakeResponse(request_url)

    monkeypatch.setattr("workers.runners.httpx.runner.httpx_client.Client", FakeClient)

    execution = execute_httpx_probe(["10.0.20.96"], timeout_seconds=3)

    assert captured["verify"] is False
    assert execution.exit_code == 0
    assert execution.metadata["verify_tls"] is False
    assert "10.0.20.96" in execution.stdout


def test_httpx_probe_records_passive_response_signals_without_extra_requests(monkeypatch) -> None:
    captured: dict[str, object] = {"requests": 0}

    class FakeHeaders(dict):
        def get_list(self, key: str) -> list[str]:
            value = self.get(key, "")
            return [value] if value else []

    class FakeResponse:
        status_code = 200
        reason_phrase = "OK"
        headers = FakeHeaders(
            {
                "content-type": "text/html",
                "server": "nginx",
                "x-powered-by": "PHP/8.2",
                "set-cookie": "PHPSESSID=abc; HttpOnly; Secure",
            }
        )
        content = (
            b"<html><form action='/login' method='post'>"
            b"<input name='user'>"
            b"<input name='password' type='password'>"
            b"</form><a href='/graphql'>GraphQL</a></html>"
        )

        def __init__(self, url: str) -> None:
            self.url = url

    class FakeClient:
        def __init__(self, **kwargs) -> None:
            captured.update(kwargs)

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb) -> None:
            return None

        def get(self, request_url: str) -> FakeResponse:
            captured["requests"] = int(captured["requests"]) + 1
            return FakeResponse(request_url)

    monkeypatch.setattr("workers.runners.httpx.runner.httpx_client.Client", FakeClient)

    execution = execute_httpx_probe(["https://app.example.test"], timeout_seconds=3)
    payload = json.loads(execution.stdout)["results"][0]

    assert captured["requests"] == 1
    assert payload["response_headers"]["server"] == "nginx"
    assert payload["cookies"][0]["name"] == "PHPSESSID"
    assert payload["forms"][0]["action"] == "https://app.example.test/login"
    assert payload["forms"][0]["inputs"][1]["type"] == "password"
    assert payload["links"] == ["https://app.example.test/graphql"]


def test_burp_api_url_is_structured() -> None:
    url = build_burp_api_url("http://burpd:1337/api/key/", "scan", "123", "issues")

    assert url == "http://burpd:1337/api/key/scan/123/issues"


def test_nuclei_command_is_structured(tmp_path: Path) -> None:
    command = build_nuclei_command(
        binary="nuclei",
        targets_file=tmp_path / "targets.txt",
        template_file=tmp_path / "template.yaml",
        output_file=tmp_path / "output.jsonl",
        rate_limit=2,
        timeout_seconds=15,
    )

    assert command == [
        "nuclei",
        "-duc",
        "-l",
        str(tmp_path / "targets.txt"),
        "-t",
        str(tmp_path / "template.yaml"),
        "-jsonl",
        "-jsonl-export",
        str(tmp_path / "output.jsonl"),
        "-rl",
        "2",
        "-timeout",
        "15",
        "-retries",
        "0",
        "-no-stdin",
        "-nc",
    ]


def test_nmap_command_is_structured(tmp_path: Path) -> None:
    command = build_nmap_command(
        binary="nmap",
        output_file=tmp_path / "nmap-results.xml",
        targets=["10.10.0.0/24", "10.10.1.15"],
        discovery_only=True,
    )

    assert command == [
        "nmap",
        "-n",
        "-oX",
        str(tmp_path / "nmap-results.xml"),
        "-sn",
        "10.10.0.0/24",
        "10.10.1.15",
    ]


def test_nmap_service_enumeration_command_is_structured(tmp_path: Path) -> None:
    command = build_nmap_command(
        binary="nmap",
        output_file=tmp_path / "nmap-results.xml",
        targets=["10.10.1.15"],
        discovery_only=False,
        service_detection=True,
        skip_discovery=True,
        top_ports=50,
    )

    assert command == [
        "nmap",
        "-n",
        "-oX",
        str(tmp_path / "nmap-results.xml"),
        "-Pn",
        "-sV",
        "--top-ports",
        "50",
        "10.10.1.15",
    ]


def test_nmap_nse_command_is_bounded_and_structured(tmp_path: Path) -> None:
    command = build_nmap_command(
        binary="nmap",
        output_file=tmp_path / "nmap-results.xml",
        targets=["10.0.20.8"],
        discovery_only=False,
        service_detection=True,
        skip_discovery=True,
        ports=["80", "443", "8123", "49152-49157"],
        scripts=[
            "http-title",
            "http-server-header",
            "ssl-cert",
            "rtsp-url-brute",
            "upnp-info",
        ],
        script_args={"rtsp-url-brute.paths": "/cam,/video,/live,/stream"},
        version_intensity=2,
        timing_template="T3",
        max_retries=1,
        host_timeout_seconds=45,
    )

    assert command == [
        "nmap",
        "-n",
        "-oX",
        str(tmp_path / "nmap-results.xml"),
        "-Pn",
        "-sV",
        "--version-intensity",
        "2",
        "-p",
        "80,443,8123,49152-49157",
        "--script",
        "http-title,http-server-header,ssl-cert,rtsp-url-brute,upnp-info",
        "--script-args",
        "rtsp-url-brute.paths=/cam,/video,/live,/stream",
        "-T3",
        "--max-retries",
        "1",
        "--host-timeout",
        "45s",
        "10.0.20.8",
    ]


def test_nmap_drops_unallowlisted_nse_script(tmp_path: Path) -> None:
    """Unallowlisted NSE scripts are DROPPED (not run), and the scan still
    builds — failing the whole task on one bad script broke port discovery
    (2026-05-28: XBEN-009 nmap failed on http-headers, losing the multi-port
    attack surface). Dropping is strictly safer than running the script."""
    # A single unallowlisted script: command builds, script is absent.
    command = build_nmap_command(
        binary="nmap",
        output_file=tmp_path / "nmap-results.xml",
        targets=["10.0.20.8"],
        discovery_only=False,
        scripts=["http-vuln-cve2006-3392"],
    )
    assert "http-vuln-cve2006-3392" not in command
    assert "--script" not in command  # nothing allowlisted remained
    # Mixed: the allowlisted one survives, the disallowed one is dropped.
    command2 = build_nmap_command(
        binary="nmap",
        output_file=tmp_path / "nmap-results2.xml",
        targets=["10.0.20.8"],
        discovery_only=False,
        scripts=["http-title", "http-vuln-cve2006-3392"],
    )
    assert "--script" in command2
    script_arg = command2[command2.index("--script") + 1]
    assert "http-title" in script_arg
    assert "http-vuln-cve2006-3392" not in script_arg


def test_nmap_command_preview_uses_nested_profile_limits() -> None:
    preview = _runner_command_preview(
        "nmap",
        ["10.0.20.8"],
        {
            "profile_name": "passive-network-service-enumeration",
            "limits": {
                "discovery_only": False,
                "service_detection": True,
                "skip_discovery": True,
                "top_ports": 50,
                "version_intensity": 2,
                "timing_template": "T3",
                "max_retries": 2,
                "host_timeout_seconds": 30,
            },
        },
    )

    assert "-sn" not in preview
    assert "-Pn" in preview
    assert "-sV" in preview
    assert "--top-ports 50" in preview
    assert "10.0.20.8" in preview


def test_nmap_command_preview_includes_nse_ports_and_scripts() -> None:
    preview = _runner_command_preview(
        "nmap",
        ["10.0.20.8"],
        {
            "profile_name": "passive-lan-nse-full",
            "limits": {
                "discovery_only": False,
                "service_detection": True,
                "skip_discovery": True,
                "ports": ["80", "443", "8123"],
                "scripts": ["http-title", "ssl-cert", "upnp-info"],
                "script_args": {"rtsp-url-brute.paths": "/cam,/video"},
            },
        },
    )

    assert "-p 80,443,8123" in preview
    assert "--script http-title,ssl-cert,upnp-info" in preview
    assert "--script-args rtsp-url-brute.paths=/cam,/video" in preview
    assert "10.0.20.8" in preview


def test_smart_home_command_preview_is_read_only() -> None:
    preview = _runner_command_preview(
        "smart-home",
        ["10.0.20.44"],
        {"limits": {"mqtt_listen_seconds": 30}},
    )

    assert "--mqtt-anonymous-readonly" in preview
    assert "--mqtt-subscribe '#'" in preview
    assert "--home-assistant-get-only" in preview
    assert "--redact-values" in preview
    assert "10.0.20.44" in preview


def test_snmp_enum_command_preview_includes_configured_ports() -> None:
    preview = _runner_command_preview(
        "snmp-enum",
        ["10.0.20.8"],
        {"ports": [161, 1161], "community_strings": ["public", "private"]},
    )

    assert "--ports 161,1161" in preview
    assert "--default-communities 2" in preview
    assert "10.0.20.8" in preview


def test_network_capture_command_preview_is_bounded_and_redacted() -> None:
    preview = _runner_command_preview(
        "network-capture",
        ["10.0.20.0/24"],
        {"interface": "eth0", "capture_seconds": 60, "packet_limit": 10000},
    )

    assert "--tcpdump-passive" in preview
    assert "--redact-secrets" in preview
    assert "--seconds 60" in preview
    assert "--packet-limit 10000" in preview
    assert "--arp-consistency" in preview
    assert "10.0.20.0/24" in preview


def test_crypto_audit_command_preview_names_safe_tooling() -> None:
    preview = _runner_command_preview(
        "crypto-audit",
        ["https://portal.example.test"],
        {"limits": {"mode": "passive"}},
    )

    assert "testssl.sh" in preview
    assert "ssh-audit" in preview
    assert "--no-bruteforce" in preview
    assert "--no-decryption" in preview
    assert "https://portal.example.test" in preview


def test_sqlmap_command_preview_describes_bounded_two_phase_scan() -> None:
    preview = _runner_command_preview(
        "sqlmap",
        ["https://portal.example.test/app/"],
        {
            "injectable_parameters": [
                {"url": "https://portal.example.test/app/item?id=1", "parameter": "id"}
            ]
        },
    )

    assert "phase-a" in preview
    assert "--identify-waf" in preview
    assert "--level 1 --risk 1" in preview
    assert "phase-b" in preview
    assert "--level 3 --risk 2" in preview
    assert "--technique T" in preview
    assert "--tamper space2comment,between,randomcase" in preview
    assert "--approved-parameters 1" in preview
    assert "--risk 3" not in preview
    assert "--dump" not in preview
    assert "--os-shell" not in preview


def test_camera_test_command_preview_is_read_only() -> None:
    preview = _runner_command_preview(
        "camera-test",
        ["10.0.20.50"],
        {"limits": {"max_default_credential_attempts": 10}},
    )

    assert "--onvif-ws-discovery" in preview
    assert "--rtsp-options-describe-only" in preview
    assert "--snapshot-get-no-store" in preview
    assert "--bounded-default-creds" in preview
    assert "--no-ptz" in preview
    assert "--no-config-change" in preview
    assert "10.0.20.50" in preview


def test_nmap_ipv6_command_is_structured(tmp_path: Path) -> None:
    command = build_nmap_command(
        binary="nmap",
        output_file=tmp_path / "nmap-results.xml",
        targets=["fe80::1"],
        discovery_only=False,
        service_detection=True,
        skip_discovery=True,
        ports=["80", "443"],
        ipv6=True,
    )

    assert command[:5] == ["nmap", "-n", "-6", "-oX", str(tmp_path / "nmap-results.xml")]
    assert "-Pn" in command
    assert "-sV" in command
    assert "fe80::1" in command


def test_nmap_nse_script_sets_remain_explicitly_scoped() -> None:
    assert "smb-vuln-ms17-010" not in PASSIVE_LAN_NSE_DISCOVERY_SCRIPTS
    assert "http-default-accounts" in ACTIVE_DEFAULT_CREDENTIAL_NSE_SCRIPTS
    assert "telnet-brute" in ACTIVE_DEFAULT_CREDENTIAL_NSE_SCRIPTS
    assert "rtsp-url-brute" in IOT_NSE_DISCOVERY_SCRIPTS


def test_nmap_full_port_command_is_structured(tmp_path: Path) -> None:
    command = build_nmap_command(
        binary="nmap",
        output_file=tmp_path / "nmap-results.xml",
        targets=["203.0.113.10"],
        discovery_only=False,
        service_detection=True,
        skip_discovery=True,
        full_port_scan=True,
    )

    assert command == [
        "nmap",
        "-n",
        "-oX",
        str(tmp_path / "nmap-results.xml"),
        "-Pn",
        "-sV",
        "-p-",
        "203.0.113.10",
    ]


def test_nmap_runner_marks_timeout(tmp_path: Path) -> None:
    binary = tmp_path / "slow-nmap"
    binary.write_text(
        """#!/usr/bin/env python3
import sys
import time

if "--version" in sys.argv:
    print("Nmap version slow-test")
    raise SystemExit(0)

time.sleep(5)
""",
        encoding="utf-8",
    )
    binary.chmod(0o755)

    execution = execute_nmap_scan(
        ["127.0.0.1"],
        binary=str(binary),
        timeout_seconds=0.1,
    )

    assert execution.exit_code == 124
    assert execution.metadata["status"] == "timeout"
    assert execution.metadata["timed_out"] is True
    assert "timed out" in execution.stderr


def test_responder_command_is_structured() -> None:
    command = build_responder_command("responder", interface="eth0")

    assert command == [
        "responder",
        "-I",
        "eth0",
        "-r",
        "-d",
        "-f",
    ]


def test_zap_api_url_is_structured() -> None:
    url = build_zap_api_url(
        base_url="http://zapd:8080/",
        component="core",
        category="view",
        name="version",
    )

    assert url == "http://zapd:8080/JSON/core/view/version/"


def test_semgrep_command_is_structured(tmp_path: Path) -> None:
    command = build_semgrep_command(
        binary="semgrep",
        config_file=tmp_path / "rule.yml",
        target_path=tmp_path / "repo",
        output_file=tmp_path / "results.json",
        jobs=2,
    )

    assert command == [
        "semgrep",
        "scan",
        "--config",
        str(tmp_path / "rule.yml"),
        "--json",
        "--output",
        str(tmp_path / "results.json"),
        "--jobs",
        "2",
        "--disable-version-check",
        "--metrics=off",
        "--no-git-ignore",
        "--quiet",
        str(tmp_path / "repo"),
    ]


def test_semgrep_rule_id_is_normalized() -> None:
    assert (
        normalize_semgrep_rule_id("aegispt.python.hardcoded-secret")
        == "aegispt.python.hardcoded-secret"
    )
    assert (
        normalize_semgrep_rule_id("tmp.aegispt-semgrep-rule.aegispt.python.hardcoded-secret")
        == "aegispt.python.hardcoded-secret"
    )


def test_semgrep_env_drops_blank_proxy_values(monkeypatch) -> None:
    monkeypatch.setenv("HTTP_PROXY", "")
    monkeypatch.setenv("HTTPS_PROXY", "")
    monkeypatch.setenv("NO_PROXY", "127.0.0.1")

    env = _semgrep_env()

    assert "HTTP_PROXY" not in env
    assert "HTTPS_PROXY" not in env
    assert env["NO_PROXY"] == "127.0.0.1"
