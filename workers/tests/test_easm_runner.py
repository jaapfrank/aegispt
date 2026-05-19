from __future__ import annotations

import json

import pytest

from workers.runners.easm import runner as easm_runner
from workers.runners.easm.runner import (
    EASM_RESULTS_ARTIFACT_NAME,
    execute_easm_discovery,
    normalize_root_domain,
)


def test_normalize_root_domain_accepts_url_targets() -> None:
    assert normalize_root_domain("https://portal.example.com/login") == "portal.example.com"


def test_easm_runner_discovers_assets_and_writes_artifact(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        easm_runner,
        "enumerate_subdomains_with_subfinder",
        lambda root_domain, **kwargs: {"api.example.com"},
    )
    monkeypatch.setattr(
        easm_runner,
        "fetch_crtsh_subdomains",
        lambda root_domain, **kwargs: {"portal.example.com"},
    )
    monkeypatch.setattr(
        easm_runner,
        "load_dns_wordlist",
        lambda path=None, limit=easm_runner.MAX_DNS_WORDLIST_ENTRIES: ["admin"],
    )
    monkeypatch.setattr(
        easm_runner,
        "enumerate_dns_wordlist_subdomains",
        lambda root_domain, **kwargs: {"admin.example.com"},
    )
    monkeypatch.setattr(
        easm_runner,
        "resolve_hostname_addresses",
        lambda hostname: {
            "example.com": ["203.0.113.10"],
            "api.example.com": ["203.0.113.11"],
            "portal.example.com": ["203.0.113.12"],
            "admin.example.com": ["203.0.113.13"],
        }.get(hostname, []),
    )
    monkeypatch.setattr(
        easm_runner,
        "probe_http_endpoints_for_host",
        lambda host, **kwargs: [
            {
                "url": f"https://{host}",
                "status_code": 200,
                "title": f"{host} welcome",
                "content_type": "text/html",
                "server_header": "nginx",
                "confidence": 0.84,
            }
        ],
    )

    execution = execute_easm_discovery(
        ["https://example.com/login"],
        scope_allowlist={"domains": ["example.com"]},
    )

    assert execution.tool == "easm-discover"
    assert execution.exit_code == 0
    assert execution.metadata["asset_count"] == 4
    assert execution.metadata["resolved_asset_count"] == 4
    assert execution.metadata["http_endpoint_count"] == 4
    assert execution.artifacts[0].name == EASM_RESULTS_ARTIFACT_NAME

    payload = json.loads(execution.artifacts[0].data.decode("utf-8"))
    assert payload["summary"]["asset_count"] == 4
    assert payload["summary"]["http_endpoint_count"] == 4
    assert payload["results"][0]["root_domain"] == "example.com"
    discovered_hosts = {asset["host"] for asset in payload["results"][0]["assets"]}
    assert discovered_hosts == {
        "example.com",
        "api.example.com",
        "portal.example.com",
        "admin.example.com",
    }


def test_easm_runner_rejects_targets_outside_scope() -> None:
    with pytest.raises(ValueError, match="target outside scope"):
        execute_easm_discovery(
            ["https://example.net"],
            scope_allowlist={"domains": ["example.com"]},
        )
