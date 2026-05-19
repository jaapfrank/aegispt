from __future__ import annotations

from workers.runners.easm import runner as easm_runner


def test_inline_dispatch_executes_easm_task_and_keeps_scope_static(
    inline_client,
    monkeypatch,
) -> None:
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
                "title": f"{host} login",
                "content_type": "text/html",
                "server_header": "nginx",
                "confidence": 0.84,
            }
        ],
    )

    engagement_response = inline_client.post(
        "/api/v1/engagements",
        headers={"X-Actor": "tester"},
        json={
            "name": "Inline EASM Validation",
            "client": "Acme Corp",
            "roe_ref": "ROE-2026-EASM",
        },
    )
    engagement_id = engagement_response.json()["id"]

    inline_client.post(
        f"/api/v1/engagements/{engagement_id}/scope",
        headers={"X-Actor": "tester"},
        json={"allowlist_json": {"domains": ["example.com"]}, "denylist_json": {}},
    )

    run_response = inline_client.post(
        f"/api/v1/engagements/{engagement_id}/runs",
        headers={"X-Actor": "tester"},
        json={"profile_name": "passive-easm-discovery"},
    )
    payload = run_response.json()
    task_id = payload["tasks"][0]["id"]
    run_id = payload["id"]

    dispatch_response = inline_client.post(
        f"/api/v1/runs/{run_id}/dispatch",
        headers={"X-Actor": "dispatcher"},
    )
    dispatch_payload = dispatch_response.json()

    assert dispatch_response.status_code == 200
    assert dispatch_payload["dispatch_mode"] == "inline"
    assert dispatch_payload["run"]["status"] == "completed"
    assert dispatch_payload["run"]["tasks"][0]["tool"] == "easm-discover"
    assert dispatch_payload["run"]["tasks"][0]["status"] == "completed"
    assert dispatch_payload["run"]["findings"]["finding_count"] == 0

    task_response = inline_client.get(f"/api/v1/tasks/{task_id}")
    task_payload = task_response.json()
    assert task_response.status_code == 200
    assert task_payload["status"] == "completed"
    assert task_payload["executions"][0]["exit_code"] == 0
    assert task_payload["executions"][0]["artifacts"][0]["metadata_json"]["name"] == "easm-results.json"

    inventory_response = inline_client.get(f"/api/v1/engagements/{engagement_id}/inventory")
    inventory_payload = inventory_response.json()
    assert inventory_response.status_code == 200
    assert len(inventory_payload) == 1
    assert inventory_payload[0]["source_tools_json"] == ["easm-discover"]
    assert inventory_payload[0]["summary_json"]["host_count"] == 4
    assert inventory_payload[0]["summary_json"]["endpoint_count"] == 4
    assert sorted(host["host"] for host in inventory_payload[0]["normalized_inventory_json"]["hosts"]) == [
        "admin.example.com",
        "api.example.com",
        "example.com",
        "portal.example.com",
    ]

    scope_response = inline_client.get(f"/api/v1/engagements/{engagement_id}/scope")
    scope_payload = scope_response.json()
    assert scope_response.status_code == 200
    assert scope_payload["allowlist_json"] == {"domains": ["example.com"]}
