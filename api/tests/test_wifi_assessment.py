from __future__ import annotations


IW_SCAN_FIXTURE = """
BSS aa:bb:cc:dd:ee:ff(on wlan0)
    signal: -42.00 dBm
    SSID: CorpWiFi
    DS Parameter set: channel 6
    RSN:     * Version: 1
             * Group cipher: CCMP
             * Pairwise ciphers: CCMP
             * Authentication suites: PSK
BSS 11:22:33:44:55:66(on wlan0)
    signal: -70.00 dBm
    SSID: GuestWiFi
    DS Parameter set: channel 11
    capability: ESS Privacy
    WPS:
""".strip()


def _create_wifi_engagement(client) -> str:
    engagement_response = client.post(
        "/api/v1/engagements",
        headers={"X-Actor": "wifi-operator"},
        json={
            "name": "Wireless Foundation Validation",
            "client": "Acme Corp",
            "roe_ref": "ROE-WIFI-2026",
        },
    )
    assert engagement_response.status_code == 201
    engagement_id = engagement_response.json()["id"]

    scope_response = client.post(
        f"/api/v1/engagements/{engagement_id}/scope",
        headers={"X-Actor": "wifi-operator"},
        json={
            "allowlist_json": {
                "wireless_sites": ["HQ-Amsterdam"],
                "ssids": ["CorpWiFi"],
                "bssids": ["aa:bb:cc:dd:ee:ff"],
            },
            "denylist_json": {
                "ssids": ["GuestWiFi"],
            },
        },
    )
    assert scope_response.status_code == 201
    return engagement_id


def _wifi_configuration(*, roe_acknowledged: bool = True) -> dict:
    return {
        "assessment_type": "WiFi / Wireless",
        "execution_profile": "passive-wifi-survey",
        "targets": {
            "wireless_sites": ["HQ-Amsterdam"],
            "ssids": ["CorpWiFi"],
            "bssids": ["aa:bb:cc:dd:ee:ff"],
        },
        "exclusions": {
            "ssids": ["GuestWiFi"],
        },
        "wireless": {
            "site": "HQ-Amsterdam",
            "adapter": "wlan0",
            "approved_ssids": ["CorpWiFi"],
            "approved_bssids": ["aa:bb:cc:dd:ee:ff"],
            "excluded_ssids": ["GuestWiFi"],
            "roe_acknowledged": roe_acknowledged,
            "passive_only": True,
            "rf_disruptive_actions": False,
            "handshake_capture": False,
            "credential_harvesting": False,
            "wps_pin_testing": False,
            "fixture_iw_scan_text": IW_SCAN_FIXTURE,
        },
    }


def test_wifi_assessment_dispatch_stores_inventory_findings_and_report(inline_client) -> None:
    engagement_id = _create_wifi_engagement(inline_client)

    run_response = inline_client.post(
        f"/api/v1/engagements/{engagement_id}/runs",
        headers={"X-Actor": "wifi-operator"},
        json={
            "profile_name": "passive-wifi-survey",
            "configuration_json": _wifi_configuration(),
        },
    )
    assert run_response.status_code == 201
    run_payload = run_response.json()
    assert run_payload["status"] == "queued"
    assert run_payload["tasks"][0]["tool"] == "wifi-survey"
    assert run_payload["tasks"][0]["params_json"]["passive_only"] is True
    assert run_payload["tasks"][0]["params_json"]["rf_disruptive_actions"] is False

    dispatch_response = inline_client.post(
        f"/api/v1/runs/{run_payload['id']}/dispatch",
        headers={"X-Actor": "wifi-dispatcher"},
    )
    assert dispatch_response.status_code == 200
    dispatch_payload = dispatch_response.json()
    assert dispatch_payload["run"]["status"] == "completed"
    task_payload = dispatch_payload["run"]["tasks"][0]
    assert task_payload["status"] == "completed"

    findings_response = inline_client.get(f"/api/v1/runs/{run_payload['id']}/findings")
    assert findings_response.status_code == 200
    findings = findings_response.json()
    assert any(finding["title"] == "Wireless PMF posture not confirmed" for finding in findings)

    inventory_response = inline_client.get(f"/api/v1/engagements/{engagement_id}/inventory")
    assert inventory_response.status_code == 200
    inventory = inventory_response.json()
    assert inventory[0]["summary_json"]["wireless_access_point_count"] == 1
    assert inventory[0]["summary_json"]["wireless_network_count"] == 1

    catalog_response = inline_client.get(f"/api/v1/runs/{run_payload['id']}/reports")
    assert catalog_response.status_code == 200
    catalog = catalog_response.json()
    assert any(
        "wifi_security_summary" in report["included_findings"]["report_sections"]
        and report["included_inventory"]["wireless_access_point_count"] == 1
        for report in catalog
    )

    markdown_response = inline_client.get(f"/api/v1/runs/{run_payload['id']}/report?format=markdown")
    assert markdown_response.status_code == 200
    assert "## WiFi Security Summary" in markdown_response.text
    assert "no deauthentication, jamming, evil-twin, handshake capture, WPS brute force, or credential harvesting was performed" in markdown_response.text


def test_wifi_assessment_rejects_missing_wireless_roe(client) -> None:
    engagement_id = _create_wifi_engagement(client)

    run_response = client.post(
        f"/api/v1/engagements/{engagement_id}/runs",
        headers={"X-Actor": "wifi-operator"},
        json={
            "profile_name": "passive-wifi-survey",
            "configuration_json": _wifi_configuration(roe_acknowledged=False),
        },
    )

    assert run_response.status_code == 409
    assert "wireless ROE acknowledgement" in run_response.json()["detail"]


def test_settings_readiness_includes_wireless_capability(client, monkeypatch) -> None:
    def fake_which(binary: str) -> str | None:
        if binary in {"iw", "airodump-ng", "aircrack-ng"}:
            return f"/usr/bin/{binary}"
        return None

    monkeypatch.setattr("api.app.services.settings.shutil.which", fake_which)
    monkeypatch.setattr("api.app.services.settings._detect_wireless_adapters", lambda: ["wlan0"])

    response = client.get("/api/v1/settings/readiness")

    assert response.status_code == 200
    capabilities = {item["id"]: item for item in response.json()["capabilities"]}
    wireless = capabilities["wireless_readiness"]
    assert wireless["status"] == "ready"
    assert wireless["metadata"]["detected_adapters"] == ["wlan0"]
    assert wireless["metadata"]["safe_parallelism_limit"] == 1
    assert wireless["metadata"]["rf_disruptive_actions_allowed"] is False
    assert wireless["metadata"]["handshake_capture_allowed"] is False

    monkeypatch.setattr("api.app.services.settings.shutil.which", lambda _binary: None)
    monkeypatch.setattr("api.app.services.settings._detect_wireless_adapters", lambda: ["wlan0"])
    degraded_response = client.get("/api/v1/settings/readiness")
    degraded_capabilities = {item["id"]: item for item in degraded_response.json()["capabilities"]}
    assert degraded_capabilities["wireless_readiness"]["status"] == "degraded"
    assert "tooling is incomplete" in degraded_capabilities["wireless_readiness"]["summary"]

    monkeypatch.setattr("api.app.services.settings._detect_wireless_adapters", lambda: [])
    blocked_response = client.get("/api/v1/settings/readiness")
    blocked_capabilities = {item["id"]: item for item in blocked_response.json()["capabilities"]}
    assert blocked_capabilities["wireless_readiness"]["status"] == "blocked"
    assert "No wireless adapter is detected" in blocked_capabilities["wireless_readiness"]["summary"]
