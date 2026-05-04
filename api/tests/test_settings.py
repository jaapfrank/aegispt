from __future__ import annotations

from sqlalchemy import select

from api.app.config import Settings
from api.app.models import InstanceSetting
from api.app.services.settings import effective_runtime_settings, read_settings_readiness


def _settings_by_key(payload: dict) -> dict[str, dict]:
    return {
        setting["key"]: setting
        for section in payload["sections"]
        for setting in section["settings"]
    }


def test_get_settings_returns_all_sections_with_environment_defaults(client) -> None:
    response = client.get("/api/v1/settings")

    assert response.status_code == 200
    payload = response.json()
    assert payload["tenant_id"] == "default"
    assert payload["sensitive_plaintext_exposed"] is False
    assert {section["id"] for section in payload["sections"]} == {
        "ai_provider",
        "enterprise_identity",
        "default_network_scope",
        "default_scan_profile",
        "runtime_execution",
        "integrations",
        "notifications",
        "threat_intel",
        "evidence_integrity",
        "deployment_hardening",
        "remediation",
        "instance",
    }

    settings = _settings_by_key(payload)
    assert settings["ai.chatgpt_model"]["value"] == "gpt-5.4"
    assert settings["ai.chatgpt_model"]["read_only"] is True
    assert settings["ai.finding_enrichment_enabled"]["value"] is False
    assert settings["ai.post_task_analysis_enabled"]["value"] is False
    assert settings["ai.intake_intelligence_enabled"]["value"] is False
    assert settings["ai.autofix_enabled"]["value"] is False
    assert settings["ai.report_drafting_enabled"]["value"] is False
    assert settings["identity.enterprise_sso_provider"]["value"] == "disabled"
    assert settings["identity.session_timeout_minutes"]["value"] == 480
    assert settings["identity.oidc_client_secret"]["sensitive"] is True
    assert settings["network.default_lan_cidr"]["value"] == "10.0.0.0/8"
    assert settings["network.default_lan_cidr"]["source"] == "environment"
    assert settings["runtime.inline_task_workers"]["value"] == 4
    assert settings["runtime.inline_task_workers"]["input_type"] == "number"
    assert settings["runtime.inline_task_workers"]["min_value"] == 1
    assert settings["runtime.inline_task_workers"]["max_value"] == 32
    assert settings["integrations.slack_webhook_url"]["sensitive"] is True
    assert settings["integrations.slack_webhook_url"]["value"] is None
    assert settings["integrations.slack_webhook_url"]["configured"] is False
    assert settings["threat_intel.sync_enabled"]["value"] is True
    assert settings["threat_intel.nvd_api_key"]["sensitive"] is True
    assert settings["threat_intel.opencve_api_token"]["value"] is None
    assert settings["deployment.tls_terminated_by_proxy"]["read_only"] is True
    assert settings["deployment.secure_cookies"]["read_only"] is True
    assert settings["deployment.outbound_proxy_url"]["sensitive"] is True
    assert settings["deployment.outbound_proxy_url"]["value"] is None


def test_patch_settings_persists_plain_and_encrypted_sensitive_values(client) -> None:
    secret = "https://hooks.slack.example/services/T000/B000/super-secret"
    response = client.patch(
        "/api/v1/settings",
        headers={"X-Actor": "settings-admin"},
        json={
            "settings": {
                "network.default_lan_cidr": "10.42.0.0/16",
                "network.default_vlan_cidrs": ["10.43.0.0/16", "10.44.0.0/16"],
                "notifications.run_completion": True,
                "integrations.slack_webhook_url": secret,
            }
        },
    )

    assert response.status_code == 200
    settings = _settings_by_key(response.json())
    assert settings["network.default_lan_cidr"]["value"] == "10.42.0.0/16"
    assert settings["network.default_vlan_cidrs"]["value"] == ["10.43.0.0/16", "10.44.0.0/16"]
    assert settings["notifications.run_completion"]["value"] is True
    assert settings["integrations.slack_webhook_url"]["value"] is None
    assert settings["integrations.slack_webhook_url"]["configured"] is True
    assert settings["integrations.slack_webhook_url"]["masked_value"]
    assert secret not in str(response.json())

    with client.app.state.session_factory() as session:
        rows = {row.setting_key: row for row in session.scalars(select(InstanceSetting)).all()}

    assert rows["network.default_lan_cidr"].value_json == {"value": "10.42.0.0/16"}
    assert rows["integrations.slack_webhook_url"].sensitive is True
    assert rows["integrations.slack_webhook_url"].encrypted_value
    assert secret not in rows["integrations.slack_webhook_url"].encrypted_value
    assert rows["integrations.slack_webhook_url"].updated_by == "settings-admin"


def test_settings_are_tenant_scoped(client) -> None:
    tenant_headers = {"X-Actor": "settings-admin", "X-Tenant-ID": "acme"}
    response = client.patch(
        "/api/v1/settings",
        headers=tenant_headers,
        json={"settings": {"network.default_lan_cidr": "10.99.0.0/16"}},
    )
    assert response.status_code == 200
    assert _settings_by_key(response.json())["network.default_lan_cidr"]["value"] == "10.99.0.0/16"
    assert response.json()["tenant_id"] == "acme"

    default_response = client.get("/api/v1/settings")
    assert default_response.status_code == 200
    assert _settings_by_key(default_response.json())["network.default_lan_cidr"]["value"] == "10.0.0.0/8"

    tenant_response = client.get("/api/v1/settings", headers={"X-Tenant-ID": "acme"})
    assert tenant_response.status_code == 200
    assert _settings_by_key(tenant_response.json())["network.default_lan_cidr"]["value"] == "10.99.0.0/16"


def test_patch_rejects_unknown_and_read_only_settings(client) -> None:
    unknown_response = client.patch(
        "/api/v1/settings",
        json={"settings": {"scan.activate_new_runner": "nope"}},
    )
    assert unknown_response.status_code == 400
    assert "unknown setting key" in unknown_response.json()["detail"]

    readonly_response = client.patch(
        "/api/v1/settings",
        json={"settings": {"ai.chatgpt_model": "other-model"}},
    )
    assert readonly_response.status_code == 400
    assert "read-only" in readonly_response.json()["detail"]


def test_patch_settings_persists_ai_feature_toggles_and_runtime_overlay(client) -> None:
    response = client.patch(
        "/api/v1/settings",
        headers={"X-Actor": "settings-admin"},
        json={
            "settings": {
                "ai.provider": "chatgpt_oauth",
                "ai.finding_enrichment_enabled": True,
                "ai.post_task_analysis_enabled": True,
                "ai.intake_intelligence_enabled": True,
                "ai.autofix_enabled": True,
                "ai.report_drafting_enabled": True,
            }
        },
    )

    assert response.status_code == 200
    payload = _settings_by_key(response.json())
    assert payload["ai.provider"]["value"] == "chatgpt_oauth"
    assert payload["ai.finding_enrichment_enabled"]["value"] is True
    assert payload["ai.post_task_analysis_enabled"]["value"] is True
    assert payload["ai.intake_intelligence_enabled"]["value"] is True
    assert payload["ai.autofix_enabled"]["value"] is True
    assert payload["ai.report_drafting_enabled"]["value"] is True

    with client.app.state.session_factory() as session:
        effective = effective_runtime_settings(session, tenant_id=None, settings=Settings())

    assert effective.ai_provider == "chatgpt_oauth"
    assert effective.ai_finding_enrichment_enabled is True
    assert effective.ai_agent_post_task_analysis_enabled is True
    assert effective.ai_intake_interpretation_enabled is True
    assert effective.ai_autofix_enabled is True
    assert effective.ai_report_drafting_enabled is True


def test_patch_settings_persists_runtime_parallelism_and_validates_limits(client) -> None:
    response = client.patch(
        "/api/v1/settings",
        headers={"X-Actor": "settings-admin"},
        json={"settings": {"runtime.inline_task_workers": "8"}},
    )

    assert response.status_code == 200
    payload = _settings_by_key(response.json())
    assert payload["runtime.inline_task_workers"]["value"] == 8
    assert payload["runtime.inline_task_workers"]["description"]

    with client.app.state.session_factory() as session:
        effective = effective_runtime_settings(session, tenant_id=None, settings=Settings())

    assert effective.inline_task_workers == 8

    too_low = client.patch("/api/v1/settings", json={"settings": {"runtime.inline_task_workers": 0}})
    assert too_low.status_code == 400
    assert "at least 1" in too_low.json()["detail"]

    too_high = client.patch("/api/v1/settings", json={"settings": {"runtime.inline_task_workers": 64}})
    assert too_high.status_code == 400
    assert "at most 32" in too_high.json()["detail"]


def test_settings_readiness_reports_tools_runtime_and_export_artifact(client, monkeypatch) -> None:
    def fake_which(binary: str) -> str | None:
        if binary in {"nmap", "nuclei", "httpx"}:
            return f"/usr/bin/{binary}"
        return None

    monkeypatch.setattr("api.app.services.settings.shutil.which", fake_which)

    patch_response = client.patch(
        "/api/v1/settings",
        headers={"X-Actor": "settings-admin"},
        json={"settings": {"runtime.inline_task_workers": "6", "ai.provider": "chatgpt_oauth"}},
    )
    assert patch_response.status_code == 200

    response = client.get("/api/v1/settings/readiness")
    assert response.status_code == 200
    payload = response.json()
    assert payload["tenant_id"] == "default"
    assert payload["overall_status"] in {"ready", "degraded", "missing", "blocked"}
    assert payload["artifact"]["kind"] == "aegispt.settings_readiness"
    assert payload["artifact"]["tenant_id"] == "default"

    capabilities = {item["id"]: item for item in payload["capabilities"]}
    assert capabilities["runtime_concurrency"]["metadata"]["current"] == 6
    assert capabilities["runtime_concurrency"]["metadata"]["min"] == 1
    assert capabilities["runtime_concurrency"]["metadata"]["max"] == 32
    assert "does not mutate active runs" in " ".join(capabilities["runtime_concurrency"]["details"])
    assert capabilities["ai_provider"]["metadata"]["provider"] == "chatgpt_oauth"
    assert capabilities["enterprise_identity"]["metadata"]["status"] == "disabled"
    assert capabilities["enterprise_identity"]["metadata"]["session_policy"]["timeout_minutes"] == 480
    assert capabilities["deployment_hardening"]["status"] == "degraded"
    assert capabilities["deployment_hardening"]["metadata"]["production_like"] is False
    assert capabilities["deployment_hardening"]["metadata"]["secrets_plaintext_exposed"] is False

    tools = {item["id"]: item for item in payload["tools"]}
    assert tools["nmap"]["installed"] is True
    assert tools["nmap"]["detected_path"] == "/usr/bin/nmap"
    assert "LAN discovery" in tools["nmap"]["affected_assessment_families"]
    assert tools["httpx"]["installed"] is True
    assert tools["httpx"]["required_binary_groups"] == [["httpx-toolkit", "httpx"]]
    assert tools["metasploit"]["installed"] is False
    assert tools["metasploit"]["status"] == "degraded"
    assert "msfconsole" in tools["metasploit"]["missing_binaries"]
    assert tools["metasploit"]["repair_command"] == "sudo bash scripts/install_security_tools.sh && bash scripts/verify_host.sh"
    assert "Exploit confirmation" in tools["metasploit"]["affected_assessment_families"]
    assert tools["wifi"]["hardware_required"] is True
    assert "airodump-ng" in tools["wifi"]["missing_binaries"]

    assert capabilities["tool_readiness"]["metadata"]["host_installer_command"] == "sudo bash scripts/install_security_tools.sh"
    assert "actions" in capabilities["ai_provider"]["metadata"]


def test_settings_readiness_accepts_tool_aliases_and_reports_hardware_separately(client, monkeypatch) -> None:
    present = {
        "nmap",
        "nuclei",
        "httpx-toolkit",
        "zaproxy",
        "nxc",
        "bloodhound-python",
        "secretsdump.py",
        "psexec.py",
        "wmiexec.py",
        "GetUserSPNs.py",
        "GetNPUsers.py",
        "msfconsole",
        "msfrpcd",
        "hashcat",
        "snmpwalk",
        "iw",
        "airodump-ng",
        "aircrack-ng",
        "responder",
    }

    def fake_which(binary: str) -> str | None:
        if binary in present:
            return f"/usr/local/bin/{binary}"
        return None

    monkeypatch.setattr("api.app.services.settings.shutil.which", fake_which)
    monkeypatch.setattr("api.app.services.settings._detect_wireless_adapters", lambda: [])

    response = client.get("/api/v1/settings/readiness")
    assert response.status_code == 200
    payload = response.json()
    tools = {item["id"]: item for item in payload["tools"]}
    assert tools["httpx"]["installed"] is True
    assert tools["httpx"]["detected_path"] == "/usr/local/bin/httpx-toolkit"
    assert tools["netexec"]["installed"] is True
    assert tools["netexec"]["detected_path"] == "/usr/local/bin/nxc"
    assert tools["impacket"]["installed"] is True
    assert tools["impacket"]["missing_binaries"] == []
    assert tools["wifi"]["installed"] is True

    capabilities = {item["id"]: item for item in payload["capabilities"]}
    wireless = capabilities["wireless_readiness"]
    assert wireless["status"] == "blocked"
    assert wireless["metadata"]["tool_group_installed"] is True
    assert wireless["metadata"]["hardware_blocked"] is True
    assert "Attach authorized wireless hardware" in wireless["operator_next_step"]


def test_settings_readiness_simulated_production_deployment_hardening(client) -> None:
    production_settings = Settings(
        app_env="production",
        app_public_base_url="https://aegispt.example.test",
        database_url="postgresql+psycopg://aegispt:secret-db-pass@db.example.test/aegispt",
        artifacts_storage_mode="s3",
        artifacts_s3_enforce_sse=True,
        deployment_tls_terminated_by_proxy=True,
        deployment_secure_cookies=True,
        deployment_database_encryption_confirmed=True,
        deployment_artifact_storage_encryption_confirmed=True,
        deployment_trusted_certificate_bundle="/etc/aegispt/enterprise-ca.pem",
        deployment_outbound_proxy_url="http://proxy-user:proxy-pass@proxy.example.test:8080",
        deployment_no_internet_mode=False,
    )
    with client.app.state.session_factory() as session:
        readiness = read_settings_readiness(session, tenant_id=None, settings=production_settings)

    capabilities = {item.id: item for item in readiness.capabilities}
    hardening = capabilities["deployment_hardening"]
    assert hardening.status == "ready"
    assert hardening.metadata["production_like"] is True
    assert hardening.metadata["https_public_base_url"] is True
    assert hardening.metadata["outbound_proxy"] == "configured"
    assert hardening.metadata["secrets_plaintext_exposed"] is False
    serialized = str(hardening.model_dump())
    assert "proxy-pass" not in serialized
    assert "secret-db-pass" not in serialized


def test_settings_readiness_blocks_unsafe_production_and_air_gap_gaps(client) -> None:
    unsafe_settings = Settings(
        app_env="production",
        app_public_base_url="http://aegispt.example.test",
        database_url="sqlite+pysqlite:///./aegispt.db",
        artifacts_storage_mode="s3",
        artifacts_s3_enforce_sse=False,
        deployment_tls_terminated_by_proxy=False,
        deployment_secure_cookies=False,
        deployment_no_internet_mode=True,
        deployment_offline_update_path="/mnt/aegispt/offline-feeds",
        deployment_manual_tool_update_path="",
    )
    with client.app.state.session_factory() as session:
        readiness = read_settings_readiness(session, tenant_id=None, settings=unsafe_settings)

    capabilities = {item.id: item for item in readiness.capabilities}
    hardening = capabilities["deployment_hardening"]
    assert hardening.status == "blocked"
    assert hardening.metadata["blocking_gap_count"] >= 4
    assert hardening.metadata["database_encryption_status"] == "blocked"
    assert hardening.metadata["artifact_encryption_status"] == "blocked"
    assert hardening.metadata["no_internet_mode"] is True
    assert hardening.metadata["offline_update_path_configured"] is True
    assert hardening.metadata["manual_tool_update_path_configured"] is False


def test_read_settings_includes_ai_feature_toggle_fields(client) -> None:
    response = client.get("/api/v1/settings")
    assert response.status_code == 200

    payload = _settings_by_key(response.json())
    expected_toggle_keys = [
        "ai.finding_enrichment_enabled",
        "ai.post_task_analysis_enabled",
        "ai.intake_intelligence_enabled",
        "ai.autofix_enabled",
        "ai.report_drafting_enabled",
    ]
    for key in expected_toggle_keys:
        assert key in payload
        assert payload[key]["input_type"] == "checkbox"


def test_run_ai_insights_uses_persisted_settings_defaults(client) -> None:
    engagement_response = client.post(
        "/api/v1/engagements",
        headers={"X-Actor": "settings-admin"},
        json={"name": "AI Settings Run", "client": "Acme", "roe_ref": "ROE-AI-SETTINGS"},
    )
    assert engagement_response.status_code == 201
    engagement_id = engagement_response.json()["id"]

    scope_response = client.post(
        f"/api/v1/engagements/{engagement_id}/scope",
        headers={"X-Actor": "settings-admin"},
        json={
            "allowlist_json": {"urls": ["https://portal.example.test"]},
            "denylist_json": {},
        },
    )
    assert scope_response.status_code == 201

    patch_response = client.patch(
        "/api/v1/settings",
        headers={"X-Actor": "settings-admin"},
        json={
            "settings": {
                "ai.provider": "chatgpt_oauth",
                "ai.post_task_analysis_enabled": True,
            }
        },
    )
    assert patch_response.status_code == 200

    run_response = client.post(
        f"/api/v1/engagements/{engagement_id}/runs",
        headers={"X-Actor": "settings-admin"},
        json={
            "profile_name": "passive-web-baseline",
            "configuration_json": {"targets": {"urls": ["https://portal.example.test"]}},
        },
    )
    assert run_response.status_code == 201
    run_id = run_response.json()["id"]

    insights_response = client.get(f"/api/v1/runs/{run_id}/ai-insights")
    assert insights_response.status_code == 200
    payload = insights_response.json()
    assert payload["post_task_analysis_enabled"] is True
    assert payload["provider"] == "chatgpt_oauth"
