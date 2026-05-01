from __future__ import annotations

import httpx
import pytest
from subprocess import CompletedProcess

import scripts.acceptance_harness as acceptance_harness
from scripts.acceptance_harness import (
    activate_runtime_target,
    assert_runtime_prerequisites,
    build_engagement_payload,
    build_inventory_seed_payload,
    build_allowlist_from_target,
    build_run_configuration,
    load_target_catalog,
    summarize_result,
    resolve_safe_target,
    select_next_real_run_scenario,
    validate_target_catalog,
)


def test_resolve_safe_target_rejects_unauthorized_public_scope() -> None:
    catalog = {
        "targets": [
            {
                "id": "public-demo",
                "classification": "training_lab",
                "enabled": True,
                "authorized": True,
                "unauthorized_public": True,
            }
        ]
    }

    with pytest.raises(ValueError, match="unauthorized public scope"):
        resolve_safe_target(catalog, "public-demo")


def test_default_target_catalog_expands_benchmark_truth_safely() -> None:
    catalog = load_target_catalog()

    summary = validate_target_catalog(catalog)
    targets = {target["id"]: target for target in catalog["targets"]}
    scenarios = {scenario["id"]: scenario for scenario in catalog["real_run_scenarios"]}

    assert summary["target_count"] >= 12
    assert "secrets_lab" in summary["surface_kinds"]
    assert "llm_app" in summary["surface_kinds"]
    assert "internal_ad_lab" in summary["surface_kinds"]
    assert targets["owasp-wrongsecrets-local-template"]["runnability"] == "disabled_template"
    assert targets["promptme-reference"]["runnability"] == "documentation_only"
    assert targets["goad-ad-lab-template"]["surface_kind"] == "internal_ad_lab"
    assert targets["owasp-benchmark-reference"]["benchmark_metadata"]["vulnerable_families"]
    assert scenarios["wrongsecrets-reference-stub"]["dispatch"] is False
    assert scenarios["promptme-reference-stub"]["enabled"] is False


def test_validate_target_catalog_rejects_enabled_documentation_only_target() -> None:
    catalog = {
        "targets": [
            {
                "id": "hosted-reference",
                "classification": "training_lab",
                "enabled": True,
                "authorized": False,
                "runnability": "documentation_only",
            }
        ],
        "real_run_scenarios": [],
    }

    with pytest.raises(ValueError, match="Documentation-only target"):
        validate_target_catalog(catalog)


def test_build_run_configuration_supports_non_web_scope_inputs() -> None:
    scenario = {
        "id": "wrongsecrets-stub",
        "name": "WrongSecrets Stub",
        "assessment_type": "CI/CD and Secrets",
        "profile": "Secrets Hygiene",
        "run_profile": "passive-cicd-security-assessment",
        "modules": ["secrets_hygiene_review", "cicd_security_review"],
        "expected_outputs": ["fixture_metadata"],
    }
    target = {
        "id": "wrongsecrets-template",
        "label": "WrongSecrets Template",
        "classification": "training_lab",
        "scope": {
            "pipeline_config_paths": ["/tmp/aegispt/pipelines/build.yml"],
            "repositories": ["acme/repo"],
            "llm_endpoints": ["http://127.0.0.1:9000/chat"],
            "apk_paths": ["/tmp/aegispt/app.apk"],
            "container_images": ["registry.example/app:latest"],
            "kubernetes_manifest_paths": ["/tmp/aegispt/k8s/app.yaml"],
            "directory_domains": ["ad.lab.local"],
        },
    }

    configuration = build_run_configuration(scenario=scenario, target=target)
    allowlist = build_allowlist_from_target(target)

    assert configuration["targets"]["pipeline_config_paths"] == ["/tmp/aegispt/pipelines/build.yml"]
    assert configuration["targets"]["repositories"] == ["acme/repo"]
    assert configuration["targets"]["directory_domains"] == ["ad.lab.local"]
    assert configuration["modules"]["secrets_hygiene_review"] is True
    assert configuration["modules"]["cicd_security_review"] is True
    assert allowlist["pipeline_config_paths"] == ["/tmp/aegispt/pipelines/build.yml"]
    assert allowlist["repositories"] == ["acme/repo"]
    assert allowlist["domains"] == ["ad.lab.local"]


def test_build_run_configuration_preserves_acceptance_metadata() -> None:
    scenario = {
        "id": "lan-safe-check",
        "name": "LAN Safe Check",
        "assessment_type": "Internal Range / LAN",
        "profile": "Standard",
        "run_profile": "passive-network-discovery",
        "modules": ["discovery"],
        "expected_outputs": ["inventory", "task_evidence", "reports"],
    }
    target = {
        "id": "authorized-lan-template",
        "label": "Authorized LAN",
        "classification": "authorized_customer",
        "scope": {"cidrs": ["10.0.20.0/24"]},
    }

    configuration = build_run_configuration(scenario=scenario, target=target)
    allowlist = build_allowlist_from_target(target)

    assert configuration["assessment_type"] == "Internal Range / LAN"
    assert configuration["targets"]["cidr_ranges"] == ["10.0.20.0/24"]
    assert configuration["modules"]["discovery"] is True
    assert configuration["execution_profile"] == "passive-network-discovery"
    assert configuration["acceptance_metadata"]["scenario_id"] == "lan-safe-check"
    assert configuration["acceptance_metadata"]["target_label"] == "Authorized LAN"
    assert allowlist["cidrs"] == ["10.0.20.0/24"]


def test_select_next_real_run_scenario_prefers_unpassed_entries() -> None:
    catalog = {
        "real_run_scenarios": [
            {"id": "local-smoke", "enabled": True, "priority": 10},
            {"id": "juice-shop", "enabled": True, "priority": 20},
        ]
    }
    history = [
        {"scenario_id": "local-smoke", "status": "passed"},
    ]

    selected = select_next_real_run_scenario(catalog, history)

    assert selected["id"] == "juice-shop"


def test_activate_runtime_target_materializes_local_probe_fixture() -> None:
    target = {
        "id": "local-aegispt-smoke",
        "label": "Local Acceptance Probe Target",
        "classification": "local_dev",
        "enabled": True,
        "authorized": True,
        "scope": {"urls": []},
        "runtime_fixture": "local_http_probe",
        "runtime_fixture_path": "/health/live",
        "notes": "Fixture-backed smoke target.",
    }

    with activate_runtime_target(target) as materialized:
        assert materialized["scope"]["urls"]
        probe_url = materialized["scope"]["urls"][0]
        response = httpx.get(probe_url, timeout=5.0)

        assert response.status_code == 200
        assert response.json()["fixture"] == "local-http-probe"
        assert materialized["runtime_fixture_context"]["resolved_url"] == probe_url
        assert "Auto-spawned local probe fixture resolved to" in materialized["notes"]


def test_activate_runtime_target_materializes_webgoat_fixture(monkeypatch: pytest.MonkeyPatch) -> None:
    target = {
        "id": "owasp-webgoat-local",
        "label": "OWASP WebGoat",
        "classification": "training_lab",
        "enabled": True,
        "authorized": True,
        "scope": {"urls": ["http://127.0.0.1:8080/WebGoat"]},
        "runtime_fixture": "docker_webgoat",
        "runtime_fixture_image": "webgoat/webgoat",
        "runtime_fixture_container_port": 8080,
        "runtime_fixture_aux_port": 9090,
        "notes": "Training target for authenticated workflows.",
    }
    reserved_ports = iter([41080, 41090])
    calls: list[list[str]] = []

    monkeypatch.setattr(acceptance_harness, "_reserve_loopback_port", lambda: next(reserved_ports))
    monkeypatch.setattr(acceptance_harness, "_wait_for_http_ready", lambda *args, **kwargs: 200)

    def fake_run(args, **kwargs):
        calls.append(list(args))
        if args[:3] == ["docker", "run", "-d"]:
            return CompletedProcess(args=args, returncode=0, stdout="fixture-container\n", stderr="")
        return CompletedProcess(args=args, returncode=0, stdout="", stderr="")

    monkeypatch.setattr(acceptance_harness.subprocess, "run", fake_run)

    with activate_runtime_target(target) as materialized:
        assert materialized["scope"]["urls"] == ["http://127.0.0.1:41080/WebGoat"]
        assert materialized["runtime_fixture_context"]["fixture"] == "docker_webgoat"
        assert materialized["runtime_fixture_context"]["webwolf_url"] == "http://127.0.0.1:41090/WebWolf"
        assert "Auto-spawned WebGoat fixture resolved to http://127.0.0.1:41080/WebGoat" in materialized["notes"]

    assert any(call[:3] == ["docker", "run", "-d"] for call in calls)
    assert any(call[:3] == ["docker", "rm", "-f"] for call in calls)


def test_assert_runtime_prerequisites_checks_active_safe_tools(monkeypatch: pytest.MonkeyPatch) -> None:
    scenario = {"run_profile": "active-web-safe"}
    target = {
        "scope": {
            "urls": ["http://127.0.0.1:8888"],
            "api_base_urls": ["http://127.0.0.1:8888/identity/api"],
        }
    }
    checked_urls: list[str] = []

    monkeypatch.setattr(
        acceptance_harness,
        "_verify_zap_daemon",
        lambda: {"zap_base_url": "http://127.0.0.1:8080", "zap_version": "2.17.0"},
    )
    monkeypatch.setattr(
        acceptance_harness,
        "_wait_for_http_ready",
        lambda url, **kwargs: checked_urls.append(url) or 200,
    )

    result = assert_runtime_prerequisites(scenario=scenario, target=target)

    assert result["zap_version"] == "2.17.0"
    assert checked_urls == ["http://127.0.0.1:8888", "http://127.0.0.1:8888/identity/api"]


def test_acceptance_harness_executes_safe_local_smoke(inline_client, probe_server: str) -> None:
    scenario = {
        "id": "local-probe-smoke",
        "name": "Local Probe Smoke",
        "assessment_type": "Website / Web App",
        "profile": "Light",
        "run_profile": "passive-web-baseline",
        "modules": ["discovery", "web_crawling", "ssl_tls_analysis"],
        "safety": {
            "active_checks": "passive-only",
            "adaptive_generation": False,
            "max_validation_depth": "light",
            "time_budget_minutes": 20,
        },
        "expected_outputs": ["inventory", "task_evidence", "reports", "history_entry"],
        "minimum_reports": 4,
        "minimum_findings": 0,
    }
    target = {
        "id": "local-probe",
        "label": "Local Probe Target",
        "classification": "local_dev",
        "enabled": True,
        "authorized": True,
        "owner": "Local Development",
        "authorization_ref": "LOCAL-PROBE",
        "assessment_type": "Website / Web App",
        "scope": {"urls": [probe_server]},
        "recommended_profile": "Light",
        "recommended_run_profile": "passive-web-baseline",
    }

    engagement_response = inline_client.post(
        "/api/v1/engagements",
        headers={"X-Actor": "codex-acceptance"},
        json=build_engagement_payload(scenario=scenario, target=target),
    )
    assert engagement_response.status_code == 201
    engagement = engagement_response.json()

    scope_response = inline_client.post(
        f"/api/v1/engagements/{engagement['id']}/scope",
        headers={"X-Actor": "codex-acceptance"},
        json={"allowlist_json": build_allowlist_from_target(target), "denylist_json": {}},
    )
    assert scope_response.status_code == 201

    inventory_response = inline_client.post(
        "/api/v1/inventory/runs",
        headers={"X-Actor": "codex-acceptance"},
        json=build_inventory_seed_payload(engagement["id"], scenario=scenario, target=target),
    )
    assert inventory_response.status_code == 201
    inventory_snapshot = inventory_response.json()

    run_response = inline_client.post(
        f"/api/v1/engagements/{engagement['id']}/runs",
        headers={"X-Actor": "codex-acceptance"},
        json={
            "profile_name": "passive-web-baseline",
            "source_inventory_snapshot_id": inventory_snapshot["id"],
            "configuration_json": build_run_configuration(scenario=scenario, target=target),
        },
    )
    assert run_response.status_code == 201
    run_payload = run_response.json()
    assert run_payload["configuration_json"]["acceptance_metadata"]["scenario_id"] == "local-probe-smoke"

    dispatch_response = inline_client.post(
        f"/api/v1/runs/{run_payload['id']}/dispatch",
        headers={"X-Actor": "codex-acceptance"},
    )
    assert dispatch_response.status_code == 200
    run = dispatch_response.json()["run"]
    assert run["status"] == "completed"

    findings = inline_client.get(
        f"/api/v1/runs/{run['id']}/findings",
        headers={"X-Actor": "codex-acceptance"},
    ).json()
    reports = inline_client.get(
        f"/api/v1/runs/{run['id']}/reports",
        headers={"X-Actor": "codex-acceptance"},
    ).json()
    inventory = inline_client.get(
        f"/api/v1/engagements/{engagement['id']}/inventory",
        headers={"X-Actor": "codex-acceptance"},
    ).json()
    packs = inline_client.get(
        f"/api/v1/engagements/{engagement['id']}/packs",
        headers={"X-Actor": "codex-acceptance"},
    ).json()
    task_details = [
        inline_client.get(f"/api/v1/tasks/{task['id']}", headers={"X-Actor": "codex-acceptance"}).json()
        for task in run["tasks"]
    ]

    result = summarize_result(
        scenario=scenario,
        target=target,
        engagement_id=engagement["id"],
        run=run,
        findings=findings,
        reports=reports,
        inventory=inventory,
        packs=packs,
        task_details=task_details,
        base_url="http://testserver",
    )

    assert result["status"] == "passed"
    assert result["checks"]["task_execution_available"] is True
    assert result["checks"]["artifact_available"] is True
    assert result["links"]["run_report_pdf"].endswith("format=pdf&variant=technical")
