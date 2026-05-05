from __future__ import annotations

import json
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

from cryptography.fernet import Fernet
from fastapi.testclient import TestClient
from sqlalchemy import select

from workers.runners.base.contracts import (
    EvidenceArtifact,
    ProtectedSecretMaterial,
    RunnerExecution,
)
from workers.runners.bloodhound.runner import (
    BLOODHOUND_COLLECTION_ARTIFACT_NAME,
    BLOODHOUND_RESULTS_ARTIFACT_NAME,
)
from workers.runners.credential_attacks.runner import (
    CREDENTIAL_ATTACK_LOG_ARTIFACT_NAME,
    CREDENTIAL_ATTACK_RESULTS_ARTIFACT_NAME,
)
from workers.runners.netexec.runner import NETEXEC_LOG_ARTIFACT_NAME, NETEXEC_RESULTS_ARTIFACT_NAME
from workers.runners.responder.runner import (
    RESPONDER_LOG_ARTIFACT_NAME,
    RESPONDER_RESULTS_ARTIFACT_NAME,
)


def create_engagement_with_scope(client) -> str:
    engagement_response = client.post(
        "/api/v1/engagements",
        headers={"X-Actor": "tester"},
        json={
            "name": "Acme Validation",
            "client": "Acme Corp",
            "roe_ref": "ROE-2026-002",
        },
    )
    engagement_id = engagement_response.json()["id"]

    client.post(
        f"/api/v1/engagements/{engagement_id}/scope",
        headers={"X-Actor": "tester"},
        json={
            "allowlist_json": {
                "domains": ["example.com"],
                "urls": ["https://example.com"],
            },
            "denylist_json": {"domains": ["admin.example.com"]},
        },
    )

    return engagement_id


def create_engagement_with_url_scope(client, url: str) -> str:
    engagement_response = client.post(
        "/api/v1/engagements",
        headers={"X-Actor": "tester"},
        json={
            "name": "Scheduled Validation",
            "client": "Acme Corp",
            "roe_ref": "ROE-2026-SCHEDULED",
        },
    )
    engagement_id = engagement_response.json()["id"]

    client.post(
        f"/api/v1/engagements/{engagement_id}/scope",
        headers={"X-Actor": "tester"},
        json={
            "allowlist_json": {"urls": [url]},
            "denylist_json": {},
        },
    )

    return engagement_id


def create_engagement_with_mobile_scope(client, apk_path: str) -> str:
    engagement_response = client.post(
        "/api/v1/engagements",
        headers={"X-Actor": "tester"},
        json={
            "name": "Android Mobile Assessment",
            "client": "Acme Corp",
            "roe_ref": "ROE-2026-MOBILE",
        },
    )
    engagement_id = engagement_response.json()["id"]

    client.post(
        f"/api/v1/engagements/{engagement_id}/scope",
        headers={"X-Actor": "tester"},
        json={
            "allowlist_json": {"apk_paths": [apk_path]},
            "denylist_json": {},
        },
    )

    return engagement_id


def create_engagement_with_desktop_scope(
    client,
    *,
    artifact_path: str = "/tmp/aegispt/desktop/operator.zip",
    helper_url: str = "http://127.0.0.1:4372",
) -> str:
    engagement_response = client.post(
        "/api/v1/engagements",
        headers={"X-Actor": "tester"},
        json={
            "name": "Desktop Client Assessment",
            "client": "Acme Corp",
            "roe_ref": "ROE-2026-DESKTOP",
        },
    )
    engagement_id = engagement_response.json()["id"]

    client.post(
        f"/api/v1/engagements/{engagement_id}/scope",
        headers={"X-Actor": "tester"},
        json={
            "allowlist_json": {
                "desktop_artifact_paths": [artifact_path],
                "local_helper_urls": [helper_url],
            },
            "denylist_json": {},
        },
    )

    return engagement_id


def create_engagement_with_cloud_native_scope(
    client,
    *,
    manifest_path: str = "/tmp/aegispt/k8s/app.yaml",
    image_ref: str = "registry.example/app:latest",
) -> str:
    engagement_response = client.post(
        "/api/v1/engagements",
        headers={"X-Actor": "tester"},
        json={
            "name": "Cloud Native Assessment",
            "client": "Acme Corp",
            "roe_ref": "ROE-2026-CLOUD-NATIVE",
        },
    )
    engagement_id = engagement_response.json()["id"]

    client.post(
        f"/api/v1/engagements/{engagement_id}/scope",
        headers={"X-Actor": "tester"},
        json={
            "allowlist_json": {
                "kubernetes_manifest_paths": [manifest_path],
                "container_images": [image_ref],
            },
            "denylist_json": {},
        },
    )

    return engagement_id


def create_engagement_with_cicd_scope(
    client,
    *,
    pipeline_path: str = "/tmp/aegispt/pipelines/build.yml",
    repository: str = "acme/repo",
) -> str:
    engagement_response = client.post(
        "/api/v1/engagements",
        headers={"X-Actor": "tester"},
        json={
            "name": "CI/CD Security Assessment",
            "client": "Acme Corp",
            "roe_ref": "ROE-2026-CICD",
        },
    )
    engagement_id = engagement_response.json()["id"]

    client.post(
        f"/api/v1/engagements/{engagement_id}/scope",
        headers={"X-Actor": "tester"},
        json={
            "allowlist_json": {
                "pipeline_config_paths": [pipeline_path],
                "repositories": [repository],
            },
            "denylist_json": {},
        },
    )

    return engagement_id


def create_engagement_with_cidr_scope(client, cidr: str) -> str:
    engagement_response = client.post(
        "/api/v1/engagements",
        headers={"X-Actor": "tester"},
        json={
            "name": "Internal Credential Capture",
            "client": "Acme Corp",
            "roe_ref": "ROE-2026-RESPONDER",
        },
    )
    engagement_id = engagement_response.json()["id"]

    client.post(
        f"/api/v1/engagements/{engagement_id}/scope",
        headers={"X-Actor": "tester"},
        json={
            "allowlist_json": {"cidrs": [cidr]},
            "denylist_json": {},
        },
    )

    return engagement_id


def create_engagement_with_directory_scope(client, domain: str, host: str) -> str:
    engagement_response = client.post(
        "/api/v1/engagements",
        headers={"X-Actor": "tester"},
        json={
            "name": "AD Graph Collection",
            "client": "Acme Corp",
            "roe_ref": "ROE-2026-BLOODHOUND",
        },
    )
    engagement_id = engagement_response.json()["id"]

    client.post(
        f"/api/v1/engagements/{engagement_id}/scope",
        headers={"X-Actor": "tester"},
        json={
            "allowlist_json": {
                "ad_domains": [domain],
                "directory_hosts": [host],
            },
            "denylist_json": {},
        },
    )

    return engagement_id


def create_engagement_with_host_scope(client, hosts: list[str]) -> str:
    engagement_response = client.post(
        "/api/v1/engagements",
        headers={"X-Actor": "tester"},
        json={
            "name": "SMB Validation",
            "client": "Acme Corp",
            "roe_ref": "ROE-2026-SMB",
        },
    )
    engagement_id = engagement_response.json()["id"]

    client.post(
        f"/api/v1/engagements/{engagement_id}/scope",
        headers={"X-Actor": "tester"},
        json={
            "allowlist_json": {
                "hosts": hosts,
                "urls": ["https://portal.example.test"],
            },
            "denylist_json": {},
        },
    )

    return engagement_id


def _attach_delete_impact_records(client, run_id: str) -> None:
    from api.app.models import (
        AgentProposal,
        AgentReasoning,
        Finding,
        FindingAiEnrichment,
        FindingChain,
        FindingRemediation,
        Run,
        ToolExecution,
    )
    from api.app.models import (
        EvidenceArtifact as EvidenceArtifactRecord,
    )

    with client.app.state.session_factory() as session:
        run = session.get(Run, UUID(run_id))
        assert run is not None
        task = run.tasks[0]
        execution = ToolExecution(
            task_id=task.id,
            runner_digest="sha256:test",
            tool_version="test-runner 1.0",
            exit_code=0,
            stdout_text="delete impact evidence",
        )
        session.add(execution)
        session.flush()
        artifact = EvidenceArtifactRecord(
            tool_execution_id=execution.id,
            kind="stdout",
            uri=f"memory://delete-impact/{execution.id}",
            sha256="0" * 64,
            redaction_state="complete",
            metadata_json={"name": "delete-impact.txt"},
        )
        finding = Finding(
            run_id=run.id,
            title="Delete Impact Finding",
            severity="medium",
            target_id="https://example.com",
            evidence_ref=artifact.uri,
            status="open",
            summary="Used to prove delete impact counts.",
        )
        session.add_all([artifact, finding])
        session.flush()
        session.add_all(
            [
                FindingRemediation(finding_id=finding.id, state="not_started", created_by="tester", updated_by="tester"),
                FindingAiEnrichment(
                    finding_id=finding.id,
                    status="succeeded",
                    provider="test",
                    business_impact="Impact",
                    technical_context="Context",
                    remediation_narrative="Fix",
                ),
                FindingChain(
                    run_id=run.id,
                    pattern_id="delete-impact-chain",
                    component_hash="1" * 64,
                    title="Delete Impact Chain",
                    combined_impact_text="Combined impact",
                ),
            ]
        )
        reasoning = AgentReasoning(
            run_id=run.id,
            reasoning_type="post_task_analysis",
            status="recorded",
            provider="test",
            context_snapshot_json={},
            observations_json=[],
            hypotheses_json=[],
            proposals_json=[],
        )
        session.add(reasoning)
        session.flush()
        session.add(
            AgentProposal(
                run_id=run.id,
                agent_reasoning_id=reasoning.id,
                proposed_tool="nuclei",
                proposed_target="https://example.com",
                proposed_params_json={},
                reasoning_text="Follow-up proposal",
            )
        )
        session.commit()


def create_engagement_with_external_infra_scope(
    client,
    *,
    domains: list[str] | None = None,
    cidrs: list[str] | None = None,
    hosts: list[str] | None = None,
) -> str:
    engagement_response = client.post(
        "/api/v1/engagements",
        headers={"X-Actor": "tester"},
        json={
            "name": "External Infrastructure",
            "client": "Acme Corp",
            "roe_ref": "ROE-2026-EXT-INFRA",
        },
    )
    engagement_id = engagement_response.json()["id"]

    client.post(
        f"/api/v1/engagements/{engagement_id}/scope",
        headers={"X-Actor": "tester"},
        json={
            "allowlist_json": {
                "domains": list(domains or []),
                "cidrs": list(cidrs or []),
                "hosts": list(hosts or []),
            },
            "denylist_json": {},
        },
    )

    return engagement_id


@contextmanager
def build_client_with_env(tmp_path, monkeypatch, **env_overrides: str) -> Iterator[TestClient]:
    database_path = tmp_path / "aegispt-policy.db"
    monkeypatch.setenv("DATABASE_URL", f"sqlite+pysqlite:///{database_path}")
    monkeypatch.setenv("AUTO_CREATE_TABLES", "true")
    monkeypatch.setenv("TASK_DISPATCH_MODE", "inline")
    for key, value in env_overrides.items():
        monkeypatch.setenv(key, value)

    from api.app.config import get_settings
    from api.app.main import create_app

    get_settings.cache_clear()

    with TestClient(create_app()) as test_client:
        yield test_client

    get_settings.cache_clear()


def test_list_run_profiles(client) -> None:
    response = client.get("/api/v1/run-profiles")

    assert response.status_code == 200
    payload = response.json()
    profile_names = [profile["name"] for profile in payload]
    assert profile_names == [
        "active-ad-asreproast",
        "active-ad-bloodhound",
        "active-ad-kerberoast",
        "active-api-assessment",
        "active-browser-validation",
        "active-business-logic",
        "active-external-infrastructure",
        "active-lan-camera-audit",
        "active-lan-default-creds-audit",
        "active-lan-segmentation-test",
        "active-llm-application-probe",
        "active-offline-hash-crack",
        "active-web-auth-flow",
        "active-web-client-state",
        "active-web-content-discovery",
        "active-web-deserialization-probe",
        "active-web-graphql-probe",
        "active-web-headers-security",
        "active-web-idor-bac",
        "active-web-jwt-probe",
        "active-web-safe",
        "active-web-session-security",
        "active-web-sqlmap-confirmation",
        "active-web-ssrf-probe",
        "active-web-vuln-components",
        "active-web-xss-extended",
        "active-web-xxe-probe",
        "active-web-zap-active",
        "autonomous-internal",
        "autonomous-web",
        "intrusive-ad-password-spray",
        "intrusive-exploitation",
        "intrusive-impacket-dcsync",
        "intrusive-impacket-remote-exec",
        "intrusive-impacket-secretsdump",
        "intrusive-lan-credential-capture",
        "intrusive-lan-smb-auth",
        "intrusive-validation",
        "passive-browser-recon",
        "passive-cicd-security-assessment",
        "passive-cloud-aws-inventory",
        "passive-cloud-native-assessment",
        "passive-code-semgrep-audit",
        "passive-desktop-client-static",
        "passive-easm-discovery",
        "passive-external-infrastructure",
        "passive-external-osint-recon",
        "passive-identity-ldap-enum",
        "passive-lan-infrastructure-audit",
        "passive-lan-iot-discovery",
        "passive-lan-ipv6-discovery",
        "passive-lan-nse-full",
        "passive-lan-segmentation-check",
        "passive-lan-smart-home-audit",
        "passive-lan-smb-enum",
        "passive-lan-snmp-enum",
        "passive-mobile-android-static",
        "passive-network-discovery",
        "passive-network-service-enumeration",
        "passive-web-baseline",
        "passive-web-burp",
        "passive-web-nikto-scan",
        "passive-web-nuclei-audit",
        "passive-wifi-survey",
    ]


def test_playwright_web_passive_profile_queues_browser_task_with_session_binding(client) -> None:
    engagement_id = create_engagement_with_url_scope(client, "https://app.example.test")

    response = client.post(
        f"/api/v1/engagements/{engagement_id}/runs",
        headers={"X-Actor": "operator"},
        json={
            "profile_name": "passive-browser-recon",
            "configuration_json": {
                "access": {
                    "accounts": [
                        {
                            "label": "Portal Session",
                            "role": "User",
                            "session_ref": "sessionid=test-browser-session",
                        }
                    ]
                }
            },
        },
    )

    assert response.status_code == 201
    payload = response.json()
    assert payload["status"] == "queued"
    assert len(payload["tasks"]) == 1
    task = payload["tasks"][0]
    assert task["tool"] == "playwright-web"
    assert task["target_id"] == "https://app.example.test"
    assert task["params_json"]["mode"] == "passive"
    assert task["params_json"]["auth_contexts"][0]["secret_bindings"]["session"][
        "secret_kind"
    ] == "session"
    assert "test-browser-session" not in json.dumps(task["params_json"])


def test_api_assessment_profile_uses_approval_gate_and_queues_api_task(client) -> None:
    engagement_id = create_engagement_with_url_scope(
        client,
        "https://api.example.test",
    )

    response = client.post(
        f"/api/v1/engagements/{engagement_id}/runs",
        headers={"X-Actor": "operator"},
        json={
            "profile_name": "active-api-assessment",
            "configuration_json": {
                "api_assessment": {
                    "openapi_spec": {
                        "openapi": "3.0.3",
                        "servers": [{"url": "https://api.example.test"}],
                        "paths": {"/users/{id}": {"get": {"responses": {"200": {}}}}},
                    }
                },
                "access": {
                    "accounts": [
                        {
                            "label": "API User",
                            "role": "User",
                            "bearer_token_ref": "api-token-secret",
                        }
                    ]
                },
            },
        },
    )

    assert response.status_code == 201
    payload = response.json()
    assert payload["status"] == "pending_approval"
    assert payload["approval_step_id"] == "active-api-assessment"
    assert payload["tasks"] == []

    approval_response = client.post(
        f"/api/v1/runs/{payload['id']}/approvals",
        headers={"X-Actor": "approver"},
        json={"step_id": "active-api-assessment", "decision": "approved"},
    )

    assert approval_response.status_code == 200
    approved_payload = approval_response.json()
    assert approved_payload["status"] == "queued"
    task = approved_payload["tasks"][0]
    assert task["tool"] == "api-assessment"
    assert task["target_id"] == "https://api.example.test"
    assert task["params_json"]["openapi_spec"]["openapi"] == "3.0.3"
    assert task["params_json"]["auth_contexts"][0]["secret_bindings"]["bearer_token"][
        "secret_kind"
    ] == "bearer_token"
    assert "api-token-secret" not in json.dumps(task["params_json"])


def test_api_assessment_rejects_configured_target_outside_scope(client) -> None:
    engagement_id = create_engagement_with_url_scope(client, "https://api.example.test")

    response = client.post(
        f"/api/v1/engagements/{engagement_id}/runs",
        headers={"X-Actor": "operator"},
        json={
            "profile_name": "active-api-assessment",
            "configuration_json": {
                "targets": {"api_base_urls": ["https://evil.example.test"]},
                "api_assessment": {
                    "openapi_spec": {
                        "openapi": "3.0.3",
                        "paths": {"/health": {"get": {"responses": {"200": {}}}}},
                    }
                },
            },
        },
    )

    assert response.status_code == 409
    assert "outside the approved engagement scope" in response.json()["detail"]


def test_mobile_android_static_profile_queues_authorized_apk_task(client) -> None:
    apk_path = "/tmp/aegispt/mobile/demo.apk"
    engagement_id = create_engagement_with_mobile_scope(client, apk_path)

    response = client.post(
        f"/api/v1/engagements/{engagement_id}/runs",
        headers={"X-Actor": "operator"},
        json={
            "profile_name": "passive-mobile-android-static",
            "configuration_json": {
                "mobile_android": {
                    "proxy_metadata": {"proxy": "http://127.0.0.1:8080"},
                    "dynamic_prerequisites": {"device_available": False},
                }
            },
        },
    )

    assert response.status_code == 201
    payload = response.json()
    assert payload["status"] == "queued"
    assert len(payload["tasks"]) == 1
    task = payload["tasks"][0]
    assert task["tool"] == "mobile-android"
    assert task["target_id"] == apk_path
    assert task["params_json"]["apk_path"] == apk_path
    assert task["params_json"]["target_kind"] == "mobile-artifact"
    assert task["params_json"]["proxy_metadata"]["proxy"] == "http://127.0.0.1:8080"
    assert task["params_json"]["dynamic_prerequisites"]["device_available"] is False


def test_mobile_android_static_profile_rejects_missing_apk_scope(client) -> None:
    engagement_id = create_engagement_with_url_scope(client, "https://app.example.test")

    response = client.post(
        f"/api/v1/engagements/{engagement_id}/runs",
        headers={"X-Actor": "operator"},
        json={"profile_name": "passive-mobile-android-static"},
    )

    assert response.status_code == 409
    assert "authorized APK artifact" in response.json()["detail"]


def test_mobile_android_static_profile_rejects_configured_apk_outside_scope(client) -> None:
    engagement_id = create_engagement_with_mobile_scope(client, "/tmp/aegispt/mobile/demo.apk")

    response = client.post(
        f"/api/v1/engagements/{engagement_id}/runs",
        headers={"X-Actor": "operator"},
        json={
            "profile_name": "passive-mobile-android-static",
            "configuration_json": {
                "targets": {"apk_paths": ["/tmp/aegispt/mobile/evil.apk"]},
            },
        },
    )

    assert response.status_code == 409
    assert "outside the approved engagement scope" in response.json()["detail"]


def test_desktop_client_profile_queues_authorized_artifact_and_helper_tasks(client) -> None:
    artifact_path = "/tmp/aegispt/desktop/operator.zip"
    helper_url = "http://127.0.0.1:4372"
    engagement_id = create_engagement_with_desktop_scope(
        client,
        artifact_path=artifact_path,
        helper_url=helper_url,
    )

    response = client.post(
        f"/api/v1/engagements/{engagement_id}/runs",
        headers={"X-Actor": "operator"},
        json={
            "profile_name": "passive-desktop-client-static",
            "configuration_json": {
                "desktop_client": {
                    "desktop_metadata": {
                        "artifact": artifact_path,
                        "code_signing_verified": False,
                    }
                }
            },
        },
    )

    assert response.status_code == 201
    payload = response.json()
    assert payload["status"] == "queued"
    assert {task["tool"] for task in payload["tasks"]} == {"desktop-client"}
    assert {task["target_id"] for task in payload["tasks"]} == {artifact_path, helper_url}
    artifact_task = next(task for task in payload["tasks"] if task["target_id"] == artifact_path)
    helper_task = next(task for task in payload["tasks"] if task["target_id"] == helper_url)
    assert artifact_task["params_json"]["artifact_paths"] == [artifact_path]
    assert artifact_task["params_json"]["desktop_metadata"]["code_signing_verified"] is False
    assert helper_task["params_json"]["helper_urls"] == [helper_url]


def test_desktop_client_profile_rejects_missing_desktop_scope(client) -> None:
    engagement_id = create_engagement_with_url_scope(client, "https://app.example.test")

    response = client.post(
        f"/api/v1/engagements/{engagement_id}/runs",
        headers={"X-Actor": "operator"},
        json={"profile_name": "passive-desktop-client-static"},
    )

    assert response.status_code == 409
    assert "desktop-client requires" in response.json()["detail"]


def test_desktop_client_profile_rejects_configured_artifact_outside_scope(client) -> None:
    engagement_id = create_engagement_with_desktop_scope(
        client,
        artifact_path="/tmp/aegispt/desktop/operator.zip",
    )

    response = client.post(
        f"/api/v1/engagements/{engagement_id}/runs",
        headers={"X-Actor": "operator"},
        json={
            "profile_name": "passive-desktop-client-static",
            "configuration_json": {
                "targets": {"desktop_artifact_paths": ["/tmp/aegispt/desktop/evil.zip"]},
            },
        },
    )

    assert response.status_code == 409
    assert "outside the approved engagement scope" in response.json()["detail"]


def test_cloud_native_profile_queues_manifest_and_image_tasks(client) -> None:
    manifest_path = "/tmp/aegispt/k8s/app.yaml"
    image_ref = "registry.example/app:latest"
    engagement_id = create_engagement_with_cloud_native_scope(
        client,
        manifest_path=manifest_path,
        image_ref=image_ref,
    )

    response = client.post(
        f"/api/v1/engagements/{engagement_id}/runs",
        headers={"X-Actor": "operator"},
        json={
            "profile_name": "passive-cloud-native-assessment",
            "configuration_json": {
                "cloud_native": {
                    "provider": "kubernetes",
                    "image_metadata": [
                        {
                            "image": image_ref,
                            "base_image": "ubuntu:latest",
                            "user": "root",
                        }
                    ],
                    "cluster_posture": {"cluster_id": "prod-k8s", "rbac_enabled": True},
                }
            },
        },
    )

    assert response.status_code == 201
    payload = response.json()
    assert payload["status"] == "queued"
    assert {task["tool"] for task in payload["tasks"]} == {"cloud-native"}
    assert {task["target_id"] for task in payload["tasks"]} == {manifest_path, image_ref}
    manifest_task = next(task for task in payload["tasks"] if task["target_id"] == manifest_path)
    image_task = next(task for task in payload["tasks"] if task["target_id"] == image_ref)
    assert manifest_task["params_json"]["manifest_paths"] == [manifest_path]
    assert manifest_task["params_json"]["provider"] == "kubernetes"
    assert image_task["params_json"]["image_metadata"][0]["image"] == image_ref
    assert image_task["params_json"]["cluster_posture"]["cluster_id"] == "prod-k8s"


def test_cloud_native_profile_rejects_missing_cloud_native_scope(client) -> None:
    engagement_id = create_engagement_with_url_scope(client, "https://app.example.test")

    response = client.post(
        f"/api/v1/engagements/{engagement_id}/runs",
        headers={"X-Actor": "operator"},
        json={"profile_name": "passive-cloud-native-assessment"},
    )

    assert response.status_code == 409
    assert "cloud-native requires" in response.json()["detail"]


def test_cloud_native_profile_rejects_configured_manifest_outside_scope(client) -> None:
    engagement_id = create_engagement_with_cloud_native_scope(
        client,
        manifest_path="/tmp/aegispt/k8s/app.yaml",
        image_ref="registry.example/app:latest",
    )

    response = client.post(
        f"/api/v1/engagements/{engagement_id}/runs",
        headers={"X-Actor": "operator"},
        json={
            "profile_name": "passive-cloud-native-assessment",
            "configuration_json": {
                "targets": {"kubernetes_manifest_paths": ["/tmp/aegispt/k8s/evil.yaml"]}
            },
        },
    )

    assert response.status_code == 409
    assert "outside the approved engagement scope" in response.json()["detail"]


def test_cicd_security_profile_queues_pipeline_and_repository_tasks(client) -> None:
    pipeline_path = "/tmp/aegispt/pipelines/build.yml"
    repository = "acme/repo"
    engagement_id = create_engagement_with_cicd_scope(
        client,
        pipeline_path=pipeline_path,
        repository=repository,
    )

    response = client.post(
        f"/api/v1/engagements/{engagement_id}/runs",
        headers={"X-Actor": "operator"},
        json={
            "profile_name": "passive-cicd-security-assessment",
            "configuration_json": {
                "cicd_security": {
                    "repository_metadata": {
                        "repository": repository,
                        "branch_protection_enabled": False,
                        "secret_scanning_enabled": False,
                    }
                }
            },
        },
    )

    assert response.status_code == 201
    payload = response.json()
    assert payload["status"] == "queued"
    assert {task["tool"] for task in payload["tasks"]} == {"cicd-security"}
    assert {task["target_id"] for task in payload["tasks"]} == {pipeline_path, repository}
    pipeline_task = next(task for task in payload["tasks"] if task["target_id"] == pipeline_path)
    repository_task = next(task for task in payload["tasks"] if task["target_id"] == repository)
    assert pipeline_task["params_json"]["pipeline_paths"] == [pipeline_path]
    assert pipeline_task["params_json"]["repository_metadata"]["repository"] == repository
    assert repository_task["params_json"]["repository_metadata"]["repository"] == repository


def test_cicd_security_profile_rejects_missing_cicd_scope(client) -> None:
    engagement_id = create_engagement_with_url_scope(client, "https://app.example.test")

    response = client.post(
        f"/api/v1/engagements/{engagement_id}/runs",
        headers={"X-Actor": "operator"},
        json={"profile_name": "passive-cicd-security-assessment"},
    )

    assert response.status_code == 409
    assert "cicd-security requires" in response.json()["detail"]


def test_cicd_security_profile_rejects_configured_pipeline_outside_scope(client) -> None:
    engagement_id = create_engagement_with_cicd_scope(
        client,
        pipeline_path="/tmp/aegispt/pipelines/build.yml",
        repository="acme/repo",
    )

    response = client.post(
        f"/api/v1/engagements/{engagement_id}/runs",
        headers={"X-Actor": "operator"},
        json={
            "profile_name": "passive-cicd-security-assessment",
            "configuration_json": {
                "targets": {"pipeline_config_paths": ["/tmp/aegispt/pipelines/evil.yml"]}
            },
        },
    )

    assert response.status_code == 409
    assert "outside the approved engagement scope" in response.json()["detail"]


def test_playwright_web_active_profile_uses_approval_gate(client) -> None:
    engagement_id = create_engagement_with_url_scope(client, "https://app.example.test")

    response = client.post(
        f"/api/v1/engagements/{engagement_id}/runs",
        headers={"X-Actor": "operator"},
        json={"profile_name": "active-browser-validation"},
    )

    assert response.status_code == 201
    payload = response.json()
    assert payload["status"] == "pending_approval"
    assert payload["approval_step_id"] == "active-browser-validation"
    assert payload["tasks"] == []

    approval_response = client.post(
        f"/api/v1/runs/{payload['id']}/approvals",
        headers={"X-Actor": "approver"},
        json={"step_id": "active-browser-validation", "decision": "approved"},
    )

    assert approval_response.status_code == 200
    approved_payload = approval_response.json()
    assert approved_payload["status"] == "queued"
    assert approved_payload["tasks"][0]["tool"] == "playwright-web"
    assert approved_payload["tasks"][0]["params_json"]["mode"] == "active"
    assert approved_payload["tasks"][0]["params_json"]["proof_marker"]


def test_playwright_web_rejects_configured_target_outside_scope(client) -> None:
    engagement_id = create_engagement_with_url_scope(client, "https://app.example.test")

    response = client.post(
        f"/api/v1/engagements/{engagement_id}/runs",
        headers={"X-Actor": "operator"},
        json={
            "profile_name": "passive-browser-recon",
            "configuration_json": {"targets": {"urls": ["https://evil.example.test"]}},
        },
    )

    assert response.status_code == 409
    assert "outside the approved engagement scope" in response.json()["detail"]


def test_delete_run_dry_run_soft_deletes_excludes_and_audits(client) -> None:
    from api.app.models import AuditEvent, Run

    engagement_id = create_engagement_with_scope(client)
    create_response = client.post(
        f"/api/v1/engagements/{engagement_id}/runs",
        headers={"X-Actor": "tester"},
        json={"profile_name": "passive-web-baseline"},
    )
    assert create_response.status_code == 201
    run_id = create_response.json()["id"]
    _attach_delete_impact_records(client, run_id)

    preview_response = client.delete(
        f"/api/v1/runs/{run_id}?dry_run=true",
        headers={"X-Actor": "tester"},
    )
    assert preview_response.status_code == 200
    preview = preview_response.json()
    assert preview["dry_run"] is True
    assert preview["counts"]["runs"] == 1
    assert preview["counts"]["tasks"] >= 1
    assert preview["counts"]["findings"] == 1
    assert preview["counts"]["artifacts"] == 1
    assert preview["counts"]["remediation_records"] == 1
    assert preview["counts"]["ai_enrichments"] == 1
    assert preview["counts"]["chain_detections"] == 1
    assert preview["counts"]["agent_proposals"] == 1
    assert preview["deleted_at"] is None

    delete_response = client.delete(f"/api/v1/runs/{run_id}", headers={"X-Actor": "tester"})
    assert delete_response.status_code == 200
    deleted = delete_response.json()
    assert deleted["dry_run"] is False
    assert deleted["deleted_ids"] == [run_id]
    assert deleted["deleted_at"]

    assert client.get(f"/api/v1/runs/{run_id}").status_code == 404
    runs_response = client.get(f"/api/v1/engagements/{engagement_id}/runs")
    assert runs_response.status_code == 200
    assert run_id not in {run["id"] for run in runs_response.json()}

    with client.app.state.session_factory() as session:
        stored_run = session.get(Run, UUID(run_id))
        assert stored_run is not None
        assert stored_run.deleted_at is not None
        audit = session.scalar(
            select(AuditEvent).where(
                AuditEvent.object_id == run_id,
                AuditEvent.action == "run.deleted",
            )
        )
        assert audit is not None
        assert audit.metadata_json["item_count"] >= preview["total_items"]
        assert audit.metadata_json["counts"]["findings"] == 1


def test_delete_running_run_returns_conflict(client) -> None:
    from api.app.models import Run

    engagement_id = create_engagement_with_scope(client)
    create_response = client.post(
        f"/api/v1/engagements/{engagement_id}/runs",
        headers={"X-Actor": "tester"},
        json={"profile_name": "passive-web-baseline"},
    )
    assert create_response.status_code == 201
    run_id = create_response.json()["id"]

    with client.app.state.session_factory() as session:
        run = session.get(Run, UUID(run_id))
        assert run is not None
        run.status = "running"
        run.tasks[0].status = "running"
        session.commit()

    response = client.delete(f"/api/v1/runs/{run_id}", headers={"X-Actor": "tester"})
    assert response.status_code == 409
    assert response.json()["detail"] == "Stop the run before deleting"

    preview_response = client.delete(
        f"/api/v1/runs/{run_id}?dry_run=true",
        headers={"X-Actor": "tester"},
    )
    assert preview_response.status_code == 200
    assert preview_response.json()["blocked"] is True


def test_bulk_delete_runs_uses_same_preview_and_soft_delete(client) -> None:
    engagement_id = create_engagement_with_scope(client)
    run_ids: list[str] = []
    for _index in range(2):
        response = client.post(
            f"/api/v1/engagements/{engagement_id}/runs",
            headers={"X-Actor": "tester"},
            json={"profile_name": "passive-web-baseline"},
        )
        assert response.status_code == 201
        run_ids.append(response.json()["id"])

    preview_response = client.request(
        "DELETE",
        "/api/v1/runs?dry_run=true",
        headers={"X-Actor": "tester"},
        json={"run_ids": run_ids},
    )
    assert preview_response.status_code == 200
    assert preview_response.json()["counts"]["runs"] == 2

    delete_response = client.request(
        "DELETE",
        "/api/v1/runs",
        headers={"X-Actor": "tester"},
        json={"run_ids": run_ids},
    )
    assert delete_response.status_code == 200
    assert set(delete_response.json()["deleted_ids"]) == set(run_ids)

    runs_response = client.get(f"/api/v1/engagements/{engagement_id}/runs")
    assert runs_response.status_code == 200
    assert {run["id"] for run in runs_response.json()}.isdisjoint(run_ids)


def test_soft_deleted_run_retention_purge_hard_deletes_expired_run(client) -> None:
    from api.app.models import AuditEvent, Run
    from api.app.services.soft_delete import purge_expired_soft_deleted_runs

    engagement_id = create_engagement_with_scope(client)
    create_response = client.post(
        f"/api/v1/engagements/{engagement_id}/runs",
        headers={"X-Actor": "tester"},
        json={"profile_name": "passive-web-baseline"},
    )
    assert create_response.status_code == 201
    run_id = create_response.json()["id"]
    _attach_delete_impact_records(client, run_id)

    delete_response = client.delete(f"/api/v1/runs/{run_id}", headers={"X-Actor": "tester"})
    assert delete_response.status_code == 200

    with client.app.state.session_factory() as session:
        run = session.get(Run, UUID(run_id))
        assert run is not None
        run.deleted_at = datetime.now(tz=UTC) - timedelta(days=31)
        session.commit()

    with client.app.state.session_factory() as session:
        result = purge_expired_soft_deleted_runs(session=session, actor="retention-test")
        session.commit()

    assert result["purged_runs"] == 1
    assert result["counts"]["runs"] == 1
    assert result["counts"]["tasks"] >= 1
    assert result["counts"]["findings"] == 1

    with client.app.state.session_factory() as session:
        assert session.get(Run, UUID(run_id)) is None
        audit = session.scalar(
            select(AuditEvent).where(
                AuditEvent.action == "soft_delete.retention_purged",
                AuditEvent.object_type == "runs",
            )
        )
        assert audit is not None
        assert run_id in audit.metadata_json["purged_run_ids"]


def test_active_ad_kerberoast_profile_queues_candidate_accounts_from_source_inventory(
    client,
) -> None:
    from api.app.models import InventorySnapshot

    engagement_id = create_engagement_with_directory_scope(
        client,
        "corp.example",
        "dc01.corp.example",
    )

    with client.app.state.session_factory() as session:
        inventory_snapshot = InventorySnapshot(
            engagement_id=UUID(engagement_id),
            requested_by="planner",
            status="completed",
            source_tools_json=["ldap-enum"],
            raw_inputs_json={
                "credential_attack_context": {
                    "domains": ["corp.example"],
                    "kerberoastable_accounts": [
                        {
                            "account_name": "svc-sql",
                            "user_principal_name": "svc-sql@corp.example",
                            "service_principal_names": ["MSSQLSvc/sql01.corp.example:1433"],
                            "privilege_level": "service",
                        }
                    ],
                    "asrep_roastable_accounts": [],
                    "password_policy": {"lockout_threshold": 5},
                    "privileged_names": [],
                }
            },
            normalized_inventory_json={"privileged_memberships": []},
            summary_json={},
            environment_notes_json=[],
            assumptions_json=[],
            confidence_score=0.82,
        )
        session.add(inventory_snapshot)
        session.commit()
        inventory_id = str(inventory_snapshot.id)

    response = client.post(
        f"/api/v1/engagements/{engagement_id}/runs",
        headers={"X-Actor": "operator"},
        json={
            "profile_name": "active-ad-kerberoast",
            "source_inventory_snapshot_id": inventory_id,
            "configuration_json": {
                "credential_attacks": {"domain": "corp.example"},
                "access": {
                    "accounts": [
                        {
                            "label": "Read-only AD",
                            "username": "alice@corp.example",
                            "secret_ref": "Password123!",
                        }
                    ]
                },
            },
        },
    )

    assert response.status_code == 201
    payload = response.json()
    assert payload["status"] == "pending_approval"
    assert payload["approval_step_id"] == "active-ad-credential-attacks"
    assert payload["tasks"] == []

    approval_response = client.post(
        f"/api/v1/runs/{payload['id']}/approvals",
        headers={"X-Actor": "approver"},
        json={"step_id": "active-ad-credential-attacks", "decision": "approved"},
    )
    assert approval_response.status_code == 200
    approved_payload = approval_response.json()
    assert approved_payload["status"] == "queued"
    task_params = approved_payload["tasks"][0]["params_json"]
    assert task_params["mode"] == "kerberoast"
    assert task_params["candidate_accounts"][0]["account_name"] == "svc-sql"
    assert task_params["candidate_accounts"][0]["privilege_level"] == "service"
    assert (
        task_params["auth_contexts"][0]["secret_bindings"]["password"]["secret_kind"] == "password"
    )


def test_passive_external_infrastructure_profile_queues_single_multi_target_task(client) -> None:
    engagement_id = create_engagement_with_external_infra_scope(
        client,
        domains=["example.com"],
        cidrs=["203.0.113.0/28"],
        hosts=["203.0.113.10"],
    )

    response = client.post(
        f"/api/v1/engagements/{engagement_id}/runs",
        headers={"X-Actor": "operator"},
        json={"profile_name": "passive-external-infrastructure"},
    )

    assert response.status_code == 201
    payload = response.json()
    assert payload["status"] == "queued"
    assert len(payload["tasks"]) == 1
    task = payload["tasks"][0]
    assert task["tool"] == "external-infra"
    assert task["params_json"]["mode"] == "passive"
    assert task["params_json"]["targets"] == [
        "example.com",
        "203.0.113.0/28",
        "203.0.113.10",
    ]


def test_active_external_infrastructure_profile_requires_approval_then_queues_active_task(
    client,
) -> None:
    engagement_id = create_engagement_with_external_infra_scope(
        client,
        domains=["example.com"],
        cidrs=["203.0.113.0/28"],
    )

    create_response = client.post(
        f"/api/v1/engagements/{engagement_id}/runs",
        headers={"X-Actor": "operator"},
        json={"profile_name": "active-external-infrastructure"},
    )

    assert create_response.status_code == 201
    created_payload = create_response.json()
    assert created_payload["status"] == "pending_approval"
    assert created_payload["tasks"] == []
    assert created_payload["required_approvals"] == 1

    approval_response = client.post(
        f"/api/v1/runs/{created_payload['id']}/approvals",
        headers={"X-Actor": "approver"},
        json={"step_id": "run.launch", "decision": "approved"},
    )

    assert approval_response.status_code == 200
    approval_payload = approval_response.json()
    assert approval_payload["status"] == "queued"
    assert len(approval_payload["tasks"]) == 1
    task = approval_payload["tasks"][0]
    assert task["tool"] == "external-infra"
    assert task["params_json"]["mode"] == "active"
    assert task["params_json"]["include_passive_smb"] is True


def test_iot_default_creds_profile_requires_approval_and_passes_inventory(client) -> None:
    from api.app.models import InventorySnapshot

    engagement_id = create_engagement_with_host_scope(client, ["10.0.20.10"])

    with client.app.state.session_factory() as session:
        inventory_snapshot = InventorySnapshot(
            engagement_id=UUID(engagement_id),
            requested_by="planner",
            status="completed",
            source_tools_json=["mdns-ssdp"],
            raw_inputs_json={},
            normalized_inventory_json={
                "hosts": [{"host": "10.0.20.10", "source": "mdns-ssdp"}],
                "services": [
                    {
                        "host": "10.0.20.10",
                        "port": 80,
                        "protocol": "tcp",
                        "service": "http",
                        "product": "UniFi Network",
                    }
                ],
                "http_endpoints": [{"url": "http://10.0.20.10/", "title": "UniFi Network"}],
                "vendor_product_fingerprints": [
                    {"vendor": "Ubiquiti", "product": "UniFi", "confidence": 0.8}
                ],
            },
            summary_json={},
            environment_notes_json=[],
            assumptions_json=[],
            confidence_score=0.84,
        )
        session.add(inventory_snapshot)
        session.commit()
        inventory_id = str(inventory_snapshot.id)

    create_response = client.post(
        f"/api/v1/engagements/{engagement_id}/runs",
        headers={"X-Actor": "operator"},
        json={
            "profile_name": "active-lan-default-creds-audit",
            "source_inventory_snapshot_id": inventory_id,
        },
    )

    assert create_response.status_code == 201
    created_payload = create_response.json()
    assert created_payload["status"] == "pending_approval"
    assert created_payload["approval_step_id"] == "active-lan-default-creds-audit"
    assert created_payload["tasks"] == []

    approval_response = client.post(
        f"/api/v1/runs/{created_payload['id']}/approvals",
        headers={"X-Actor": "approver"},
        json={"step_id": "active-lan-default-creds-audit", "decision": "approved"},
    )

    assert approval_response.status_code == 200
    approval_payload = approval_response.json()
    assert approval_payload["status"] == "queued"
    task = approval_payload["tasks"][0]
    assert task["tool"] == "iot-default-creds"
    assert task["params_json"]["source_inventory_snapshot_id"] == inventory_id
    assert task["params_json"]["inventory"]["http_endpoints"][0]["url"] == "http://10.0.20.10/"
    assert task["params_json"]["max_attempts_per_host"] == 3
    assert task["params_json"]["rate_limit_per_second"] == 1.0
    nmap_task = next(task for task in approval_payload["tasks"] if task["tool"] == "nmap")
    limits = nmap_task["params_json"]["limits"]
    assert limits["required_approvals"] == 1
    assert limits["scripts"] == [
        "http-default-accounts",
        "telnet-brute",
        "ftp-brute",
        "http-auth-finder",
    ]
    assert limits["script_args"]["brute.firstonly"] == "true"
    assert limits["script_args"]["unpwdb.timelimit"] == "15s"
    assert nmap_task["params_json"]["target_kind"] == "host"


def test_camera_audit_profile_requires_approval_and_queues_read_only_task(client) -> None:
    from api.app.models import InventorySnapshot

    engagement_id = create_engagement_with_cidr_scope(client, "10.0.20.0/30")

    with client.app.state.session_factory() as session:
        inventory_snapshot = InventorySnapshot(
            engagement_id=UUID(engagement_id),
            requested_by="planner",
            status="completed",
            source_tools_json=["nmap"],
            raw_inputs_json={},
            normalized_inventory_json={
                "hosts": [{"host": "10.0.20.10", "source": "nmap"}],
                "services": [
                    {"host": "10.0.20.10", "port": 554, "service": "rtsp"},
                    {"host": "10.0.20.10", "port": 80, "service": "camera-http"},
                ],
            },
            summary_json={},
            environment_notes_json=[],
            assumptions_json=[],
            confidence_score=0.78,
        )
        session.add(inventory_snapshot)
        session.commit()
        inventory_id = str(inventory_snapshot.id)

    create_response = client.post(
        f"/api/v1/engagements/{engagement_id}/runs",
        headers={"X-Actor": "operator"},
        json={
            "profile_name": "active-lan-camera-audit",
            "source_inventory_snapshot_id": inventory_id,
        },
    )

    assert create_response.status_code == 201
    created_payload = create_response.json()
    assert created_payload["status"] == "pending_approval"
    assert created_payload["approval_step_id"] == "active-lan-camera-audit"
    assert created_payload["tasks"] == []

    approval_response = client.post(
        f"/api/v1/runs/{created_payload['id']}/approvals",
        headers={"X-Actor": "approver"},
        json={"step_id": "active-lan-camera-audit", "decision": "approved"},
    )

    assert approval_response.status_code == 200
    approval_payload = approval_response.json()
    assert approval_payload["status"] == "queued"
    assert len(approval_payload["tasks"]) == 1
    task = approval_payload["tasks"][0]
    assert task["tool"] == "camera-test"
    assert task["target_id"] == "10.0.20.0/30"
    assert task["params_json"]["source_inventory_snapshot_id"] == inventory_id
    assert task["params_json"]["inventory"]["hosts"][0]["host"] == "10.0.20.10"
    assert task["params_json"]["read_only"] is True
    assert task["params_json"]["rtsp_methods"] == ["OPTIONS", "DESCRIBE"]
    assert task["params_json"]["rtsp_setup_performed"] is False
    assert task["params_json"]["rtsp_play_performed"] is False
    assert task["params_json"]["video_frame_storage"] is False
    assert task["params_json"]["video_frame_captured"] is False
    assert task["params_json"]["ptz_control"] is False
    assert task["params_json"]["configuration_changes"] is False
    assert task["params_json"]["default_credentials_bounded"] is True
    assert task["params_json"]["max_default_credential_attempts"] == 10
    assert task["params_json"]["max_target_hosts"] == 128


def test_network_segmentation_profiles_pass_inventory_and_authorization_boundaries(client) -> None:
    from api.app.models import InventorySnapshot

    engagement_id = create_engagement_with_cidr_scope(client, "10.0.20.0/24")

    with client.app.state.session_factory() as session:
        inventory_snapshot = InventorySnapshot(
            engagement_id=UUID(engagement_id),
            requested_by="planner",
            status="completed",
            source_tools_json=["nmap", "mdns-ssdp"],
            raw_inputs_json={},
            normalized_inventory_json={
                "services": [{"host": "10.0.20.1", "port": 161, "service": "snmp"}],
                "routes": [{"destination_cidr": "192.168.10.0/24", "gateway": "10.0.20.1"}],
            },
            summary_json={},
            environment_notes_json=[],
            assumptions_json=[],
            confidence_score=0.77,
        )
        session.add(inventory_snapshot)
        session.commit()
        inventory_id = str(inventory_snapshot.id)

    passive_response = client.post(
        f"/api/v1/engagements/{engagement_id}/runs",
        headers={"X-Actor": "operator"},
        json={
            "profile_name": "passive-lan-segmentation-check",
            "source_inventory_snapshot_id": inventory_id,
        },
    )

    assert passive_response.status_code == 201
    passive_payload = passive_response.json()
    assert passive_payload["status"] == "queued"
    passive_task = passive_payload["tasks"][0]
    assert passive_task["tool"] == "network-segmentation"
    assert passive_task["params_json"]["mode"] == "passive"
    assert passive_task["params_json"]["source_inventory_snapshot_id"] == inventory_id
    assert passive_task["params_json"]["inventory"]["routes"][0]["destination_cidr"] == "192.168.10.0/24"

    active_response = client.post(
        f"/api/v1/engagements/{engagement_id}/runs",
        headers={"X-Actor": "operator"},
        json={
            "profile_name": "active-lan-segmentation-test",
            "source_inventory_snapshot_id": inventory_id,
            "configuration_json": {"native_vlan": 1, "target_vlan": 20, "vlan_interface": "eth0"},
        },
    )

    assert active_response.status_code == 201
    active_payload = active_response.json()
    assert active_payload["status"] == "pending_approval"
    assert active_payload["approval_step_id"] == "active-lan-segmentation-test"
    assert active_payload["tasks"] == []

    approval_response = client.post(
        f"/api/v1/runs/{active_payload['id']}/approvals",
        headers={"X-Actor": "approver"},
        json={"step_id": "active-lan-segmentation-test", "decision": "approved"},
    )

    assert approval_response.status_code == 200
    approval_payload = approval_response.json()
    active_task = approval_payload["tasks"][0]
    assert active_task["tool"] == "network-segmentation"
    assert active_task["params_json"]["mode"] == "active"
    assert active_task["params_json"]["native_vlan"] == 1
    assert active_task["params_json"]["target_vlan"] == 20
    assert active_task["params_json"]["vlan_interface"] == "eth0"


def test_snmp_enum_profile_queues_read_only_bounded_default_community_task(client) -> None:
    from api.app.models import InventorySnapshot

    engagement_id = create_engagement_with_cidr_scope(client, "10.0.20.0/30")

    with client.app.state.session_factory() as session:
        inventory_snapshot = InventorySnapshot(
            engagement_id=UUID(engagement_id),
            requested_by="planner",
            status="completed",
            source_tools_json=["nmap"],
            raw_inputs_json={},
            normalized_inventory_json={
                "services": [{"host": "10.0.20.1", "port": 161, "service": "snmp"}],
            },
            summary_json={},
            environment_notes_json=[],
            assumptions_json=[],
            confidence_score=0.74,
        )
        session.add(inventory_snapshot)
        session.commit()
        inventory_id = str(inventory_snapshot.id)

    response = client.post(
        f"/api/v1/engagements/{engagement_id}/runs",
        headers={"X-Actor": "operator"},
        json={
            "profile_name": "passive-lan-snmp-enum",
            "source_inventory_snapshot_id": inventory_id,
        },
    )

    assert response.status_code == 201
    payload = response.json()
    assert payload["status"] == "queued"
    assert len(payload["tasks"]) == 1
    task = payload["tasks"][0]
    assert task["tool"] == "snmp-enum"
    assert task["target_id"] == "10.0.20.0/30"
    assert task["params_json"]["read_only"] is True
    assert task["params_json"]["source_inventory_snapshot_id"] == inventory_id
    assert task["params_json"]["inventory"]["services"][0]["port"] == 161
    assert task["params_json"]["community_strings"] == [
        "public",
        "private",
        "community",
        "manager",
        "admin",
        "snmpd",
        "cisco",
        "ubiquiti",
    ]
    assert task["params_json"]["max_target_hosts"] == 256


def test_ipv6_discovery_profile_queues_passive_bounded_task(client) -> None:
    from api.app.models import InventorySnapshot

    engagement_id = create_engagement_with_cidr_scope(client, "10.0.20.0/30")

    with client.app.state.session_factory() as session:
        inventory_snapshot = InventorySnapshot(
            engagement_id=UUID(engagement_id),
            requested_by="planner",
            status="completed",
            source_tools_json=["nmap"],
            raw_inputs_json={},
            normalized_inventory_json={
                "hosts": [{"host": "10.0.20.1", "source": "nmap"}],
                "network_interfaces": [{"mac": "00:11:22:33:44:55"}],
            },
            summary_json={},
            environment_notes_json=[],
            assumptions_json=[],
            confidence_score=0.74,
        )
        session.add(inventory_snapshot)
        session.commit()
        inventory_id = str(inventory_snapshot.id)

    response = client.post(
        f"/api/v1/engagements/{engagement_id}/runs",
        headers={"X-Actor": "operator"},
        json={
            "profile_name": "passive-lan-ipv6-discovery",
            "source_inventory_snapshot_id": inventory_id,
            "configuration_json": {"ipv6_interface": "eth0"},
        },
    )

    assert response.status_code == 201
    payload = response.json()
    assert payload["status"] == "queued"
    assert len(payload["tasks"]) == 1
    task = payload["tasks"][0]
    assert task["tool"] == "ipv6-discovery"
    assert task["target_id"] == "10.0.20.0/30"
    assert task["params_json"]["source_inventory_snapshot_id"] == inventory_id
    assert task["params_json"]["inventory"]["hosts"][0]["host"] == "10.0.20.1"
    assert task["params_json"]["interface"] == "eth0"
    assert task["params_json"]["run_nmap"] is True
    assert task["params_json"]["max_discovered_hosts"] == 128
    assert "8123" in task["params_json"]["ports"]


def test_smart_home_profile_queues_read_only_bounded_task(client) -> None:
    from api.app.models import InventorySnapshot

    engagement_id = create_engagement_with_cidr_scope(client, "10.0.20.0/30")

    with client.app.state.session_factory() as session:
        inventory_snapshot = InventorySnapshot(
            engagement_id=UUID(engagement_id),
            requested_by="planner",
            status="completed",
            source_tools_json=["nmap", "mdns-ssdp"],
            raw_inputs_json={},
            normalized_inventory_json={
                "hosts": [{"host": "10.0.20.44", "source": "mdns-ssdp"}],
                "services": [
                    {"host": "10.0.20.44", "port": 1883, "service": "mqtt"},
                    {"host": "10.0.20.44", "port": 8123, "service": "home-assistant"},
                ],
            },
            summary_json={},
            environment_notes_json=[],
            assumptions_json=[],
            confidence_score=0.72,
        )
        session.add(inventory_snapshot)
        session.commit()
        inventory_id = str(inventory_snapshot.id)

    response = client.post(
        f"/api/v1/engagements/{engagement_id}/runs",
        headers={"X-Actor": "operator"},
        json={
            "profile_name": "passive-lan-smart-home-audit",
            "source_inventory_snapshot_id": inventory_id,
        },
    )

    assert response.status_code == 201
    payload = response.json()
    assert payload["status"] == "queued"
    assert len(payload["tasks"]) == 1
    task = payload["tasks"][0]
    assert task["tool"] == "smart-home"
    assert task["target_id"] == "10.0.20.0/30"
    assert task["params_json"]["source_inventory_snapshot_id"] == inventory_id
    assert task["params_json"]["inventory"]["hosts"][0]["host"] == "10.0.20.44"
    assert task["params_json"]["read_only"] is True
    assert task["params_json"]["mqtt_subscribe_only"] is True
    assert task["params_json"]["mqtt_publish_performed"] is False
    assert task["params_json"]["home_assistant_get_only"] is True
    assert task["params_json"]["device_control_performed"] is False
    assert task["params_json"]["mqtt_listen_seconds"] == 30.0
    assert task["params_json"]["max_target_hosts"] == 128


def test_intrusive_password_spray_requires_lockout_confirmation(client) -> None:
    from api.app.config import get_settings
    from api.app.models import InventorySnapshot, SecretRef
    from api.app.services.secrets import encrypt_secret_value

    engagement_id = create_engagement_with_directory_scope(
        client,
        "corp.example",
        "dc01.corp.example",
    )

    with client.app.state.session_factory() as session:
        password_secret = SecretRef(
            id=uuid4(),
            engagement_id=UUID(engagement_id),
            vault_pointer="aegispt://secret-ref/password-candidate",
            purpose="task.credential_attacks.seed_password",
            secret_kind="password",
            storage_backend="encrypted_local",
            display_label="protected password",
            encrypted_value=encrypt_secret_value("Winter2026!", get_settings()),
            metadata_json={"raw_secret_material_exposed": False},
        )
        inventory_snapshot = InventorySnapshot(
            engagement_id=UUID(engagement_id),
            requested_by="planner",
            status="completed",
            source_tools_json=["ldap-enum"],
            raw_inputs_json={
                "credential_attack_context": {
                    "domains": ["corp.example"],
                    "kerberoastable_accounts": [],
                    "asrep_roastable_accounts": [],
                    "password_policy": {"lockout_threshold": 5},
                    "privileged_names": ["backup-admin@corp.example"],
                }
            },
            normalized_inventory_json={"privileged_memberships": []},
            summary_json={},
            environment_notes_json=[],
            assumptions_json=[],
            confidence_score=0.82,
        )
        session.add(password_secret)
        session.add(inventory_snapshot)
        session.commit()
        inventory_id = str(inventory_snapshot.id)
        password_ref = f"aegispt://secret-ref/{password_secret.id}"

    response = client.post(
        f"/api/v1/engagements/{engagement_id}/runs",
        headers={"X-Actor": "operator"},
        json={
            "profile_name": "intrusive-ad-password-spray",
            "source_inventory_snapshot_id": inventory_id,
            "configuration_json": {
                "credential_attacks": {
                    "spray_accounts": ["backup-admin@corp.example"],
                    "attempts_per_window": 1,
                    "window_minutes": 30,
                    "password_candidates": [{"label": "Seasonal", "password_ref": password_ref}],
                }
            },
        },
    )

    assert response.status_code == 409
    assert "lockout_threshold_confirmed" in response.json()["detail"]

    confirmed_response = client.post(
        f"/api/v1/engagements/{engagement_id}/runs",
        headers={"X-Actor": "operator"},
        json={
            "profile_name": "intrusive-ad-password-spray",
            "source_inventory_snapshot_id": inventory_id,
            "configuration_json": {
                "credential_attacks": {
                    "spray_accounts": ["backup-admin@corp.example"],
                    "attempts_per_window": 1,
                    "window_minutes": 30,
                    "lockout_threshold_confirmed": 5,
                    "password_candidates": [{"label": "Seasonal", "password_ref": password_ref}],
                }
            },
        },
    )

    assert confirmed_response.status_code == 201
    confirmed_payload = confirmed_response.json()
    assert confirmed_payload["status"] == "pending_approval"
    assert confirmed_payload["approval_step_id"] == "intrusive-ad-password-spray"


def test_active_business_logic_profile_rejects_missing_authenticated_accounts(client) -> None:
    engagement_id = create_engagement_with_url_scope(client, "https://portal.example.test")

    response = client.post(
        f"/api/v1/engagements/{engagement_id}/runs",
        headers={"X-Actor": "operator"},
        json={
            "profile_name": "active-business-logic",
            "configuration_json": {
                "targets": {"urls": ["https://portal.example.test"]},
                "access": {
                    "accounts": [
                        {
                            "label": "Manual SSO",
                            "role": "User",
                        }
                    ],
                    "manual_auth_steps": "Operator must complete SSO manually.",
                },
            },
        },
    )

    assert response.status_code == 409
    assert "requires at least one authenticated access account" in response.json()["detail"]


def test_passive_netexec_profile_queues_only_host_targets_without_auth(client) -> None:
    engagement_id = create_engagement_with_host_scope(client, ["10.0.20.25", "10.0.20.26"])

    response = client.post(
        f"/api/v1/engagements/{engagement_id}/runs",
        headers={"X-Actor": "operator"},
        json={"profile_name": "passive-lan-smb-enum"},
    )

    assert response.status_code == 201
    payload = response.json()
    assert payload["status"] == "queued"
    assert payload["required_approvals"] == 0
    assert {task["tool"] for task in payload["tasks"]} == {"netexec"}
    assert {task["target_id"] for task in payload["tasks"]} == {"10.0.20.25", "10.0.20.26"}
    assert all(task["params_json"]["mode"] == "passive" for task in payload["tasks"])
    assert all("auth_contexts" not in task["params_json"] for task in payload["tasks"])
    assert "https://portal.example.test" not in {task["target_id"] for task in payload["tasks"]}


def test_intrusive_netexec_profile_requires_named_approval_gate_and_auth_context(client) -> None:
    engagement_id = create_engagement_with_host_scope(client, ["10.0.20.25"])

    missing_auth = client.post(
        f"/api/v1/engagements/{engagement_id}/runs",
        headers={"X-Actor": "operator"},
        json={"profile_name": "intrusive-lan-smb-auth"},
    )

    assert missing_auth.status_code == 409
    assert "stored password or NTLM hash binding" in missing_auth.json()["detail"]

    create_response = client.post(
        f"/api/v1/engagements/{engagement_id}/runs",
        headers={"X-Actor": "operator"},
        json={
            "profile_name": "intrusive-lan-smb-auth",
            "configuration_json": {
                "targets": {"hosts": ["10.0.20.25"]},
                "access": {
                    "accounts": [
                        {
                            "label": "Backup Admin",
                            "username": "backup-admin",
                            "local_auth": True,
                            "hash_ref": "31d6cfe0d16ae931b73c59d7e0c089c0",
                        }
                    ]
                },
            },
        },
    )

    assert create_response.status_code == 201
    created_payload = create_response.json()
    assert created_payload["status"] == "pending_approval"
    assert created_payload["required_approvals"] == 2
    assert created_payload["approval_step_id"] == "intrusive-lan-smb-auth"

    client.post(
        f"/api/v1/runs/{created_payload['id']}/approvals",
        headers={"X-Actor": "approver-1"},
        json={"step_id": "intrusive-lan-smb-auth", "decision": "approved"},
    )
    approval_response = client.post(
        f"/api/v1/runs/{created_payload['id']}/approvals",
        headers={"X-Actor": "approver-2"},
        json={"step_id": "intrusive-lan-smb-auth", "decision": "approved"},
    )

    assert approval_response.status_code == 200
    approval_payload = approval_response.json()
    assert approval_payload["status"] == "queued"
    task = approval_payload["tasks"][0]
    assert task["tool"] == "netexec"
    assert task["params_json"]["mode"] == "intrusive"
    assert "31d6cfe0d16ae931b73c59d7e0c089c0" not in json.dumps(task["params_json"])
    assert "ntlm_hash" in task["params_json"]["auth_contexts"][0]["secret_bindings"]
    assert task["params_json"]["auth_contexts"][0]["local_auth"] is True


def test_active_business_logic_profile_requires_approval_and_queues_authenticated_task(
    client,
) -> None:
    engagement_id = create_engagement_with_url_scope(client, "https://portal.example.test")

    create_response = client.post(
        f"/api/v1/engagements/{engagement_id}/runs",
        headers={"X-Actor": "operator"},
        json={
            "profile_name": "active-business-logic",
            "configuration_json": {
                "targets": {"urls": ["https://portal.example.test"]},
                "access": {
                    "accounts": [
                        {
                            "label": "Standard User",
                            "username": "alice@example.test",
                            "role": "User",
                            "bearer_token_ref": "business-logic-token",
                            "tenant": "tenant-a",
                            "marker_tokens": ["alice@example.test"],
                        }
                    ]
                },
                "business_logic": {
                    "test_types": ["idor", "privilege_escalation"],
                    "idor_paths": ["/api/orders/{id}"],
                    "admin_paths": ["/admin/users"],
                    "candidate_object_ids": ["101", "202"],
                },
            },
        },
    )

    assert create_response.status_code == 201
    created_payload = create_response.json()
    assert created_payload["status"] == "pending_approval"
    assert created_payload["tasks"] == []
    assert created_payload["pending_approvals"] == 1

    approval_response = client.post(
        f"/api/v1/runs/{created_payload['id']}/approvals",
        headers={"X-Actor": "approver"},
        json={"step_id": "run.launch", "decision": "approved"},
    )

    assert approval_response.status_code == 200
    approval_payload = approval_response.json()
    assert approval_payload["status"] == "queued"
    assert approval_payload["pending_approvals"] == 0
    assert len(approval_payload["tasks"]) == 1
    task = approval_payload["tasks"][0]
    assert task["tool"] == "biz-logic-probe"
    assert task["target_id"] == "https://portal.example.test"
    assert task["params_json"]["test_types"] == ["idor", "privilege_escalation"]
    assert task["params_json"]["idor_paths"] == ["/api/orders/{id}"]
    assert task["params_json"]["admin_paths"] == ["/admin/users"]
    assert task["params_json"]["candidate_object_ids"] == ["101", "202"]
    assert task["params_json"]["auth_contexts"][0]["label"] == "Standard User"
    assert "bearer_token" in task["params_json"]["auth_contexts"][0]["secret_bindings"]


def test_active_idor_bac_profile_requires_approval_and_queues_authenticated_task(
    client,
) -> None:
    engagement_id = create_engagement_with_url_scope(client, "https://portal.example.test/app/")

    create_response = client.post(
        f"/api/v1/engagements/{engagement_id}/runs",
        headers={"X-Actor": "operator"},
        json={
            "profile_name": "active-web-idor-bac",
            "configuration_json": {
                "targets": {"urls": ["https://portal.example.test/app/"]},
                "access": {
                    "accounts": [
                        {
                            "label": "Standard User",
                            "username": "alice@example.test",
                            "role": "User",
                            "bearer_token_ref": "idor-token",
                            "marker_tokens": ["alice@example.test"],
                            "owned_object_ids": ["100"],
                        },
                        {
                            "label": "Peer User",
                            "username": "bob@example.test",
                            "role": "User",
                            "bearer_token_ref": "idor-peer-token",
                            "marker_tokens": ["bob@example.test"],
                            "owned_object_ids": ["120"],
                        },
                    ]
                },
                "idor_bac": {
                    "candidate_paths": ["api/users/100"],
                    "request_contexts": [
                        {
                            "url": "https://portal.example.test/app/settings?role=user",
                            "success_markers": ["admin-panel-ready"],
                        }
                    ],
                    "method_override_paths": ["api/users/100"],
                    "admin_paths": ["admin"],
                    "max_id_delta": 20,
                },
            },
        },
    )

    assert create_response.status_code == 201
    created_payload = create_response.json()
    assert created_payload["status"] == "pending_approval"
    assert created_payload["tasks"] == []
    assert created_payload["pending_approvals"] == 1

    approval_response = client.post(
        f"/api/v1/runs/{created_payload['id']}/approvals",
        headers={"X-Actor": "approver"},
        json={"step_id": "run.launch", "decision": "approved"},
    )

    assert approval_response.status_code == 200
    approval_payload = approval_response.json()
    assert approval_payload["status"] == "queued"
    assert approval_payload["pending_approvals"] == 0
    assert len(approval_payload["tasks"]) == 1
    task = approval_payload["tasks"][0]
    assert task["tool"] == "idor-bac"
    assert task["target_id"] == "https://portal.example.test/app/"
    assert task["params_json"]["candidate_paths"] == ["api/users/100"]
    assert task["params_json"]["method_override_paths"] == ["api/users/100"]
    assert task["params_json"]["admin_paths"] == ["admin"]
    assert task["params_json"]["max_id_delta"] == 20
    assert task["params_json"]["auth_contexts"][0]["label"] == "Standard User"
    assert "bearer_token" in task["params_json"]["auth_contexts"][0]["secret_bindings"]


def test_active_xss_extended_profile_requires_approval_and_queues_task(client) -> None:
    engagement_id = create_engagement_with_url_scope(client, "https://portal.example.test/app/")

    create_response = client.post(
        f"/api/v1/engagements/{engagement_id}/runs",
        headers={"X-Actor": "operator"},
        json={
            "profile_name": "active-web-xss-extended",
            "configuration_json": {
                "targets": {"urls": ["https://portal.example.test/app/"]},
                "xss_extended": {
                    "upload_contexts": [
                        {"url": "upload", "uploaded_url": "uploads/aegispt-xss.html"},
                    ],
                    "ajax_contexts": [
                        {"url": "api/search?q=baseline", "parameters": ["q"]},
                    ],
                    "xssi_contexts": [
                        {"url": "api/profile.json"},
                    ],
                    "candidate_paths": ["api/profile.json"],
                },
            },
        },
    )

    assert create_response.status_code == 201
    created_payload = create_response.json()
    assert created_payload["status"] == "pending_approval"
    assert created_payload["tasks"] == []
    assert created_payload["pending_approvals"] == 1

    approval_response = client.post(
        f"/api/v1/runs/{created_payload['id']}/approvals",
        headers={"X-Actor": "approver"},
        json={"step_id": "run.launch", "decision": "approved"},
    )

    assert approval_response.status_code == 200
    approval_payload = approval_response.json()
    assert approval_payload["status"] == "queued"
    assert approval_payload["pending_approvals"] == 0
    assert len(approval_payload["tasks"]) == 1
    task = approval_payload["tasks"][0]
    assert task["tool"] == "xss-extended"
    assert task["target_id"] == "https://portal.example.test/app/"
    assert task["params_json"]["upload_contexts"] == [
        {"url": "upload", "uploaded_url": "uploads/aegispt-xss.html"},
    ]
    assert task["params_json"]["ajax_contexts"] == [
        {"url": "api/search?q=baseline", "parameters": ["q"]},
    ]
    assert task["params_json"]["xssi_contexts"] == [{"url": "api/profile.json"}]
    assert task["params_json"]["candidate_paths"] == ["api/profile.json"]


def test_active_ssrf_probe_profile_requires_approval_and_queues_task(client) -> None:
    engagement_id = create_engagement_with_url_scope(client, "https://portal.example.test/app/")

    create_response = client.post(
        f"/api/v1/engagements/{engagement_id}/runs",
        headers={"X-Actor": "operator"},
        json={
            "profile_name": "active-web-ssrf-probe",
            "configuration_json": {
                "targets": {"urls": ["https://portal.example.test/app/"]},
                "ssrf": {
                    "request_contexts": [
                        {"url": "fetch?url=baseline", "parameters": ["url"]},
                    ],
                    "header_contexts": [
                        {"url": "render", "headers": ["X-Forwarded-Host"]},
                    ],
                    "callback_base_url": "https://callback.example.test/aegispt",
                    "callback_token": "ssrf-token",
                    "oob_confirmation_refs": [
                        {"token": "ssrf-token", "interaction_id": "oob-1"},
                    ],
                    "cloud_metadata_probe_enabled": True,
                    "cloud_hosted": True,
                    "cloud_provider": "aws",
                },
            },
        },
    )

    assert create_response.status_code == 201
    created_payload = create_response.json()
    assert created_payload["status"] == "pending_approval"
    assert created_payload["tasks"] == []
    assert created_payload["pending_approvals"] == 1

    approval_response = client.post(
        f"/api/v1/runs/{created_payload['id']}/approvals",
        headers={"X-Actor": "approver"},
        json={"step_id": "run.launch", "decision": "approved"},
    )

    assert approval_response.status_code == 200
    approval_payload = approval_response.json()
    assert approval_payload["status"] == "queued"
    assert approval_payload["pending_approvals"] == 0
    assert len(approval_payload["tasks"]) == 1
    task = approval_payload["tasks"][0]
    assert task["tool"] == "ssrf-probe"
    assert task["target_id"] == "https://portal.example.test/app/"
    assert task["params_json"]["request_contexts"] == [
        {"url": "fetch?url=baseline", "parameters": ["url"]},
    ]
    assert task["params_json"]["header_contexts"] == [
        {"url": "render", "headers": ["X-Forwarded-Host"]},
    ]
    assert task["params_json"]["callback_base_url"] == "https://callback.example.test/aegispt"
    assert task["params_json"]["callback_token"] == "ssrf-token"
    assert task["params_json"]["cloud_metadata_probe_enabled"] is True
    assert task["params_json"]["cloud_hosted"] is True
    assert task["params_json"]["cloud_provider"] == "aws"


def test_active_deserialization_probe_profile_requires_approval_and_queues_task(client) -> None:
    engagement_id = create_engagement_with_url_scope(client, "https://portal.example.test/app/")

    create_response = client.post(
        f"/api/v1/engagements/{engagement_id}/runs",
        headers={"X-Actor": "operator"},
        json={
            "profile_name": "active-web-deserialization-probe",
            "configuration_json": {
                "targets": {"urls": ["https://portal.example.test/app/"]},
                "deserialization": {
                    "request_contexts": [
                        {
                            "url": "deserialize?data=rO0ABXNy",
                            "parameters": ["data"],
                            "java_serialized_marker": True,
                        }
                    ],
                    "evidence_records": [
                        {
                            "url": "view",
                            "parameters": {"__VIEWSTATE": "/wFTeXN0ZW0uV2ViLlVJ"},
                        }
                    ],
                    "callback_base_url": "https://callback.example.test/aegispt",
                    "callback_token": "deser-token",
                    "oob_confirmation_refs": [
                        {"token": "deser-token", "interaction_id": "dns-1"},
                    ],
                },
            },
        },
    )

    assert create_response.status_code == 201
    created_payload = create_response.json()
    assert created_payload["status"] == "pending_approval"
    assert created_payload["tasks"] == []
    assert created_payload["pending_approvals"] == 1

    approval_response = client.post(
        f"/api/v1/runs/{created_payload['id']}/approvals",
        headers={"X-Actor": "approver"},
        json={"step_id": "run.launch", "decision": "approved"},
    )

    assert approval_response.status_code == 200
    approval_payload = approval_response.json()
    assert approval_payload["status"] == "queued"
    assert approval_payload["pending_approvals"] == 0
    assert len(approval_payload["tasks"]) == 1
    task = approval_payload["tasks"][0]
    assert task["tool"] == "deserialization-probe"
    assert task["target_id"] == "https://portal.example.test/app/"
    assert task["params_json"]["request_contexts"][0]["java_serialized_marker"] is True
    assert task["params_json"]["callback_base_url"] == "https://callback.example.test/aegispt"
    assert task["params_json"]["callback_token"] == "deser-token"
    assert task["params_json"]["oob_confirmation_refs"] == [
        {"token": "deser-token", "interaction_id": "dns-1"},
    ]


def test_active_session_security_profile_requires_approval_and_queues_authenticated_task(client) -> None:
    engagement_id = create_engagement_with_url_scope(client, "https://portal.example.test/app/")

    create_response = client.post(
        f"/api/v1/engagements/{engagement_id}/runs",
        headers={"X-Actor": "operator"},
        json={
            "profile_name": "active-web-session-security",
            "configuration_json": {
                "targets": {"urls": ["https://portal.example.test/app/"]},
                "access": {
                    "accounts": [
                        {
                            "label": "Session User",
                            "username": "alice@example.test",
                            "role": "User",
                            "secret_ref": "CorrectHorseBatteryStaple!",
                        }
                    ]
                },
                "session_security": {
                    "login_url": "login",
                    "logout_url": "logout",
                    "protected_url": "account",
                    "token_sample_url": "token",
                    "username_field": "user",
                    "password_field": "pass",
                    "extra_form_fields": {"csrf": "fixture-token"},
                    "success_markers": ["welcome alice"],
                    "request_contexts": [
                        {"url": "view?sessionid=fixture-token"},
                    ],
                    "sample_count": 4,
                },
            },
        },
    )

    assert create_response.status_code == 201
    created_payload = create_response.json()
    assert created_payload["status"] == "pending_approval"
    assert created_payload["tasks"] == []
    assert created_payload["pending_approvals"] == 1

    approval_response = client.post(
        f"/api/v1/runs/{created_payload['id']}/approvals",
        headers={"X-Actor": "approver"},
        json={"step_id": "run.launch", "decision": "approved"},
    )

    assert approval_response.status_code == 200
    approval_payload = approval_response.json()
    assert approval_payload["status"] == "queued"
    assert approval_payload["pending_approvals"] == 0
    assert len(approval_payload["tasks"]) == 1
    task = approval_payload["tasks"][0]
    assert task["tool"] == "session-security"
    assert task["target_id"] == "https://portal.example.test/app/"
    assert task["params_json"]["login_url"] == "login"
    assert task["params_json"]["logout_url"] == "logout"
    assert task["params_json"]["protected_url"] == "account"
    assert task["params_json"]["token_sample_url"] == "token"
    assert task["params_json"]["username_field"] == "user"
    assert task["params_json"]["password_field"] == "pass"
    assert task["params_json"]["extra_form_fields"] == {"csrf": "fixture-token"}
    assert task["params_json"]["success_markers"] == ["welcome alice"]
    assert task["params_json"]["sample_count"] == 4
    assert task["params_json"]["auth_contexts"][0]["label"] == "Session User"
    assert task["params_json"]["auth_contexts"][0]["username"] == "alice@example.test"
    assert "password" in task["params_json"]["auth_contexts"][0]["secret_bindings"]
    assert "CorrectHorseBatteryStaple!" not in json.dumps(task["params_json"])


def test_active_auth_flow_profile_requires_approval_and_queues_authenticated_task(client) -> None:
    engagement_id = create_engagement_with_url_scope(client, "https://portal.example.test/app/")

    create_response = client.post(
        f"/api/v1/engagements/{engagement_id}/runs",
        headers={"X-Actor": "operator"},
        json={
            "profile_name": "active-web-auth-flow",
            "configuration_json": {
                "targets": {"urls": ["https://portal.example.test/app/"]},
                "access": {
                    "accounts": [
                        {
                            "label": "Auth Flow User",
                            "username": "alice@example.test",
                            "role": "User",
                            "secret_ref": "CorrectHorseBatteryStaple!",
                        }
                    ]
                },
                "auth_flow": {
                    "login_url": "login",
                    "password_reset_url": "reset",
                    "reset_consume_url": "reset/consume",
                    "username_field": "user",
                    "password_field": "pass",
                    "reset_username_field": "email",
                    "reset_token_field": "token",
                    "new_password_field": "new_password",
                    "extra_login_fields": {"csrf": "login-token"},
                    "extra_reset_fields": {"csrf": "reset-token"},
                    "invalid_usernames": ["missing@example.test"],
                    "reset_token_samples": 5,
                    "failed_login_attempts": 10,
                    "reset_poison_host": "evil.example.test",
                },
            },
        },
    )

    assert create_response.status_code == 201
    created_payload = create_response.json()
    assert created_payload["status"] == "pending_approval"
    assert created_payload["tasks"] == []
    assert created_payload["pending_approvals"] == 1

    approval_response = client.post(
        f"/api/v1/runs/{created_payload['id']}/approvals",
        headers={"X-Actor": "approver"},
        json={"step_id": "run.launch", "decision": "approved"},
    )

    assert approval_response.status_code == 200
    approval_payload = approval_response.json()
    assert approval_payload["status"] == "queued"
    assert approval_payload["pending_approvals"] == 0
    assert len(approval_payload["tasks"]) == 1
    task = approval_payload["tasks"][0]
    assert task["tool"] == "auth-flow"
    assert task["target_id"] == "https://portal.example.test/app/"
    assert task["params_json"]["login_url"] == "login"
    assert task["params_json"]["password_reset_url"] == "reset"
    assert task["params_json"]["reset_consume_url"] == "reset/consume"
    assert task["params_json"]["username_field"] == "user"
    assert task["params_json"]["password_field"] == "pass"
    assert task["params_json"]["reset_username_field"] == "email"
    assert task["params_json"]["reset_token_field"] == "token"
    assert task["params_json"]["new_password_field"] == "new_password"
    assert task["params_json"]["extra_login_fields"] == {"csrf": "login-token"}
    assert task["params_json"]["extra_reset_fields"] == {"csrf": "reset-token"}
    assert task["params_json"]["invalid_usernames"] == ["missing@example.test"]
    assert task["params_json"]["reset_token_samples"] == 5
    assert task["params_json"]["failed_login_attempts"] == 10
    assert task["params_json"]["reset_poison_host"] == "evil.example.test"
    assert task["params_json"]["auth_contexts"][0]["label"] == "Auth Flow User"
    assert task["params_json"]["auth_contexts"][0]["username"] == "alice@example.test"
    assert "password" in task["params_json"]["auth_contexts"][0]["secret_bindings"]
    assert "CorrectHorseBatteryStaple!" not in json.dumps(task["params_json"])


def test_active_client_state_profile_requires_approval_and_queues_authenticated_task(client) -> None:
    engagement_id = create_engagement_with_url_scope(client, "https://portal.example.test/app/")

    create_response = client.post(
        f"/api/v1/engagements/{engagement_id}/runs",
        headers={"X-Actor": "operator"},
        json={
            "profile_name": "active-web-client-state",
            "configuration_json": {
                "targets": {"urls": ["https://portal.example.test/app/"]},
                "access": {
                    "accounts": [
                        {
                            "label": "Client State User",
                            "username": "alice@example.test",
                            "role": "User",
                            "session_ref": "session=alice",
                        }
                    ]
                },
                "client_state": {
                    "form_contexts": [
                        {
                            "url": "settings",
                            "html": '<form action="/app/save" method="post"><input type="hidden" name="role" value="user"></form>',
                            "success_markers": ["admin panel saved"],
                        }
                    ],
                    "cookie_contexts": [
                        {
                            "url": "admin",
                            "cookie_name": "admin",
                            "original_value": "false",
                            "mutated_value": "true",
                        }
                    ],
                    "request_contexts": [
                        {"url": "profile", "method": "POST", "json": {"isAdmin": False}},
                    ],
                    "price_contexts": [
                        {"url": "checkout", "method": "POST", "json": {"price": "99.00"}},
                    ],
                    "workflow_contexts": [
                        {"final_url": "checkout/confirm", "success_markers": ["checkout complete"]},
                    ],
                    "gruyere_contexts": [
                        {
                            "url": "newsnippet",
                            "cookie_name": "is_admin",
                            "original_value": "False",
                            "mutated_value": "True",
                        }
                    ],
                },
            },
        },
    )

    assert create_response.status_code == 201
    created_payload = create_response.json()
    assert created_payload["status"] == "pending_approval"
    assert created_payload["tasks"] == []
    assert created_payload["pending_approvals"] == 1

    approval_response = client.post(
        f"/api/v1/runs/{created_payload['id']}/approvals",
        headers={"X-Actor": "approver"},
        json={"step_id": "run.launch", "decision": "approved"},
    )

    assert approval_response.status_code == 200
    approval_payload = approval_response.json()
    assert approval_payload["status"] == "queued"
    assert approval_payload["pending_approvals"] == 0
    assert len(approval_payload["tasks"]) == 1
    task = approval_payload["tasks"][0]
    assert task["tool"] == "client-state"
    assert task["target_id"] == "https://portal.example.test/app/"
    assert task["params_json"]["form_contexts"][0]["url"] == "settings"
    assert task["params_json"]["cookie_contexts"][0]["cookie_name"] == "admin"
    assert task["params_json"]["request_contexts"][0]["json"] == {"isAdmin": False}
    assert task["params_json"]["price_contexts"][0]["json"] == {"price": "99.00"}
    assert task["params_json"]["workflow_contexts"][0]["final_url"] == "checkout/confirm"
    assert task["params_json"]["gruyere_contexts"][0]["url"] == "newsnippet"
    assert task["params_json"]["auth_contexts"][0]["label"] == "Client State User"
    assert "session" in task["params_json"]["auth_contexts"][0]["secret_bindings"]
    assert "session=alice" not in json.dumps(task["params_json"])


def test_active_headers_security_profile_requires_approval_and_queues_header_task(client) -> None:
    engagement_id = create_engagement_with_url_scope(client, "https://portal.example.test/app/")

    create_response = client.post(
        f"/api/v1/engagements/{engagement_id}/runs",
        headers={"X-Actor": "operator"},
        json={
            "profile_name": "active-web-headers-security",
            "configuration_json": {
                "targets": {"urls": ["https://portal.example.test/app/"]},
                "headers_security": {
                    "attacker_origin": "https://evil.example.com",
                    "additional_origins": ["null", "https://portal.example.test.evil.example.com"],
                    "redirect_paths": ["redirect"],
                },
            },
        },
    )

    assert create_response.status_code == 201
    created_payload = create_response.json()
    assert created_payload["status"] == "pending_approval"
    assert created_payload["tasks"] == []
    assert created_payload["pending_approvals"] == 1

    approval_response = client.post(
        f"/api/v1/runs/{created_payload['id']}/approvals",
        headers={"X-Actor": "approver"},
        json={"step_id": "run.launch", "decision": "approved"},
    )

    assert approval_response.status_code == 200
    approval_payload = approval_response.json()
    assert approval_payload["status"] == "queued"
    assert approval_payload["pending_approvals"] == 0
    assert len(approval_payload["tasks"]) == 1
    task = approval_payload["tasks"][0]
    assert task["tool"] == "headers-security"
    assert task["target_id"] == "https://portal.example.test/app/"
    assert task["params_json"]["attacker_origin"] == "https://evil.example.com"
    assert task["params_json"]["additional_origins"] == [
        "null",
        "https://portal.example.test.evil.example.com",
    ]
    assert task["params_json"]["redirect_paths"] == ["redirect"]


def test_active_graphql_probe_profile_requires_approval_and_queues_graphql_task(client) -> None:
    engagement_id = create_engagement_with_url_scope(client, "https://portal.example.test/api/")

    create_response = client.post(
        f"/api/v1/engagements/{engagement_id}/runs",
        headers={"X-Actor": "operator"},
        json={
            "profile_name": "active-web-graphql-probe",
            "configuration_json": {
                "targets": {"urls": ["https://portal.example.test/api/"]},
                "graphql_probe": {
                    "endpoint_paths": ["/graphql", "/api/graphql"],
                    "ide_paths": ["/graphiql"],
                    "max_depth": 18,
                    "max_injection_fields": 3,
                },
            },
        },
    )

    assert create_response.status_code == 201
    created_payload = create_response.json()
    assert created_payload["status"] == "pending_approval"
    assert created_payload["tasks"] == []
    assert created_payload["pending_approvals"] == 1

    approval_response = client.post(
        f"/api/v1/runs/{created_payload['id']}/approvals",
        headers={"X-Actor": "approver"},
        json={"step_id": "run.launch", "decision": "approved"},
    )

    assert approval_response.status_code == 200
    approval_payload = approval_response.json()
    assert approval_payload["status"] == "queued"
    assert approval_payload["pending_approvals"] == 0
    assert len(approval_payload["tasks"]) == 1
    task = approval_payload["tasks"][0]
    assert task["tool"] == "graphql-probe"
    assert task["target_id"] == "https://portal.example.test/api/"
    assert task["params_json"]["endpoint_paths"] == ["/graphql", "/api/graphql"]
    assert task["params_json"]["ide_paths"] == ["/graphiql"]
    assert task["params_json"]["max_depth"] == 18
    assert task["params_json"]["max_injection_fields"] == 3


def test_intrusive_responder_profile_requires_named_approval_gate_and_configured_interface(
    client,
) -> None:
    engagement_id = create_engagement_with_cidr_scope(client, "10.0.20.0/24")

    missing_interface = client.post(
        f"/api/v1/engagements/{engagement_id}/runs",
        headers={"X-Actor": "operator"},
        json={
            "profile_name": "intrusive-lan-credential-capture",
            "configuration_json": {
                "targets": {"cidrs": ["10.0.20.0/24"]},
            },
        },
    )

    assert missing_interface.status_code == 409
    assert "responder.interface" in missing_interface.json()["detail"]

    create_response = client.post(
        f"/api/v1/engagements/{engagement_id}/runs",
        headers={"X-Actor": "operator"},
        json={
            "profile_name": "intrusive-lan-credential-capture",
            "configuration_json": {
                "targets": {"cidrs": ["10.0.20.0/24"]},
                "responder": {"interface": "eth0", "duration_minutes": 15},
            },
        },
    )

    assert create_response.status_code == 201
    created_payload = create_response.json()
    assert created_payload["status"] == "pending_approval"
    assert created_payload["approval_step_id"] == "intrusive-lan-poisoning"
    assert created_payload["required_approvals"] == 2
    assert created_payload["pending_approvals"] == 2

    wrong_step = client.post(
        f"/api/v1/runs/{created_payload['id']}/approvals",
        headers={"X-Actor": "approver-1"},
        json={"step_id": "run.launch", "decision": "approved"},
    )
    assert wrong_step.status_code == 409
    assert "intrusive-lan-poisoning" in wrong_step.json()["detail"]

    first_approval = client.post(
        f"/api/v1/runs/{created_payload['id']}/approvals",
        headers={"X-Actor": "approver-1"},
        json={"step_id": "intrusive-lan-poisoning", "decision": "approved"},
    )
    assert first_approval.status_code == 200
    assert first_approval.json()["status"] == "pending_approval"
    assert first_approval.json()["pending_approvals"] == 1

    second_approval = client.post(
        f"/api/v1/runs/{created_payload['id']}/approvals",
        headers={"X-Actor": "approver-2"},
        json={"step_id": "intrusive-lan-poisoning", "decision": "approved"},
    )
    assert second_approval.status_code == 200
    approval_payload = second_approval.json()
    assert approval_payload["status"] == "queued"
    assert approval_payload["pending_approvals"] == 0
    assert len(approval_payload["tasks"]) == 1
    task = approval_payload["tasks"][0]
    assert task["tool"] == "responder"
    assert task["target_id"] == "10.0.20.0/24"
    assert task["params_json"]["interface"] == "eth0"
    assert task["params_json"]["duration_minutes"] == 15.0
    assert task["params_json"]["approved_scope_cidrs"] == ["10.0.20.0/24"]


def test_intrusive_exploitation_profile_requires_source_finding_and_auth_for_psexec(client) -> None:
    from api.app.models import Finding, Run, RunProfile
    from api.app.services.run_profiles import ensure_default_run_profiles

    engagement_id = create_engagement_with_host_scope(client, ["10.0.20.25"])

    with client.app.state.session_factory() as session:
        ensure_default_run_profiles(session)
        source_profile = session.scalar(
            select(RunProfile).where(RunProfile.name == "intrusive-lan-smb-auth")
        )
        assert source_profile is not None
        source_run = Run(
            engagement_id=UUID(engagement_id),
            profile_id=source_profile.id,
            requested_by="seed",
            status="completed",
            configuration_json={},
        )
        session.add(source_run)
        session.flush()
        source_finding = Finding(
            run_id=source_run.id,
            title="Pass-the-hash SMB access succeeded on 10.0.20.25",
            severity="critical",
            target_id="10.0.20.25",
            evidence_ref="artifact://seed/netexec",
            summary="Prior SMB validation confirmed pass-the-hash access.",
            methodology_tags=["smb", "pass_the_hash"],
        )
        session.add(source_finding)
        session.commit()
        finding_id = str(source_finding.id)

    missing_auth = client.post(
        f"/api/v1/engagements/{engagement_id}/runs",
        headers={"X-Actor": "operator"},
        json={
            "profile_name": "intrusive-exploitation",
            "configuration_json": {
                "targets": {"hosts": ["10.0.20.25"]},
                "metasploit": {"finding_id": finding_id, "lhost": "127.0.0.1"},
            },
        },
    )
    assert missing_auth.status_code == 409
    assert "stored password or NTLM hash binding" in missing_auth.json()["detail"]

    create_response = client.post(
        f"/api/v1/engagements/{engagement_id}/runs",
        headers={"X-Actor": "operator"},
        json={
            "profile_name": "intrusive-exploitation",
            "configuration_json": {
                "targets": {"hosts": ["10.0.20.25"]},
                "metasploit": {"finding_id": finding_id, "lhost": "127.0.0.1", "lport": 4444},
                "access": {
                    "accounts": [
                        {
                            "label": "Backup Admin",
                            "username": "backup-admin",
                            "domain": "CORP",
                            "hash_ref": "31d6cfe0d16ae931b73c59d7e0c089c0",
                        }
                    ]
                },
            },
        },
    )

    assert create_response.status_code == 201
    created_payload = create_response.json()
    assert created_payload["status"] == "pending_approval"
    assert created_payload["approval_step_id"] == "intrusive-exploitation"
    assert created_payload["required_approvals"] == 2

    first_approval = client.post(
        f"/api/v1/runs/{created_payload['id']}/approvals",
        headers={"X-Actor": "approver-1"},
        json={"step_id": "intrusive-exploitation", "decision": "approved"},
    )
    assert first_approval.status_code == 200
    assert first_approval.json()["pending_approvals"] == 1

    second_approval = client.post(
        f"/api/v1/runs/{created_payload['id']}/approvals",
        headers={"X-Actor": "approver-2"},
        json={"step_id": "intrusive-exploitation", "decision": "approved"},
    )
    assert second_approval.status_code == 200
    approval_payload = second_approval.json()
    assert approval_payload["status"] == "queued"
    task = approval_payload["tasks"][0]
    assert task["tool"] == "metasploit"
    assert task["target_id"] == "10.0.20.25"
    assert task["source_finding_id"] == finding_id
    assert task["params_json"]["module_name"] == "windows/smb/psexec"
    assert task["params_json"]["reference_label"] == "credentialed SMB remote code execution"
    assert task["params_json"]["lhost"] == "127.0.0.1"
    assert "ntlm_hash" in task["params_json"]["auth_contexts"][0]["secret_bindings"]


def test_intrusive_impacket_remote_exec_profile_requires_auth_and_intrusive_gate(client) -> None:
    engagement_id = create_engagement_with_host_scope(client, ["10.0.20.25"])

    missing_auth = client.post(
        f"/api/v1/engagements/{engagement_id}/runs",
        headers={"X-Actor": "operator"},
        json={
            "profile_name": "intrusive-impacket-remote-exec",
            "configuration_json": {
                "targets": {"hosts": ["10.0.20.25"]},
                "impacket": {"remote_exec_method": "wmiexec"},
            },
        },
    )
    assert missing_auth.status_code == 409
    assert "stored password or NTLM hash binding" in missing_auth.json()["detail"]

    create_response = client.post(
        f"/api/v1/engagements/{engagement_id}/runs",
        headers={"X-Actor": "operator"},
        json={
            "profile_name": "intrusive-impacket-remote-exec",
            "configuration_json": {
                "targets": {"hosts": ["10.0.20.25"]},
                "impacket": {"remote_exec_method": "wmiexec"},
                "access": {
                    "accounts": [
                        {
                            "label": "Backup Admin",
                            "username": "backup-admin",
                            "domain": "CORP",
                            "hash_ref": "31d6cfe0d16ae931b73c59d7e0c089c0",
                        }
                    ]
                },
            },
        },
    )
    assert create_response.status_code == 201
    created_payload = create_response.json()
    assert created_payload["status"] == "pending_approval"
    assert created_payload["approval_step_id"] == "intrusive-exploitation"
    assert created_payload["required_approvals"] == 2

    client.post(
        f"/api/v1/runs/{created_payload['id']}/approvals",
        headers={"X-Actor": "approver-1"},
        json={"step_id": "intrusive-exploitation", "decision": "approved"},
    )
    second_approval = client.post(
        f"/api/v1/runs/{created_payload['id']}/approvals",
        headers={"X-Actor": "approver-2"},
        json={"step_id": "intrusive-exploitation", "decision": "approved"},
    )
    assert second_approval.status_code == 200
    approval_payload = second_approval.json()
    task = approval_payload["tasks"][0]
    assert task["tool"] == "impacket-lateral"
    assert task["target_id"] == "10.0.20.25"
    assert task["params_json"]["mode"] == "remote_exec"
    assert task["params_json"]["remote_exec_method"] == "wmiexec"
    assert "ntlm_hash" in task["params_json"]["auth_contexts"][0]["secret_bindings"]


def test_active_ad_bloodhound_profile_requires_domain_auth_and_queues_domain_target(client) -> None:
    engagement_id = create_engagement_with_directory_scope(
        client,
        "corp.example",
        "dc01.corp.example",
    )

    missing_auth = client.post(
        f"/api/v1/engagements/{engagement_id}/runs",
        headers={"X-Actor": "operator"},
        json={
            "profile_name": "active-ad-bloodhound",
            "configuration_json": {
                "targets": {"ad_domains": ["corp.example"]},
            },
        },
    )

    assert missing_auth.status_code == 409
    assert "stored password binding" in missing_auth.json()["detail"]

    create_response = client.post(
        f"/api/v1/engagements/{engagement_id}/runs",
        headers={"X-Actor": "operator"},
        json={
            "profile_name": "active-ad-bloodhound",
            "configuration_json": {
                "targets": {
                    "ad_domains": ["corp.example"],
                    "directory_hosts": ["dc01.corp.example"],
                },
                "bloodhound": {
                    "domain": "corp.example",
                    "domain_controller": "dc01.corp.example",
                    "nameserver": "10.0.0.10",
                    "collection_methods": ["All"],
                },
                "access": {
                    "accounts": [
                        {
                            "label": "Read-only Domain User",
                            "username": "alice@corp.example",
                            "domain": "corp.example",
                            "secret_ref": "CorrectHorseBatteryStaple!",
                        }
                    ]
                },
            },
        },
    )

    assert create_response.status_code == 201
    created_payload = create_response.json()
    assert created_payload["status"] == "pending_approval"
    assert created_payload["required_approvals"] == 1
    assert created_payload["approval_step_id"] == "run.launch"

    approval_response = client.post(
        f"/api/v1/runs/{created_payload['id']}/approvals",
        headers={"X-Actor": "approver"},
        json={"step_id": "run.launch", "decision": "approved"},
    )

    assert approval_response.status_code == 200
    approval_payload = approval_response.json()
    assert approval_payload["status"] == "queued"
    task = approval_payload["tasks"][0]
    assert task["tool"] == "bloodhound-collect"
    assert task["target_id"] == "corp.example"
    assert task["params_json"]["domain"] == "corp.example"
    assert task["params_json"]["domain_controller"] == "dc01.corp.example"
    assert task["params_json"]["nameserver"] == "10.0.0.10"
    assert task["params_json"]["collection_methods"] == ["All"]
    assert task["params_json"]["auth_contexts"][0]["username"] == "alice@corp.example"
    assert "password" in task["params_json"]["auth_contexts"][0]["secret_bindings"]


def test_inline_responder_dispatch_stores_hash_bundle_without_plaintext_leakage(
    inline_client,
    monkeypatch,
) -> None:
    from api.app.config import get_settings
    from api.app.models import SecretRef, ToolExecution
    from api.app.services.secrets import load_secret_value

    raw_hash = "alice::EXAMPLE:1122334455667788:99AABBCCDDEEFF001122334455667788:0101000000000000"

    def fake_dispatch_runner(request):
        assert request.tool == "responder"
        return RunnerExecution(
            tool="responder",
            exit_code=0,
            stdout="Responder captured protected NTLMv2 material.\n",
            stderr="",
            metadata={
                "status": "ok",
                "capture_count": 1,
                "interface": "eth0",
                "tool_version": "Responder test",
                "runner_digest": "workers.responder.runner:v1",
            },
            artifacts=[
                EvidenceArtifact(
                    name=RESPONDER_RESULTS_ARTIFACT_NAME,
                    content_type="application/json",
                    data=(
                        json.dumps(
                            {
                                "summary": {
                                    "capture_count": 1,
                                    "hash_material_stored_as": "protected_secret_ref",
                                },
                                "captures": [
                                    {
                                        "host": "10.0.20.44",
                                        "username": "alice",
                                        "domain": "EXAMPLE",
                                        "hash_type": "NTLMv2",
                                        "summary": "Protected hash capture stored separately.",
                                    }
                                ],
                            }
                        )
                        + "\n"
                    ).encode("utf-8"),
                    kind="credential-capture-results",
                ),
                EvidenceArtifact(
                    name=RESPONDER_LOG_ARTIFACT_NAME,
                    content_type="text/plain",
                    data=b"Responder captured protected NTLMv2 material.\n",
                    kind="execution-log",
                ),
            ],
            protected_outputs=[
                ProtectedSecretMaterial(
                    artifact_name=RESPONDER_RESULTS_ARTIFACT_NAME,
                    value=json.dumps({"captures": [{"raw_hash": raw_hash}]}),
                    secret_kind="ntlmv2_hash_bundle",
                    purpose="task.responder.captured_hashes",
                    display_label="Responder captured NTLMv2 hashes (1)",
                    content_type="application/json",
                    metadata={"capture_count": 1},
                )
            ],
        )

    monkeypatch.setattr("workers.orchestration.tasks.dispatch_runner", fake_dispatch_runner)

    engagement_id = create_engagement_with_cidr_scope(inline_client, "10.0.20.0/24")
    create_response = inline_client.post(
        f"/api/v1/engagements/{engagement_id}/runs",
        headers={"X-Actor": "operator"},
        json={
            "profile_name": "intrusive-lan-credential-capture",
            "configuration_json": {
                "targets": {"cidrs": ["10.0.20.0/24"]},
                "responder": {"interface": "eth0", "duration_minutes": 5},
            },
        },
    )
    run_id = create_response.json()["id"]

    inline_client.post(
        f"/api/v1/runs/{run_id}/approvals",
        headers={"X-Actor": "approver-1"},
        json={"step_id": "intrusive-lan-poisoning", "decision": "approved"},
    )
    second_approval = inline_client.post(
        f"/api/v1/runs/{run_id}/approvals",
        headers={"X-Actor": "approver-2"},
        json={"step_id": "intrusive-lan-poisoning", "decision": "approved"},
    )
    task_id = second_approval.json()["tasks"][0]["id"]

    dispatch_response = inline_client.post(
        f"/api/v1/runs/{run_id}/dispatch",
        headers={"X-Actor": "operator"},
    )
    assert dispatch_response.status_code == 200

    task_detail = inline_client.get(f"/api/v1/tasks/{task_id}")
    assert task_detail.status_code == 200
    task_payload = task_detail.json()
    assert raw_hash not in json.dumps(task_payload)
    protected_binding = task_payload["executions"][0]["artifacts"][0]["metadata_json"][
        "protected_secret_binding"
    ]
    assert protected_binding["secret_kind"] == "ntlmv2_hash_bundle"

    with inline_client.app.state.session_factory() as session:
        secret_ref = session.scalar(
            select(SecretRef).where(SecretRef.purpose == "task.responder.captured_hashes")
        )
        assert secret_ref is not None
        protected_payload = load_secret_value(secret_ref, get_settings())
        assert protected_payload is not None
        assert raw_hash in protected_payload

        execution = session.scalar(
            select(ToolExecution).where(ToolExecution.task_id == UUID(task_id))
        )
        assert execution is not None
        assert raw_hash not in (execution.stdout_text or "")
        assert raw_hash not in (execution.stderr_text or "")


def test_inline_bloodhound_dispatch_stores_protected_zip_without_plaintext_leakage(
    inline_client,
    monkeypatch,
) -> None:
    from api.app.config import get_settings
    from api.app.models import SecretRef, ToolExecution
    from api.app.services.secrets import load_secret_value

    protected_collection = "UEsDBAoAAAAAA"

    def fake_dispatch_runner(request):
        assert request.tool == "bloodhound-collect"
        return RunnerExecution(
            tool="bloodhound-collect",
            exit_code=0,
            stdout="BloodHound completed with protected collection storage.\n",
            stderr="",
            metadata={
                "status": "ok",
                "read_only": True,
                "tool_version": "bloodhound-python test",
                "runner_digest": "workers.bloodhound.runner:test",
                "confirmed_edge_count": 2,
                "attack_path_count": 1,
            },
            artifacts=[
                EvidenceArtifact(
                    name=BLOODHOUND_COLLECTION_ARTIFACT_NAME,
                    content_type="application/vnd.aegispt.protected-artifact-reference+json",
                    data=json.dumps({"stored_as": "protected_secret_ref"}).encode("utf-8"),
                    kind="protected-collection-reference",
                ),
                EvidenceArtifact(
                    name=BLOODHOUND_RESULTS_ARTIFACT_NAME,
                    content_type="application/json",
                    data=(
                        json.dumps(
                            {
                                "targets": [
                                    {
                                        "target": "corp.example",
                                        "status": "ok",
                                        "identity_subjects": [
                                            {
                                                "account_name": "alice@corp.example",
                                                "enabled": True,
                                                "confidence": 0.86,
                                            }
                                        ],
                                        "identity_groups": [
                                            {
                                                "name": "Domain Admins",
                                                "privileged": True,
                                                "confidence": 0.84,
                                            }
                                        ],
                                        "bloodhound_confirmed_edges": [],
                                        "bloodhound_attack_paths": [
                                            {
                                                "path_id": "bloodhound-path:1",
                                                "finding_title": "Read-only AD attack path to Domain Admins observed from alice@corp.example",
                                                "finding_target_id": "Domain Admins",
                                                "severity": "high",
                                                "node_ids": [
                                                    "identity-subject:alice-corp-example",
                                                    "identity-group:domain-admins",
                                                ],
                                                "node_labels": [
                                                    "alice@corp.example",
                                                    "Domain Admins",
                                                ],
                                                "edge_chain": [],
                                                "summary": "Read-only BloodHound analysis found a path to Domain Admins.",
                                                "confidence": 0.82,
                                            }
                                        ],
                                        "analysis_findings": [
                                            {
                                                "title": "Read-only AD attack path to Domain Admins observed from alice@corp.example",
                                                "severity": "high",
                                                "target_id": "Domain Admins",
                                                "summary": "Read-only BloodHound analysis found a path to Domain Admins.",
                                                "methodology_tags": [
                                                    "bloodhound",
                                                    "active_directory",
                                                ],
                                            }
                                        ],
                                        "summary": {"attack_path_count": 1},
                                    }
                                ],
                                "summary": {
                                    "attack_path_count": 1,
                                    "confirmed_edge_count": 0,
                                    "finding_count": 1,
                                },
                            }
                        )
                        + "\n"
                    ).encode("utf-8"),
                    kind="identity-graph-results",
                ),
            ],
            protected_outputs=[
                ProtectedSecretMaterial(
                    artifact_name=BLOODHOUND_COLLECTION_ARTIFACT_NAME,
                    value=protected_collection,
                    secret_kind="bloodhound_collection_zip",
                    purpose="task.bloodhound.collection_zip",
                    display_label="BloodHound collection ZIP for corp.example",
                    content_type="application/zip+base64",
                    metadata={"encoding": "base64", "byte_length": 1024},
                )
            ],
        )

    monkeypatch.setattr("workers.orchestration.tasks.dispatch_runner", fake_dispatch_runner)

    engagement_id = create_engagement_with_directory_scope(
        inline_client,
        "corp.example",
        "dc01.corp.example",
    )
    create_response = inline_client.post(
        f"/api/v1/engagements/{engagement_id}/runs",
        headers={"X-Actor": "operator"},
        json={
            "profile_name": "active-ad-bloodhound",
            "configuration_json": {
                "targets": {"ad_domains": ["corp.example"]},
                "bloodhound": {"domain": "corp.example"},
                "access": {
                    "accounts": [
                        {
                            "label": "Read-only Domain User",
                            "username": "alice@corp.example",
                            "domain": "corp.example",
                            "secret_ref": "CorrectHorseBatteryStaple!",
                        }
                    ]
                },
            },
        },
    )
    run_id = create_response.json()["id"]

    approval_response = inline_client.post(
        f"/api/v1/runs/{run_id}/approvals",
        headers={"X-Actor": "approver"},
        json={"step_id": "run.launch", "decision": "approved"},
    )
    task_id = approval_response.json()["tasks"][0]["id"]

    dispatch_response = inline_client.post(
        f"/api/v1/runs/{run_id}/dispatch",
        headers={"X-Actor": "operator"},
    )
    assert dispatch_response.status_code == 200

    task_detail = inline_client.get(f"/api/v1/tasks/{task_id}")
    assert task_detail.status_code == 200
    task_payload = task_detail.json()
    assert protected_collection not in json.dumps(task_payload)
    protected_binding = task_payload["executions"][0]["artifacts"][0]["metadata_json"][
        "protected_secret_binding"
    ]
    assert protected_binding["secret_kind"] == "bloodhound_collection_zip"

    inventory_response = inline_client.get(f"/api/v1/engagements/{engagement_id}/inventory")
    assert inventory_response.status_code == 200
    assert inventory_response.json()[0]["source_tools_json"] == ["bloodhound-collect"]

    with inline_client.app.state.session_factory() as session:
        secret_ref = session.scalar(
            select(SecretRef).where(SecretRef.purpose == "task.bloodhound.collection_zip")
        )
        assert secret_ref is not None
        protected_payload = load_secret_value(secret_ref, get_settings())
        assert protected_payload == protected_collection

        execution = session.scalar(
            select(ToolExecution).where(ToolExecution.task_id == UUID(task_id))
        )
        assert execution is not None
        assert protected_collection not in (execution.stdout_text or "")
        assert protected_collection not in (execution.stderr_text or "")


def test_inline_netexec_dispatch_dereferences_hash_secret_ref_without_plaintext_leakage(
    inline_client,
    monkeypatch,
) -> None:
    from api.app.config import get_settings
    from api.app.models import SecretRef, ToolExecution
    from api.app.services.secrets import encrypt_secret_value, load_secret_value

    raw_hash = "31d6cfe0d16ae931b73c59d7e0c089c0"

    def fake_dispatch_runner(request):
        assert request.tool == "netexec"
        assert request.params["mode"] == "intrusive"
        assert request.params["auth_contexts"][0]["ntlm_hash"] == raw_hash
        return RunnerExecution(
            tool="netexec",
            exit_code=0,
            stdout="NetExec SMB validation completed.\n",
            stderr="",
            metadata={
                "status": "ok",
                "mode": "intrusive",
                "tool_version": "nxc test",
                "runner_digest": "workers.netexec.runner:test",
                "finding_count": 2,
                "successful_auth_count": 1,
                "pass_the_hash_success_count": 1,
                "terminated_by_kill_switch": False,
                "read_only": False,
            },
            artifacts=[
                EvidenceArtifact(
                    name=NETEXEC_RESULTS_ARTIFACT_NAME,
                    content_type="application/json",
                    data=(
                        json.dumps(
                            {
                                "summary": {
                                    "mode": "intrusive",
                                    "finding_count": 2,
                                    "successful_auth_count": 1,
                                    "pass_the_hash_success_count": 1,
                                    "terminated_by_kill_switch": False,
                                },
                                "targets": [
                                    {
                                        "target": "10.0.20.25",
                                        "mode": "intrusive",
                                        "status": "ok",
                                        "host": {
                                            "reachable": True,
                                            "hostname": "FS01",
                                            "domain": "CORP",
                                            "os": "Windows Server 2022",
                                            "signing": False,
                                            "smb_v1": False,
                                        },
                                        "null_session_enabled": False,
                                        "auth_attempts": [
                                            {
                                                "label": "Backup Admin",
                                                "username": "backup-admin",
                                                "credential_type": "ntlm_hash",
                                                "domain": None,
                                                "local_auth": True,
                                                "success": True,
                                                "admin_access": True,
                                            }
                                        ],
                                        "shares": [
                                            {
                                                "name": "Finance",
                                                "permissions": ["READ", "WRITE"],
                                                "anonymous": False,
                                            }
                                        ],
                                        "loggedon_users": ["CORP\\\\alice"],
                                        "local_groups": [
                                            {
                                                "name": "Administrators",
                                                "members": ["CORP\\\\backup-admin"],
                                            }
                                        ],
                                        "spider_files": [
                                            {
                                                "share": "Finance",
                                                "path": "\\\\Finance\\\\Passwords.xlsx",
                                            }
                                        ],
                                        "analysis_findings": [
                                            {
                                                "title": "Pass-the-hash SMB access succeeded on 10.0.20.25",
                                                "severity": "critical",
                                                "target_id": "10.0.20.25",
                                                "summary": "NetExec validated NTLM hash reuse against 10.0.20.25 using account Backup Admin.",
                                                "methodology_tags": [
                                                    "internal_network",
                                                    "smb",
                                                    "pass_the_hash",
                                                ],
                                                "control_family": "authentication",
                                            },
                                            {
                                                "title": "Sensitive SMB share content exposed on 10.0.20.25",
                                                "severity": "high",
                                                "target_id": "10.0.20.25",
                                                "summary": "NetExec spider_plus enumeration identified potentially sensitive content in share Finance on 10.0.20.25: \\\\Finance\\\\Passwords.xlsx.",
                                                "methodology_tags": [
                                                    "internal_network",
                                                    "smb",
                                                    "share_exposure",
                                                ],
                                                "control_family": "authorization",
                                            },
                                        ],
                                        "errors": [],
                                    }
                                ],
                            }
                        )
                        + "\n"
                    ).encode("utf-8"),
                    kind="smb-results",
                ),
                EvidenceArtifact(
                    name="netexec-10.0.20.25.json",
                    content_type="application/json",
                    data=(
                        json.dumps(
                            {
                                "target": "10.0.20.25",
                                "mode": "intrusive",
                                "status": "ok",
                                "host": {"reachable": True, "signing": False},
                                "auth_attempts": [
                                    {
                                        "label": "Backup Admin",
                                        "username": "backup-admin",
                                        "credential_type": "ntlm_hash",
                                        "success": True,
                                        "admin_access": True,
                                    }
                                ],
                                "shares": [
                                    {
                                        "name": "Finance",
                                        "permissions": ["READ", "WRITE"],
                                        "anonymous": False,
                                    }
                                ],
                                "loggedon_users": ["CORP\\\\alice"],
                                "local_groups": [
                                    {"name": "Administrators", "members": ["CORP\\\\backup-admin"]}
                                ],
                                "spider_files": [
                                    {"share": "Finance", "path": "\\\\Finance\\\\Passwords.xlsx"}
                                ],
                                "analysis_findings": [
                                    {
                                        "title": "Pass-the-hash SMB access succeeded on 10.0.20.25",
                                        "severity": "critical",
                                        "target_id": "10.0.20.25",
                                        "summary": "NetExec validated NTLM hash reuse against 10.0.20.25 using account Backup Admin.",
                                    }
                                ],
                                "errors": [],
                            }
                        )
                        + "\n"
                    ).encode("utf-8"),
                    kind="smb-host-results",
                ),
                EvidenceArtifact(
                    name=NETEXEC_LOG_ARTIFACT_NAME,
                    content_type="text/plain",
                    data=b"NetExec SMB validation completed.\n",
                    kind="execution-log",
                ),
            ],
            protected_outputs=[
                ProtectedSecretMaterial(
                    artifact_name="netexec-10.0.20.25.json",
                    value=json.dumps({"target": "10.0.20.25", "ntlm_hash": raw_hash}),
                    secret_kind="ntlm_hash_validation_bundle",
                    purpose="task.netexec.pass_the_hash.10.0.20.25",
                    display_label="Validated NTLM hash evidence for 10.0.20.25",
                    content_type="application/json",
                    metadata={"raw_secret_material_exposed": False},
                )
            ],
        )

    monkeypatch.setattr("workers.orchestration.tasks.dispatch_runner", fake_dispatch_runner)

    engagement_id = create_engagement_with_host_scope(inline_client, ["10.0.20.25"])
    with inline_client.app.state.session_factory() as session:
        settings = get_settings()
        source_secret_ref_id = uuid4()
        source_secret_ref = SecretRef(
            id=source_secret_ref_id,
            engagement_id=UUID(engagement_id),
            vault_pointer=f"aegispt://secret-ref/{source_secret_ref_id}",
            purpose="credential.ntlm_hash.imported",
            secret_kind="ntlm_hash",
            storage_backend="encrypted_local",
            display_label="ntlm hash protected locally",
            encrypted_value=encrypt_secret_value(raw_hash, settings),
            metadata_json={"raw_secret_material_exposed": False},
        )
        session.add(source_secret_ref)
        session.commit()

    create_response = inline_client.post(
        f"/api/v1/engagements/{engagement_id}/runs",
        headers={"X-Actor": "operator"},
        json={
            "profile_name": "intrusive-lan-smb-auth",
            "configuration_json": {
                "targets": {"hosts": ["10.0.20.25"]},
                "access": {
                    "accounts": [
                        {
                            "label": "Backup Admin",
                            "username": "backup-admin",
                            "local_auth": True,
                            "hash_ref": f"aegispt://secret-ref/{source_secret_ref_id}",
                        }
                    ]
                },
            },
        },
    )
    run_id = create_response.json()["id"]

    inline_client.post(
        f"/api/v1/runs/{run_id}/approvals",
        headers={"X-Actor": "approver-1"},
        json={"step_id": "intrusive-lan-smb-auth", "decision": "approved"},
    )
    second_approval = inline_client.post(
        f"/api/v1/runs/{run_id}/approvals",
        headers={"X-Actor": "approver-2"},
        json={"step_id": "intrusive-lan-smb-auth", "decision": "approved"},
    )
    task_id = second_approval.json()["tasks"][0]["id"]

    dispatch_response = inline_client.post(
        f"/api/v1/runs/{run_id}/dispatch",
        headers={"X-Actor": "operator"},
    )
    assert dispatch_response.status_code == 200

    task_detail = inline_client.get(f"/api/v1/tasks/{task_id}")
    assert task_detail.status_code == 200
    task_payload = task_detail.json()
    assert raw_hash not in json.dumps(task_payload)
    protected_artifact = next(
        artifact
        for artifact in task_payload["executions"][0]["artifacts"]
        if artifact["metadata_json"].get("protected_secret_binding")
    )
    assert protected_artifact["metadata_json"]["protected_secret_binding"]["secret_kind"] == (
        "ntlm_hash_validation_bundle"
    )

    with inline_client.app.state.session_factory() as session:
        secret_ref = session.scalar(
            select(SecretRef).where(SecretRef.purpose == "task.netexec.pass_the_hash.10.0.20.25")
        )
        assert secret_ref is not None
        protected_payload = load_secret_value(secret_ref, get_settings())
        assert protected_payload is not None
        assert raw_hash in protected_payload

        execution = session.scalar(
            select(ToolExecution).where(ToolExecution.task_id == UUID(task_id))
        )
        assert execution is not None
        assert raw_hash not in (execution.stdout_text or "")
        assert raw_hash not in (execution.stderr_text or "")


def test_autonomous_profile_defaults_run_flags_on_create(client) -> None:
    engagement_id = create_engagement_with_scope(client)

    response = client.post(
        f"/api/v1/engagements/{engagement_id}/runs",
        headers={"X-Actor": "operator"},
        json={"profile_name": "autonomous-web"},
    )

    assert response.status_code == 201
    payload = response.json()
    assert payload["autonomous_mode"] is True
    assert payload["autonomous_intrusive_allowed"] is False
    assert {task["tool"] for task in payload["tasks"]} == {"httpx"}


def test_inline_hashcat_dispatch_dereferences_hash_bundle_without_plaintext_leakage(
    inline_client,
    monkeypatch,
) -> None:
    from api.app.config import get_settings
    from api.app.models import SecretRef, ToolExecution
    from api.app.services.secrets import encrypt_secret_value, load_secret_value

    raw_hash = "$krb5tgs$23$*svc-sql$CORP.EXAMPLE$MSSQLSvc/sql01.corp.example:1433*$112233$445566"
    raw_password = "ServicePass!2026"

    def fake_dispatch_runner(request):
        assert request.tool == "credential-attacks"
        assert request.params["mode"] == "hashcat"
        assert request.params["hash_sources"][0]["value"]
        assert raw_hash in request.params["hash_sources"][0]["value"]
        return RunnerExecution(
            tool="credential-attacks",
            exit_code=0,
            stdout="hashcat completed\n",
            stderr="",
            metadata={
                "status": "ok",
                "mode": "hashcat",
                "tool_version": "hashcat test",
                "runner_digest": "workers.credential_attacks.runner:test",
                "hash_source_count": 1,
                "cracked_password_count": 1,
                "finding_count": 1,
                "terminated_by_kill_switch": False,
            },
            artifacts=[
                EvidenceArtifact(
                    name=CREDENTIAL_ATTACK_RESULTS_ARTIFACT_NAME,
                    content_type="application/json",
                    data=(
                        json.dumps(
                            {
                                "summary": {
                                    "hash_source_count": 1,
                                    "cracked_password_count": 1,
                                    "finding_count": 1,
                                    "terminated_by_kill_switch": False,
                                },
                                "targets": [
                                    {
                                        "target": "corp.example",
                                        "mode": "hashcat",
                                        "status": "ok",
                                        "cracked_accounts": [
                                            {
                                                "account_name": "svc-sql",
                                                "user_principal_name": "svc-sql@corp.example",
                                                "source_kind": "kerberoast_tgs_hash_bundle",
                                                "privilege_level": "privileged",
                                                "password_stored_as": "protected_secret_ref",
                                            }
                                        ],
                                        "analysis_findings": [
                                            {
                                                "title": "Weak password cracked for account svc-sql",
                                                "severity": "critical",
                                                "target_id": "corp.example",
                                                "summary": "Offline hash cracking recovered a reusable password for svc-sql. The plaintext password is stored only through protected secret storage.",
                                                "methodology_tags": [
                                                    "credential_attack",
                                                    "offline_cracking",
                                                    "password_strength",
                                                ],
                                            }
                                        ],
                                        "errors": [],
                                    }
                                ],
                            }
                        )
                        + "\n"
                    ).encode("utf-8"),
                    kind="credential-attack-results",
                ),
                EvidenceArtifact(
                    name="credential-attack-cracked-svc-sql.json",
                    content_type="application/vnd.aegispt.protected-artifact-reference+json",
                    data=(
                        json.dumps(
                            {
                                "stored_as": "protected_secret_ref",
                                "artifact_name": "credential-attack-cracked-svc-sql.json",
                                "content_type": "text/plain",
                                "raw_secret_material_exposed": False,
                                "account_name": "svc-sql",
                            }
                        )
                        + "\n"
                    ).encode("utf-8"),
                    kind="protected-password-reference",
                ),
                EvidenceArtifact(
                    name=CREDENTIAL_ATTACK_LOG_ARTIFACT_NAME,
                    content_type="text/plain",
                    data=b"hashcat completed\n",
                    kind="execution-log",
                ),
            ],
            protected_outputs=[
                ProtectedSecretMaterial(
                    artifact_name="credential-attack-cracked-svc-sql.json",
                    value=raw_password,
                    secret_kind="password",
                    purpose="task.credential_attacks.cracked_password.svc-sql",
                    display_label="Protected password for svc-sql",
                    metadata={
                        "account_name": "svc-sql",
                        "target": "corp.example",
                        "privilege_level": "privileged",
                        "raw_secret_material_exposed": False,
                    },
                )
            ],
        )

    monkeypatch.setattr("workers.orchestration.tasks.dispatch_runner", fake_dispatch_runner)

    engagement_id = create_engagement_with_directory_scope(
        inline_client,
        "corp.example",
        "dc01.corp.example",
    )
    with inline_client.app.state.session_factory() as session:
        settings = get_settings()
        source_secret_ref_id = uuid4()
        source_secret_ref = SecretRef(
            id=source_secret_ref_id,
            engagement_id=UUID(engagement_id),
            vault_pointer=f"aegispt://secret-ref/{source_secret_ref_id}",
            purpose="task.credential_attacks.kerberoast.seed",
            secret_kind="kerberoast_tgs_hash_bundle",
            storage_backend="encrypted_local",
            display_label="Kerberoast hashes",
            encrypted_value=encrypt_secret_value(
                json.dumps(
                    {
                        "records": [
                            {
                                "account_name": "svc-sql",
                                "user_principal_name": "svc-sql@corp.example",
                                "hash": raw_hash,
                                "hashcat_mode": 13100,
                                "privilege_level": "privileged",
                                "source": "kerberoast",
                            }
                        ]
                    }
                ),
                settings,
            ),
            metadata_json={"raw_secret_material_exposed": False},
        )
        session.add(source_secret_ref)
        session.commit()

    create_response = inline_client.post(
        f"/api/v1/engagements/{engagement_id}/runs",
        headers={"X-Actor": "operator"},
        json={
            "profile_name": "active-offline-hash-crack",
            "configuration_json": {
                "credential_attacks": {
                    "hash_sources": [
                        {
                            "label": "Kerberoast bundle",
                            "hash_ref": f"aegispt://secret-ref/{source_secret_ref_id}",
                        }
                    ]
                }
            },
        },
    )
    assert create_response.status_code == 201
    run_id = create_response.json()["id"]

    approval_response = inline_client.post(
        f"/api/v1/runs/{run_id}/approvals",
        headers={"X-Actor": "approver"},
        json={"step_id": "active-ad-credential-attacks", "decision": "approved"},
    )
    task_id = approval_response.json()["tasks"][0]["id"]

    dispatch_response = inline_client.post(
        f"/api/v1/runs/{run_id}/dispatch",
        headers={"X-Actor": "operator"},
    )
    assert dispatch_response.status_code == 200

    task_detail = inline_client.get(f"/api/v1/tasks/{task_id}")
    assert task_detail.status_code == 200
    task_payload = task_detail.json()
    serialized_task = json.dumps(task_payload)
    assert raw_hash not in serialized_task
    assert raw_password not in serialized_task

    with inline_client.app.state.session_factory() as session:
        secret_ref = session.scalar(
            select(SecretRef).where(
                SecretRef.purpose == "task.credential_attacks.cracked_password.svc-sql"
            )
        )
        assert secret_ref is not None
        protected_password = load_secret_value(secret_ref, get_settings())
        assert protected_password == raw_password

        execution = session.scalar(
            select(ToolExecution).where(ToolExecution.task_id == UUID(task_id))
        )
        assert execution is not None
        assert raw_hash not in (execution.stdout_text or "")
        assert raw_password not in (execution.stdout_text or "")


def test_passive_run_is_queued_with_tasks(client) -> None:
    engagement_id = create_engagement_with_scope(client)

    response = client.post(
        f"/api/v1/engagements/{engagement_id}/runs",
        headers={"X-Actor": "operator"},
        json={"profile_name": "passive-web-baseline"},
    )

    assert response.status_code == 201
    payload = response.json()
    assert payload["status"] == "queued"
    assert payload["required_approvals"] == 0
    assert payload["pending_approvals"] == 0
    assert len(payload["tasks"]) == 2
    assert {task["tool"] for task in payload["tasks"]} == {"httpx"}
    assert payload["updated_at"]
    assert all(task["updated_at"] for task in payload["tasks"])
    assert payload["findings"]["finding_count"] == 0
    assert payload["findings"]["findings_by_severity"] == {}
    assert payload["findings"]["findings_by_status"] == {}
    assert payload["configuration_json"] == {}


def test_ldap_profile_queues_directory_targets_without_url_targets(client) -> None:
    engagement_response = client.post(
        "/api/v1/engagements",
        headers={"X-Actor": "tester"},
        json={
            "name": "Directory Validation",
            "client": "Acme Corp",
            "roe_ref": "ROE-2026-LDAP",
        },
    )
    engagement_id = engagement_response.json()["id"]

    client.post(
        f"/api/v1/engagements/{engagement_id}/scope",
        headers={"X-Actor": "tester"},
        json={
            "allowlist_json": {
                "urls": ["https://app.corp.example"],
                "targets": ["https://generic-target.corp.example"],
                "directory_hosts": ["dc01.corp.example"],
                "ad_domains": ["corp.example"],
            },
            "denylist_json": {},
        },
    )

    response = client.post(
        f"/api/v1/engagements/{engagement_id}/runs",
        headers={"X-Actor": "operator"},
        json={
            "profile_name": "passive-identity-ldap-enum",
            "configuration_json": {
                "ldap": {
                    "base_dn": "DC=corp,DC=example",
                    "bind_dn": "CN=readonly,CN=Users,DC=corp,DC=example",
                    "password_env": "AEGISPT_LDAP_BIND_PASSWORD",
                },
            },
        },
    )

    assert response.status_code == 201
    payload = response.json()
    assert payload["status"] == "queued"
    assert {task["tool"] for task in payload["tasks"]} == {"ldap-enum"}
    assert {task["target_id"] for task in payload["tasks"]} == {"dc01.corp.example", "corp.example"}
    assert "https://app.corp.example" not in {task["target_id"] for task in payload["tasks"]}
    assert "https://generic-target.corp.example" not in {
        task["target_id"] for task in payload["tasks"]
    }
    assert all(task["params_json"]["base_dn"] == "DC=corp,DC=example" for task in payload["tasks"])
    assert all("password" not in task["params_json"] for task in payload["tasks"])


def test_aws_inventory_profile_queues_cloud_account_targets_without_url_targets(client) -> None:
    engagement_response = client.post(
        "/api/v1/engagements",
        headers={"X-Actor": "tester"},
        json={
            "name": "AWS Inventory",
            "client": "Acme Corp",
            "roe_ref": "ROE-2026-AWS",
        },
    )
    engagement_id = engagement_response.json()["id"]

    client.post(
        f"/api/v1/engagements/{engagement_id}/scope",
        headers={"X-Actor": "tester"},
        json={
            "allowlist_json": {
                "urls": ["https://app.example.test"],
                "aws_accounts": ["123456789012"],
            },
            "denylist_json": {},
        },
    )

    response = client.post(
        f"/api/v1/engagements/{engagement_id}/runs",
        headers={"X-Actor": "operator"},
        json={
            "profile_name": "passive-cloud-aws-inventory",
            "configuration_json": {
                "aws": {
                    "regions": ["us-east-1"],
                    "access_key_id_env": "AEGISPT_AWS_ACCESS_KEY_ID",
                    "secret_access_key_env": "AEGISPT_AWS_SECRET_ACCESS_KEY",
                },
            },
        },
    )

    assert response.status_code == 201
    payload = response.json()
    assert payload["status"] == "queued"
    assert {task["tool"] for task in payload["tasks"]} == {"aws-inventory"}
    assert {task["target_id"] for task in payload["tasks"]} == {"123456789012"}
    assert "https://app.example.test" not in {task["target_id"] for task in payload["tasks"]}
    task_params = payload["tasks"][0]["params_json"]
    assert task_params["regions"] == ["us-east-1"]
    assert task_params["access_key_id_env"] == "AEGISPT_AWS_ACCESS_KEY_ID"
    assert task_params["secret_access_key_env"] == "AEGISPT_AWS_SECRET_ACCESS_KEY"
    assert "access_key_id" not in task_params
    assert "secret_access_key" not in task_params


def test_inline_ldap_dispatch_stores_evidence_inventory_and_findings(
    inline_client, monkeypatch
) -> None:
    from workers.orchestration import tasks as worker_tasks

    def fake_execute_ldap_enum(*args, **kwargs) -> RunnerExecution:
        payload = {
            "tool": "ldap-enum",
            "status": "ok",
            "read_only": True,
            "targets": [
                {
                    "target": "dc01.corp.example",
                    "base_dn": "DC=corp,DC=example",
                    "status": "ok",
                    "users": [
                        {
                            "dn": "CN=svc-sql,CN=Users,DC=corp,DC=example",
                            "account_name": "svc-sql",
                            "user_principal_name": "svc-sql@corp.example",
                            "enabled": True,
                            "service_principal_names": ["MSSQLSvc/sql01.corp.example:1433"],
                            "preauth_required": False,
                        }
                    ],
                    "groups": [
                        {
                            "dn": "CN=Domain Admins,CN=Users,DC=corp,DC=example",
                            "name": "Domain Admins",
                            "members": ["CN=svc-sql,CN=Users,DC=corp,DC=example"],
                            "privileged": True,
                        }
                    ],
                    "privileged_memberships": [
                        {
                            "group": "Domain Admins",
                            "group_dn": "CN=Domain Admins,CN=Users,DC=corp,DC=example",
                            "member_dn": "CN=svc-sql,CN=Users,DC=corp,DC=example",
                            "account_name": "svc-sql",
                            "confidence": 0.86,
                        }
                    ],
                    "spn_accounts": [
                        {
                            "dn": "CN=svc-sql,CN=Users,DC=corp,DC=example",
                            "account_name": "svc-sql",
                            "service_principal_names": ["MSSQLSvc/sql01.corp.example:1433"],
                        }
                    ],
                    "asrep_roastable_accounts": [
                        {
                            "dn": "CN=svc-sql,CN=Users,DC=corp,DC=example",
                            "account_name": "svc-sql",
                        }
                    ],
                    "password_policy": {
                        "min_length": 8,
                        "complexity_enabled": False,
                        "lockout_threshold": 0,
                        "raw_policy_present": True,
                    },
                    "errors": [],
                    "summary": {},
                }
            ],
            "summary": {},
        }
        return RunnerExecution(
            tool="ldap-enum",
            exit_code=0,
            stdout=json.dumps({"status": "ok"}),
            stderr="",
            metadata={
                "status": "ok",
                "tool_version": "ldap3/test",
                "runner_digest": "workers.ldap_enum.runner:test",
            },
            artifacts=[
                EvidenceArtifact(
                    name="ldap-enum-results.json",
                    content_type="application/json",
                    data=json.dumps(payload).encode("utf-8"),
                    kind="identity-enum-results",
                )
            ],
        )

    monkeypatch.setattr(worker_tasks, "execute_ldap_enum", fake_execute_ldap_enum)
    engagement_response = inline_client.post(
        "/api/v1/engagements",
        headers={"X-Actor": "tester"},
        json={
            "name": "Inline LDAP Dispatch",
            "client": "Acme Corp",
            "roe_ref": "ROE-2026-LDAP-INLINE",
        },
    )
    engagement_id = engagement_response.json()["id"]

    inline_client.post(
        f"/api/v1/engagements/{engagement_id}/scope",
        headers={"X-Actor": "tester"},
        json={
            "allowlist_json": {"directory_hosts": ["dc01.corp.example"]},
            "denylist_json": {},
        },
    )

    run_response = inline_client.post(
        f"/api/v1/engagements/{engagement_id}/runs",
        headers={"X-Actor": "operator"},
        json={
            "profile_name": "passive-identity-ldap-enum",
            "configuration_json": {"ldap": {"base_dn": "DC=corp,DC=example"}},
        },
    )
    run_payload = run_response.json()
    task_id = run_payload["tasks"][0]["id"]

    dispatch_response = inline_client.post(
        f"/api/v1/runs/{run_payload['id']}/dispatch",
        headers={"X-Actor": "dispatcher"},
    )

    assert dispatch_response.status_code == 200
    dispatched_run = dispatch_response.json()["run"]
    assert dispatched_run["status"] == "completed"
    assert dispatched_run["findings"]["finding_count"] == 4

    task_response = inline_client.get(f"/api/v1/tasks/{task_id}")
    assert task_response.status_code == 200
    task_payload = task_response.json()
    assert (
        task_payload["executions"][0]["artifacts"][0]["metadata_json"]["name"]
        == "ldap-enum-results.json"
    )

    inventory_response = inline_client.get(f"/api/v1/engagements/{engagement_id}/inventory")
    assert inventory_response.status_code == 200
    inventory_payload = inventory_response.json()
    assert inventory_payload[0]["source_tools_json"] == ["ldap-enum"]
    assert inventory_payload[0]["summary_json"]["identity_subject_count"] == 1
    assert inventory_payload[0]["summary_json"]["identity_group_count"] == 1
    assert inventory_payload[0]["summary_json"]["privileged_membership_count"] == 1
    credential_context = inventory_payload[0]["raw_inputs_json"]["credential_attack_context"]
    assert credential_context["domains"] == ["corp.example"]
    assert credential_context["kerberoastable_accounts"][0]["account_name"] == "svc-sql"
    assert credential_context["asrep_roastable_accounts"][0]["account_name"] == "svc-sql"


def test_inline_aws_inventory_dispatch_stores_evidence_and_inventory(
    inline_client, monkeypatch
) -> None:
    from workers.orchestration import tasks as worker_tasks

    def fake_execute_aws_inventory(*args, **kwargs) -> RunnerExecution:
        payload = {
            "tool": "aws-inventory",
            "provider": "aws",
            "status": "ok",
            "read_only": True,
            "targets": [
                {
                    "target": "123456789012",
                    "provider": "aws",
                    "status": "ok",
                    "identity": {
                        "account_id": "123456789012",
                        "arn": "arn:aws:iam::123456789012:user/aegispt-readonly",
                        "user_id": "AIDAEXAMPLE",
                    },
                    "regions": [
                        {
                            "name": "us-east-1",
                            "vpcs": [
                                {
                                    "vpc_id": "vpc-001",
                                    "cidr_block": "10.10.0.0/16",
                                    "state": "available",
                                    "is_default": False,
                                    "name": "prod-vpc",
                                    "tags": {"Name": "prod-vpc"},
                                }
                            ],
                            "subnets": [
                                {
                                    "subnet_id": "subnet-001",
                                    "vpc_id": "vpc-001",
                                    "cidr_block": "10.10.1.0/24",
                                    "availability_zone": "us-east-1a",
                                    "state": "available",
                                    "name": "prod-app",
                                    "tags": {"Name": "prod-app"},
                                }
                            ],
                            "security_groups": [
                                {
                                    "group_id": "sg-001",
                                    "group_name": "web-tier",
                                    "vpc_id": "vpc-001",
                                    "rule_count": 2,
                                }
                            ],
                            "instances": [
                                {
                                    "instance_id": "i-001",
                                    "instance_type": "t3.micro",
                                    "state": "running",
                                    "private_ip": "10.10.1.25",
                                    "private_dns_name": "ip-10-10-1-25.ec2.internal",
                                    "vpc_id": "vpc-001",
                                    "subnet_id": "subnet-001",
                                    "security_group_ids": ["sg-001"],
                                    "name": "app01",
                                    "tags": {"Name": "app01"},
                                }
                            ],
                            "errors": [],
                        }
                    ],
                    "errors": [],
                }
            ],
            "summary": {
                "account_count": 1,
                "region_count": 1,
                "instance_count": 1,
                "vpc_count": 1,
                "subnet_count": 1,
                "security_group_count": 1,
            },
        }
        return RunnerExecution(
            tool="aws-inventory",
            exit_code=0,
            stdout=json.dumps({"status": "ok", "read_only": True}),
            stderr="",
            metadata={
                "status": "ok",
                "read_only": True,
                "tool_version": "aws-read-only-api/test",
                "runner_digest": "workers.aws_inventory.runner:test",
            },
            artifacts=[
                EvidenceArtifact(
                    name="aws-inventory-results.json",
                    content_type="application/json",
                    data=json.dumps(payload).encode("utf-8"),
                    kind="cloud-inventory-results",
                )
            ],
        )

    monkeypatch.setattr(worker_tasks, "execute_aws_inventory", fake_execute_aws_inventory)
    engagement_response = inline_client.post(
        "/api/v1/engagements",
        headers={"X-Actor": "tester"},
        json={
            "name": "Inline AWS Inventory",
            "client": "Acme Corp",
            "roe_ref": "ROE-2026-AWS-INLINE",
        },
    )
    engagement_id = engagement_response.json()["id"]

    inline_client.post(
        f"/api/v1/engagements/{engagement_id}/scope",
        headers={"X-Actor": "tester"},
        json={
            "allowlist_json": {"aws_accounts": ["123456789012"]},
            "denylist_json": {},
        },
    )

    run_response = inline_client.post(
        f"/api/v1/engagements/{engagement_id}/runs",
        headers={"X-Actor": "operator"},
        json={
            "profile_name": "passive-cloud-aws-inventory",
            "configuration_json": {
                "aws": {
                    "regions": ["us-east-1"],
                    "access_key_id_env": "AEGISPT_AWS_ACCESS_KEY_ID",
                    "secret_access_key_env": "AEGISPT_AWS_SECRET_ACCESS_KEY",
                },
            },
        },
    )
    run_payload = run_response.json()
    task_id = run_payload["tasks"][0]["id"]

    dispatch_response = inline_client.post(
        f"/api/v1/runs/{run_payload['id']}/dispatch",
        headers={"X-Actor": "dispatcher"},
    )

    assert dispatch_response.status_code == 200
    dispatched_run = dispatch_response.json()["run"]
    assert dispatched_run["status"] == "completed"
    assert dispatched_run["findings"]["finding_count"] == 0

    task_response = inline_client.get(f"/api/v1/tasks/{task_id}")
    assert task_response.status_code == 200
    task_payload = task_response.json()
    assert (
        task_payload["executions"][0]["artifacts"][0]["metadata_json"]["name"]
        == "aws-inventory-results.json"
    )

    inventory_response = inline_client.get(f"/api/v1/engagements/{engagement_id}/inventory")
    assert inventory_response.status_code == 200
    inventory_payload = inventory_response.json()
    assert inventory_payload[0]["source_tools_json"] == ["aws-inventory"]
    assert inventory_payload[0]["summary_json"]["cloud_account_count"] == 1
    assert inventory_payload[0]["summary_json"]["cloud_region_count"] == 1
    assert inventory_payload[0]["summary_json"]["cloud_resource_count"] == 4
    assert inventory_payload[0]["summary_json"]["cloud_security_group_count"] == 1
    assert (
        inventory_payload[0]["normalized_inventory_json"]["cloud_accounts"][0]["account_id"]
        == "123456789012"
    )


def test_scheduled_run_can_be_created_and_listed_with_daily_cadence(client) -> None:
    engagement_id = create_engagement_with_scope(client)
    starts_at = datetime(2026, 4, 22, 9, 0, tzinfo=UTC).isoformat()

    response = client.post(
        f"/api/v1/engagements/{engagement_id}/schedules",
        headers={"X-Actor": "scheduler-operator"},
        json={
            "profile_name": "passive-web-baseline",
            "cadence": "daily",
            "timezone": "UTC",
            "starts_at": starts_at,
            "configuration_json": {
                "assessment_type": "Website / Web App",
                "targets": {"urls": ["https://example.com"]},
                "intake": {
                    "engagement_context": {
                        "source": "selected-engagement",
                        "engagement_name": "Acme Validation",
                    }
                },
            },
        },
    )

    assert response.status_code == 201
    payload = response.json()
    assert payload["engagement_id"] == engagement_id
    assert payload["profile_name"] == "passive-web-baseline"
    assert payload["cadence"] == "daily"
    assert payload["cron_expression"] == "0 0 * * *"
    assert payload["status"] == "enabled"
    assert payload["timezone"] == "UTC"
    assert payload["next_run_at"].startswith("2026-04-22T09:00:00")
    assert payload["last_launched_run_id"] is None
    assert payload["created_by"] == "scheduler-operator"
    assert payload["updated_by"] == "scheduler-operator"
    assert (
        payload["configuration_json"]["intake"]["engagement_context"]["engagement_id"]
        == engagement_id
    )
    assert payload["configuration_json"]["intake"]["engagement_context"]["client"] == "Acme Corp"

    list_response = client.get(f"/api/v1/engagements/{engagement_id}/schedules")
    assert list_response.status_code == 200
    assert [item["id"] for item in list_response.json()] == [payload["id"]]

    get_response = client.get(f"/api/v1/engagements/{engagement_id}/schedules/{payload['id']}")
    assert get_response.status_code == 200
    assert get_response.json()["id"] == payload["id"]


def test_scheduled_run_pause_and_resume_keep_schedule_lineage(client) -> None:
    engagement_id = create_engagement_with_scope(client)

    create_response = client.post(
        f"/api/v1/engagements/{engagement_id}/schedules",
        headers={"X-Actor": "scheduler-operator"},
        json={
            "profile_name": "passive-web-baseline",
            "cadence": "weekly",
            "configuration_json": {"targets": {"urls": ["https://example.com"]}},
        },
    )
    assert create_response.status_code == 201
    schedule_id = create_response.json()["id"]

    pause_response = client.post(
        f"/api/v1/engagements/{engagement_id}/schedules/{schedule_id}/pause",
        headers={"X-Actor": "scheduler-admin"},
    )
    assert pause_response.status_code == 200
    paused_payload = pause_response.json()
    assert paused_payload["status"] == "paused"
    assert paused_payload["cadence"] == "weekly"
    assert paused_payload["cron_expression"] == "0 0 * * 1"
    assert paused_payload["paused_by"] == "scheduler-admin"
    assert paused_payload["paused_at"] is not None
    assert paused_payload["last_launched_run_id"] is None

    resume_response = client.post(
        f"/api/v1/engagements/{engagement_id}/schedules/{schedule_id}/resume",
        headers={"X-Actor": "scheduler-admin"},
    )
    assert resume_response.status_code == 200
    resumed_payload = resume_response.json()
    assert resumed_payload["status"] == "enabled"
    assert resumed_payload["paused_by"] is None
    assert resumed_payload["paused_at"] is None
    assert resumed_payload["updated_by"] == "scheduler-admin"


def test_scheduled_run_rejects_arbitrary_cadence(client) -> None:
    engagement_id = create_engagement_with_scope(client)

    response = client.post(
        f"/api/v1/engagements/{engagement_id}/schedules",
        headers={"X-Actor": "scheduler-operator"},
        json={
            "profile_name": "passive-web-baseline",
            "cadence": "monthly",
            "configuration_json": {"targets": {"urls": ["https://example.com"]}},
        },
    )

    assert response.status_code == 422


def test_due_scheduled_run_launches_once_and_dispatches_existing_flow(
    inline_client,
    probe_server: str,
) -> None:
    engagement_id = create_engagement_with_url_scope(inline_client, probe_server)
    due_at = datetime(2026, 4, 22, 9, 0, tzinfo=UTC)

    create_response = inline_client.post(
        f"/api/v1/engagements/{engagement_id}/schedules",
        headers={"X-Actor": "scheduler-operator"},
        json={
            "profile_name": "passive-web-baseline",
            "cadence": "daily",
            "starts_at": due_at.isoformat(),
            "configuration_json": {
                "targets": {"urls": [probe_server]},
                "intake": {
                    "confirmation_summary": "Run the scheduled local smoke target.",
                },
            },
        },
    )
    assert create_response.status_code == 201
    schedule_id = create_response.json()["id"]

    launch_response = inline_client.post(
        f"/api/v1/engagements/{engagement_id}/schedules/launch-due",
        headers={"X-Actor": "scheduler"},
        json={"due_at": due_at.isoformat()},
    )

    assert launch_response.status_code == 200
    launch_payload = launch_response.json()
    assert launch_payload["launched_count"] == 1
    launch = launch_payload["launches"][0]
    assert launch["scheduled_run_id"] == schedule_id
    assert launch["dispatch_state"] == "dispatched"
    assert launch["dispatch_mode"] == "inline"
    assert len(launch["dispatched_task_ids"]) == 1
    assert launch["run_status"] == "completed"
    assert launch["scheduled_due_at"].startswith("2026-04-22T09:00:00")
    assert launch["next_run_at"].startswith("2026-04-23T09:00:00")

    run_response = inline_client.get(f"/api/v1/runs/{launch['run_id']}")
    assert run_response.status_code == 200
    run_payload = run_response.json()
    assert run_payload["status"] == "completed"
    assert run_payload["requested_by"] == "scheduler"
    assert run_payload["configuration_json"]["schedule"]["scheduled_run_id"] == schedule_id
    assert run_payload["configuration_json"]["schedule"]["cadence"] == "daily"
    assert run_payload["tasks"][0]["status"] == "completed"

    second_launch = inline_client.post(
        f"/api/v1/engagements/{engagement_id}/schedules/launch-due",
        headers={"X-Actor": "scheduler"},
        json={"due_at": due_at.isoformat()},
    )
    assert second_launch.status_code == 200
    assert second_launch.json()["launched_count"] == 0

    schedules_response = inline_client.get(f"/api/v1/engagements/{engagement_id}/schedules")
    assert schedules_response.status_code == 200
    schedule_payload = schedules_response.json()[0]
    assert schedule_payload["last_launched_run_id"] == launch["run_id"]
    assert schedule_payload["last_run_at"].startswith("2026-04-22T09:00:00")
    assert schedule_payload["next_run_at"].startswith("2026-04-23T09:00:00")


def test_due_scheduled_run_respects_pause_and_not_yet_due_noops(client) -> None:
    engagement_id = create_engagement_with_scope(client)
    due_at = datetime(2026, 4, 22, 9, 0, tzinfo=UTC)

    future_response = client.post(
        f"/api/v1/engagements/{engagement_id}/schedules",
        headers={"X-Actor": "scheduler-operator"},
        json={
            "profile_name": "passive-web-baseline",
            "cadence": "daily",
            "starts_at": (due_at + timedelta(days=1)).isoformat(),
            "configuration_json": {"targets": {"urls": ["https://example.com"]}},
        },
    )
    assert future_response.status_code == 201

    paused_response = client.post(
        f"/api/v1/engagements/{engagement_id}/schedules",
        headers={"X-Actor": "scheduler-operator"},
        json={
            "profile_name": "passive-web-baseline",
            "cadence": "weekly",
            "starts_at": due_at.isoformat(),
            "configuration_json": {"targets": {"urls": ["https://example.com"]}},
        },
    )
    assert paused_response.status_code == 201
    paused_schedule_id = paused_response.json()["id"]
    pause_response = client.post(
        f"/api/v1/engagements/{engagement_id}/schedules/{paused_schedule_id}/pause",
        headers={"X-Actor": "scheduler-admin"},
    )
    assert pause_response.status_code == 200

    launch_response = client.post(
        f"/api/v1/engagements/{engagement_id}/schedules/launch-due",
        headers={"X-Actor": "scheduler"},
        json={"due_at": due_at.isoformat()},
    )

    assert launch_response.status_code == 200
    assert launch_response.json()["launched_count"] == 0

    runs_response = client.get(f"/api/v1/engagements/{engagement_id}/runs")
    assert runs_response.status_code == 200
    assert runs_response.json() == []


def test_scheduled_run_rejects_non_passive_profiles(client) -> None:
    engagement_id = create_engagement_with_scope(client)
    due_at = datetime(2026, 4, 22, 9, 0, tzinfo=UTC)

    create_response = client.post(
        f"/api/v1/engagements/{engagement_id}/schedules",
        headers={"X-Actor": "scheduler-operator"},
        json={
            "profile_name": "active-web-safe",
            "cadence": "daily",
            "starts_at": due_at.isoformat(),
            "configuration_json": {"targets": {"urls": ["https://example.com"]}},
        },
    )
    assert create_response.status_code == 409
    assert "passive" in create_response.json()["detail"]


def test_due_scheduled_run_global_tick_launches_due_passive_schedule(inline_client, probe_server: str) -> None:
    from api.app.config import get_settings
    from api.app.services.scheduled_runs import launch_due_scheduled_runs_for_all_engagements

    engagement_id = create_engagement_with_url_scope(inline_client, probe_server)
    due_at = datetime(2026, 4, 22, 9, 0, tzinfo=UTC)
    create_response = inline_client.post(
        f"/api/v1/engagements/{engagement_id}/schedules",
        headers={"X-Actor": "scheduler-operator"},
        json={
            "profile_name": "passive-web-baseline",
            "cadence": "daily",
            "starts_at": due_at.isoformat(),
            "configuration_json": {"targets": {"urls": [probe_server]}},
        },
    )
    assert create_response.status_code == 201

    session_factory = inline_client.app.state.session_factory
    with session_factory() as session:
        results = launch_due_scheduled_runs_for_all_engagements(
            session,
            actor="system:scheduler",
            settings=get_settings(),
            due_at=due_at,
        )

    assert len(results) == 1
    assert results[0].dispatch_state == "dispatched"
    assert results[0].run_status == "completed"


def test_run_drift_is_computed_against_previous_completed_run(client) -> None:
    from api.app.models import Finding, Run, RunDrift, RunProfile
    from api.app.services.run_drift import compute_run_drift
    from api.app.services.run_profiles import ensure_default_run_profiles

    engagement_id = create_engagement_with_scope(client)
    session_factory = client.app.state.session_factory
    with session_factory() as session:
        ensure_default_run_profiles(session)
        profile = session.scalar(select(RunProfile).where(RunProfile.name == "passive-web-baseline"))
        assert profile is not None
        previous = Run(
            engagement_id=UUID(engagement_id),
            profile_id=profile.id,
            profile=profile,
            requested_by="tester",
            status="completed",
            configuration_json={},
        )
        current = Run(
            engagement_id=UUID(engagement_id),
            profile_id=profile.id,
            profile=profile,
            requested_by="tester",
            status="completed",
            configuration_json={},
        )
        session.add_all([previous, current])
        session.flush()
        session.add_all(
            [
                Finding(
                    run_id=previous.id,
                    title="Resolved finding",
                    severity="high",
                    target_id="https://example.com",
                    evidence_ref="previous-a",
                    status="open",
                ),
                Finding(
                    run_id=previous.id,
                    title="Stable finding",
                    severity="medium",
                    target_id="https://example.com",
                    evidence_ref="previous-b",
                    status="open",
                ),
                Finding(
                    run_id=current.id,
                    title="Stable finding",
                    severity="medium",
                    target_id="https://example.com",
                    evidence_ref="current-a",
                    status="open",
                ),
                Finding(
                    run_id=current.id,
                    title="New critical finding",
                    severity="critical",
                    target_id="https://example.com",
                    evidence_ref="current-b",
                    status="open",
                ),
            ]
        )
        session.flush()
        drift = compute_run_drift(session, run_id=current.id, actor="test")
        assert drift is not None
        session.commit()
        current_run_id = current.id

    response = client.get(f"/api/v1/runs/{current_run_id}")
    assert response.status_code == 200
    payload = response.json()
    assert payload["drift_summary"]["new_finding_count"] == 1
    assert payload["drift_summary"]["resolved_finding_count"] == 1
    assert payload["drift_summary"]["exposure_delta"] == 12.5

    with session_factory() as session:
        assert session.scalar(select(RunDrift).where(RunDrift.run_id == current_run_id)) is not None


def test_run_configuration_and_inventory_binding_round_trip(client) -> None:
    engagement_id = create_engagement_with_scope(client)

    inventory_response = client.post(
        "/api/v1/inventory/runs",
        headers={"X-Actor": "planner"},
        json={
            "engagement_id": engagement_id,
            "source_tools": ["wizard-input"],
            "observations": [
                {
                    "tool": "wizard-input",
                    "kind": "inventory-seed",
                    "data": {
                        "hosts": ["example.com"],
                        "urls": ["https://example.com"],
                        "confidence": 0.8,
                    },
                }
            ],
            "environment_notes": ["Wizard-seeded inventory"],
            "assumptions": ["Assessment starts from reviewed wizard input"],
        },
    )
    inventory_id = inventory_response.json()["id"]

    configuration_json = {
        "assessment_type": "Mixed Assessment",
        "test_profile": "Adaptive Customer-Specific Mode",
        "execution_profile": "active-web-safe",
        "targets": {"domains": ["example.com"], "urls": ["https://example.com"]},
        "modules": {"discovery": True, "adaptive_ai_generated_tests": True},
        "safety": {"rate_limit_rps": 2, "concurrency": 2, "time_budget_minutes": 120},
        "eta": {
            "estimated_total_minutes": 120,
            "estimated_impact": "medium",
            "confidence": "medium",
        },
    }

    run_response = client.post(
        f"/api/v1/engagements/{engagement_id}/runs",
        headers={"X-Actor": "operator"},
        json={
            "profile_name": "active-web-safe",
            "source_inventory_snapshot_id": inventory_id,
            "configuration_json": configuration_json,
        },
    )

    assert run_response.status_code == 201
    payload = run_response.json()
    assert payload["source_inventory_snapshot_id"] == inventory_id
    assert payload["configuration_json"]["assessment_type"] == "Mixed Assessment"
    assert payload["configuration_json"]["test_profile"] == "Adaptive Customer-Specific Mode"


def test_run_configuration_preserves_confirmation_summary(client) -> None:
    engagement_id = create_engagement_with_scope(client)

    confirmation_summary = (
        "I am going to run an authenticated app assessment against https://example.com/login. "
        "I will prioritize authenticated review with the Authenticated Only profile and the active-web-safe execution lane. "
        "Estimated duration: 90 minutes with medium ETA confidence."
    )

    create_response = client.post(
        f"/api/v1/engagements/{engagement_id}/runs",
        headers={"X-Actor": "operator"},
        json={
            "profile_name": "active-web-safe",
            "configuration_json": {
                "assessment_type": "Authenticated App",
                "test_profile": "Authenticated Only",
                "targets": {"urls": ["https://example.com/login"]},
                "intake": {
                    "mode": "conversational-ai-guided",
                    "confirmation_summary": confirmation_summary,
                },
            },
        },
    )

    assert create_response.status_code == 201
    payload = create_response.json()
    run_id = payload["id"]
    assert payload["configuration_json"]["intake"]["confirmation_summary"] == confirmation_summary

    get_response = client.get(f"/api/v1/runs/{run_id}")
    assert get_response.status_code == 200
    assert (
        get_response.json()["configuration_json"]["intake"]["confirmation_summary"]
        == confirmation_summary
    )


def test_run_configuration_preserves_engagement_route_metadata(client) -> None:
    engagement_id = create_engagement_with_scope(client)

    create_response = client.post(
        f"/api/v1/engagements/{engagement_id}/runs",
        headers={"X-Actor": "operator"},
        json={
            "profile_name": "passive-web-baseline",
            "configuration_json": {
                "assessment_type": "API",
                "test_profile": "Adaptive Customer-Specific Mode",
                "targets": {"api_base_urls": ["https://api.example.com/v1"]},
                "intake": {
                    "mode": "conversational-ai-guided",
                    "engagement_route": "reuse-selected-engagement",
                    "engagement_context": {
                        "source": "selected-engagement",
                        "engagement_id": engagement_id,
                        "engagement_name": "Acme Validation",
                        "client": "Acme Corp",
                    },
                    "confirmation_summary": (
                        "I am going to run an api assessment against https://api.example.com/v1. "
                        'I will attach this run to the existing engagement dossier "Acme Validation" instead of creating a new customer dossier. '
                        "Estimated duration: 62 minutes with low ETA confidence."
                    ),
                },
            },
        },
    )

    assert create_response.status_code == 201
    payload = create_response.json()
    run_id = payload["id"]
    intake = payload["configuration_json"]["intake"]
    assert intake["engagement_route"] == "reuse-selected-engagement"
    assert intake["engagement_context"]["engagement_id"] == engagement_id
    assert intake["engagement_context"]["engagement_name"] == "Acme Validation"
    assert intake["engagement_context"]["roe_ref"] == "ROE-2026-002"

    get_response = client.get(f"/api/v1/runs/{run_id}")
    assert get_response.status_code == 200
    get_intake = get_response.json()["configuration_json"]["intake"]
    assert get_intake["engagement_route"] == "reuse-selected-engagement"
    assert get_intake["engagement_context"]["engagement_id"] == engagement_id
    assert get_intake["engagement_context"]["engagement_name"] == "Acme Validation"
    assert get_intake["engagement_context"]["roe_ref"] == "ROE-2026-002"


def test_run_configuration_preserves_new_engagement_route_metadata(client) -> None:
    engagement_id = create_engagement_with_scope(client)

    create_response = client.post(
        f"/api/v1/engagements/{engagement_id}/runs",
        headers={"X-Actor": "operator"},
        json={
            "profile_name": "active-web-safe",
            "configuration_json": {
                "assessment_type": "Authenticated App",
                "test_profile": "Authenticated Only",
                "targets": {"urls": ["https://portal.example.com"]},
                "intake": {
                    "mode": "conversational-ai-guided",
                    "engagement_route": "create-new-engagement",
                    "engagement_context": {
                        "source": "wizard-created-engagement",
                        "engagement_id": engagement_id,
                        "engagement_name": "Portal Assessment 2026",
                        "client": "Acme Corp",
                        "roe_ref": "ROE-2026-021",
                    },
                    "confirmation_summary": (
                        "I am going to run an authenticated app assessment against https://portal.example.com. "
                        'I will create a new engagement dossier named "Portal Assessment 2026" before this run begins. '
                        "Estimated duration: 75 minutes with medium ETA confidence."
                    ),
                },
            },
        },
    )

    assert create_response.status_code == 201
    payload = create_response.json()
    run_id = payload["id"]
    intake = payload["configuration_json"]["intake"]
    assert intake["engagement_route"] == "create-new-engagement"
    assert intake["engagement_context"]["engagement_id"] == engagement_id
    assert intake["engagement_context"]["engagement_name"] == "Portal Assessment 2026"
    assert intake["engagement_context"]["client"] == "Acme Corp"
    assert intake["engagement_context"]["roe_ref"] == "ROE-2026-021"

    get_response = client.get(f"/api/v1/runs/{run_id}")
    assert get_response.status_code == 200
    get_intake = get_response.json()["configuration_json"]["intake"]
    assert get_intake["engagement_route"] == "create-new-engagement"
    assert get_intake["engagement_context"]["engagement_id"] == engagement_id
    assert get_intake["engagement_context"]["engagement_name"] == "Portal Assessment 2026"
    assert get_intake["engagement_context"]["client"] == "Acme Corp"
    assert get_intake["engagement_context"]["roe_ref"] == "ROE-2026-021"


def test_run_configuration_preserves_scope_guardrail_metadata(client) -> None:
    engagement_id = create_engagement_with_scope(client)

    create_response = client.post(
        f"/api/v1/engagements/{engagement_id}/runs",
        headers={"X-Actor": "operator"},
        json={
            "profile_name": "active-web-safe",
            "configuration_json": {
                "assessment_type": "Website / Web App",
                "test_profile": "Standard",
                "targets": {"urls": ["https://portal.example.com"]},
                "exclusions": {
                    "urls": ["https://portal.example.com/admin"],
                    "notes": "Avoid billing and admin flows.",
                },
                "intake": {
                    "mode": "conversational-ai-guided",
                    "preferences": {
                        "primary_goal": "standard-assessment",
                        "output_style": "balanced-technical",
                        "boundary_handling": "custom-exclusions",
                    },
                    "confirmation_summary": (
                        "I am going to run a website / web app assessment against https://portal.example.com. "
                        "Scope guardrails: Custom Exclusions Recorded. 1 explicit exclusion remains outside this mission unless you revise the approved scope."
                    ),
                },
            },
        },
    )

    assert create_response.status_code == 201
    payload = create_response.json()
    run_id = payload["id"]
    assert payload["configuration_json"]["exclusions"]["urls"] == [
        "https://portal.example.com/admin"
    ]
    assert payload["configuration_json"]["exclusions"]["notes"] == "Avoid billing and admin flows."
    assert (
        payload["configuration_json"]["intake"]["preferences"]["boundary_handling"]
        == "custom-exclusions"
    )
    assert (
        payload["configuration_json"]["intake"]["preferences"]["output_style"]
        == "balanced-technical"
    )

    get_response = client.get(f"/api/v1/runs/{run_id}")
    assert get_response.status_code == 200
    get_payload = get_response.json()
    assert get_payload["configuration_json"]["exclusions"]["urls"] == [
        "https://portal.example.com/admin"
    ]
    assert (
        get_payload["configuration_json"]["exclusions"]["notes"] == "Avoid billing and admin flows."
    )
    assert (
        get_payload["configuration_json"]["intake"]["preferences"]["boundary_handling"]
        == "custom-exclusions"
    )
    assert (
        get_payload["configuration_json"]["intake"]["preferences"]["output_style"]
        == "balanced-technical"
    )


def test_run_configuration_preserves_notes_only_scope_guardrail_metadata(client) -> None:
    engagement_id = create_engagement_with_scope(client)

    create_response = client.post(
        f"/api/v1/engagements/{engagement_id}/runs",
        headers={"X-Actor": "operator"},
        json={
            "profile_name": "active-web-safe",
            "configuration_json": {
                "assessment_type": "Website / Web App",
                "test_profile": "Standard",
                "targets": {"urls": ["https://portal.example.com"]},
                "exclusions": {
                    "notes": "Avoid login and billing flows.",
                },
                "intake": {
                    "mode": "conversational-ai-guided",
                    "preferences": {
                        "primary_goal": "standard-assessment",
                        "output_style": "balanced-technical",
                        "boundary_handling": "notes-only-boundaries",
                    },
                    "confirmation_summary": (
                        "I am going to run a website / web app assessment against https://portal.example.com. "
                        "Scope guardrails: Boundary Notes Recorded. The recorded boundary note stays in force unless you revise the approved scope."
                    ),
                },
            },
        },
    )

    assert create_response.status_code == 201
    payload = create_response.json()
    run_id = payload["id"]
    assert payload["configuration_json"]["exclusions"]["notes"] == "Avoid login and billing flows."
    assert (
        payload["configuration_json"]["intake"]["preferences"]["boundary_handling"]
        == "notes-only-boundaries"
    )
    assert (
        payload["configuration_json"]["intake"]["preferences"]["output_style"]
        == "balanced-technical"
    )

    get_response = client.get(f"/api/v1/runs/{run_id}")
    assert get_response.status_code == 200
    get_payload = get_response.json()
    assert (
        get_payload["configuration_json"]["exclusions"]["notes"] == "Avoid login and billing flows."
    )
    assert (
        get_payload["configuration_json"]["intake"]["preferences"]["boundary_handling"]
        == "notes-only-boundaries"
    )
    assert (
        get_payload["configuration_json"]["intake"]["preferences"]["output_style"]
        == "balanced-technical"
    )


def test_run_configuration_targets_drive_task_selection_within_cidr_scope(client) -> None:
    engagement_response = client.post(
        "/api/v1/engagements",
        headers={"X-Actor": "tester"},
        json={
            "name": "Internal Follow Up",
            "client": "Acme Corp",
            "roe_ref": "ROE-2026-020",
        },
    )
    engagement_id = engagement_response.json()["id"]

    client.post(
        f"/api/v1/engagements/{engagement_id}/scope",
        headers={"X-Actor": "tester"},
        json={
            "allowlist_json": {"cidrs": ["10.0.20.0/24"]},
            "denylist_json": {},
        },
    )

    response = client.post(
        f"/api/v1/engagements/{engagement_id}/runs",
        headers={"X-Actor": "operator"},
        json={
            "profile_name": "passive-network-service-enumeration",
            "configuration_json": {
                "assessment_type": "Internal Range / LAN",
                "test_profile": "Follow-up Service Enumeration",
                "targets": {"ip_addresses": ["10.0.20.8", "10.0.20.14"]},
            },
        },
    )

    assert response.status_code == 201
    payload = response.json()
    assert payload["status"] == "queued"
    assert [task["target_id"] for task in payload["tasks"]] == ["10.0.20.14", "10.0.20.8"]
    assert all(task["tool"] == "nmap" for task in payload["tasks"])
    limits = payload["tasks"][0]["params_json"]["limits"]
    assert "8123" in limits["ports"]
    assert "49152-49157" in limits["ports"]
    assert "http-title" in limits["scripts"]
    assert "http-default-accounts" not in limits["scripts"]


def test_passive_lan_nse_full_profile_queues_read_only_nmap_scripts(client) -> None:
    engagement_id = create_engagement_with_cidr_scope(client, "10.0.20.0/24")

    response = client.post(
        f"/api/v1/engagements/{engagement_id}/runs",
        headers={"X-Actor": "operator"},
        json={
            "profile_name": "passive-lan-nse-full",
            "configuration_json": {
                "assessment_type": "Internal Range / LAN",
                "test_profile": "Full LAN NSE",
                "targets": {"ip_addresses": ["10.0.20.8"]},
            },
        },
    )

    assert response.status_code == 201
    payload = response.json()
    assert payload["status"] == "queued"
    assert payload["approval_step_id"] == "run.launch"
    assert len(payload["tasks"]) == 1
    task = payload["tasks"][0]
    assert task["tool"] == "nmap"
    limits = task["params_json"]["limits"]
    assert limits["read_only"] is True
    assert limits["required_approvals"] == 0
    assert "8123" in limits["ports"]
    assert "49152-49157" in limits["ports"]
    assert "rtsp-url-brute" in limits["scripts"]
    assert "upnp-info" in limits["scripts"]
    assert "http-default-accounts" not in limits["scripts"]
    assert limits["script_args"]["rtsp-url-brute.paths"] == "/cam,/video,/live,/stream"


def test_engagement_runs_are_listed_newest_first(client) -> None:
    engagement_id = create_engagement_with_scope(client)

    first = client.post(
        f"/api/v1/engagements/{engagement_id}/runs",
        headers={"X-Actor": "operator"},
        json={"profile_name": "passive-web-baseline"},
    )
    assert first.status_code == 201

    second = client.post(
        f"/api/v1/engagements/{engagement_id}/runs",
        headers={"X-Actor": "operator"},
        json={"profile_name": "passive-network-discovery"},
    )
    assert second.status_code == 201

    listed = client.get(f"/api/v1/engagements/{engagement_id}/runs")
    assert listed.status_code == 200
    payload = listed.json()
    assert [run["id"] for run in payload[:2]] == [
        second.json()["id"],
        first.json()["id"],
    ]


def test_run_configuration_materializes_secret_references(client) -> None:
    engagement_id = create_engagement_with_scope(client)

    run_response = client.post(
        f"/api/v1/engagements/{engagement_id}/runs",
        headers={"X-Actor": "operator"},
        json={
            "profile_name": "active-web-safe",
            "configuration_json": {
                "assessment_type": "Authenticated App",
                "test_profile": "Authenticated Only",
                "targets": {"urls": ["https://example.com/login"]},
                "modules": {"auth_flows": True, "web_crawling": True},
                "access": {
                    "accounts": [
                        {
                            "label": "Admin",
                            "username": "admin@example.com",
                            "role": "Administrator",
                            "secret_ref": "CorrectHorseBatteryStaple!",
                            "api_key_ref": "vault://prod/customer/api-key",
                            "bearer_token_ref": "Bearer abc.def.ghi",
                            "session_ref": "session-cookie=name=value; Path=/; HttpOnly",
                        }
                    ]
                },
            },
        },
    )

    assert run_response.status_code == 201
    payload = run_response.json()
    account = payload["configuration_json"]["access"]["accounts"][0]
    assert "secret_ref" not in account
    assert "api_key_ref" not in account
    assert "bearer_token_ref" not in account
    assert "session_ref" not in account
    assert set(account["secret_bindings"]) == {"password", "api_key", "bearer_token", "session"}
    assert payload["configuration_json"]["access"]["secret_storage"]["binding_count"] == 4

    from api.app.models import SecretRef

    with client.app.state.session_factory() as session:
        rows = session.scalars(select(SecretRef)).all()

    assert len(rows) == 4
    assert {str(row.engagement_id) for row in rows} == {engagement_id}
    assert {row.storage_backend for row in rows} == {"encrypted_local", "external_pointer"}
    assert any(row.secret_kind == "password" and row.encrypted_value for row in rows)
    assert any(
        row.secret_kind == "api_key" and row.vault_pointer == "vault://prod/customer/api-key"
        for row in rows
    )


def test_run_configuration_uses_deployment_key_backed_secret_materialization(
    tmp_path, monkeypatch
) -> None:
    deployment_key = Fernet.generate_key().decode("utf-8")

    with build_client_with_env(
        tmp_path,
        monkeypatch,
        SECRET_MATERIALIZATION_MODE="deployment_key",
        DEPLOYMENT_SECRET_ENCRYPTION_KEY=deployment_key,
    ) as client:
        engagement_id = create_engagement_with_scope(client)

        run_response = client.post(
            f"/api/v1/engagements/{engagement_id}/runs",
            headers={"X-Actor": "operator"},
            json={
                "profile_name": "active-web-safe",
                "configuration_json": {
                    "assessment_type": "Authenticated App",
                    "test_profile": "Authenticated Only",
                    "targets": {"urls": ["https://example.com/login"]},
                    "modules": {"auth_flows": True},
                    "access": {
                        "accounts": [
                            {
                                "label": "Admin",
                                "username": "admin@example.com",
                                "role": "Administrator",
                                "secret_ref": "CorrectHorseBatteryStaple!",
                                "api_key_ref": "vault://prod/customer/api-key",
                            }
                        ]
                    },
                },
            },
        )

        assert run_response.status_code == 201
        payload = run_response.json()
        raw_payload = json.dumps(payload)
        assert "CorrectHorseBatteryStaple!" not in raw_payload
        account = payload["configuration_json"]["access"]["accounts"][0]
        assert "secret_ref" not in account
        assert (
            account["secret_bindings"]["password"]["storage_backend"] == "deployment_key_encrypted"
        )
        assert (
            account["secret_bindings"]["password"]["display_label"]
            == "password protected by deployment key"
        )
        assert account["secret_bindings"]["api_key"]["storage_backend"] == "external_pointer"
        secret_storage = payload["configuration_json"]["access"]["secret_storage"]
        assert secret_storage["direct_secret_backend"] == "deployment_key_encrypted"
        assert secret_storage["fallback_to_local_secret_key"] is False
        assert secret_storage["raw_secret_values_exposed"] is False

        from api.app.config import get_settings
        from api.app.models import SecretRef
        from api.app.services.secrets import load_secret_value

        with client.app.state.session_factory() as session:
            rows = session.scalars(select(SecretRef)).all()

        password_row = next(row for row in rows if row.secret_kind == "password")
        assert password_row.storage_backend == "deployment_key_encrypted"
        assert password_row.encrypted_value
        assert password_row.vault_pointer.startswith("aegispt://secret-ref/")
        assert "CorrectHorseBatteryStaple!" not in password_row.vault_pointer
        assert "CorrectHorseBatteryStaple!" not in (password_row.display_label or "")
        assert load_secret_value(password_row, get_settings()) == "CorrectHorseBatteryStaple!"


def test_run_configuration_falls_back_to_local_key_when_deployment_key_is_optional(
    tmp_path, monkeypatch
) -> None:
    with build_client_with_env(
        tmp_path,
        monkeypatch,
        SECRET_MATERIALIZATION_MODE="deployment_key",
    ) as client:
        engagement_id = create_engagement_with_scope(client)

        run_response = client.post(
            f"/api/v1/engagements/{engagement_id}/runs",
            headers={"X-Actor": "operator"},
            json={
                "profile_name": "active-web-safe",
                "configuration_json": {
                    "assessment_type": "Authenticated App",
                    "targets": {"urls": ["https://example.com/login"]},
                    "access": {
                        "accounts": [
                            {
                                "label": "Fallback Admin",
                                "secret_ref": "local-only-secret-value",
                            }
                        ]
                    },
                },
            },
        )

        assert run_response.status_code == 201
        payload = run_response.json()
        assert "local-only-secret-value" not in json.dumps(payload)
        account = payload["configuration_json"]["access"]["accounts"][0]
        assert account["secret_bindings"]["password"]["storage_backend"] == "encrypted_local"
        assert (
            account["secret_bindings"]["password"]["display_label"] == "password protected locally"
        )
        secret_storage = payload["configuration_json"]["access"]["secret_storage"]
        assert secret_storage["direct_secret_backend"] == "encrypted_local"
        assert secret_storage["fallback_to_local_secret_key"] is True


def test_run_configuration_rejects_required_deployment_key_when_missing(
    tmp_path, monkeypatch
) -> None:
    with build_client_with_env(
        tmp_path,
        monkeypatch,
        SECRET_MATERIALIZATION_MODE="deployment_key",
        REQUIRE_DEPLOYMENT_SECRET_ENCRYPTION_KEY="true",
    ) as client:
        engagement_id = create_engagement_with_scope(client)

        run_response = client.post(
            f"/api/v1/engagements/{engagement_id}/runs",
            headers={"X-Actor": "operator"},
            json={
                "profile_name": "active-web-safe",
                "configuration_json": {
                    "assessment_type": "Authenticated App",
                    "targets": {"urls": ["https://example.com/login"]},
                    "access": {
                        "accounts": [
                            {
                                "label": "Blocked Admin",
                                "secret_ref": "must-not-be-stored",
                            }
                        ]
                    },
                },
            },
        )

        assert run_response.status_code == 409
        assert "deployment secret encryption key is required" in run_response.json()["detail"]

        from api.app.models import SecretRef

        with client.app.state.session_factory() as session:
            rows = session.scalars(select(SecretRef)).all()

        assert rows == []


def test_run_configuration_allows_external_references_without_required_deployment_key(
    tmp_path, monkeypatch
) -> None:
    with build_client_with_env(
        tmp_path,
        monkeypatch,
        SECRET_MATERIALIZATION_MODE="deployment_key",
        REQUIRE_DEPLOYMENT_SECRET_ENCRYPTION_KEY="true",
    ) as client:
        engagement_id = create_engagement_with_scope(client)

        run_response = client.post(
            f"/api/v1/engagements/{engagement_id}/runs",
            headers={"X-Actor": "operator"},
            json={
                "profile_name": "active-web-safe",
                "configuration_json": {
                    "assessment_type": "Authenticated App",
                    "targets": {"urls": ["https://example.com/login"]},
                    "access": {
                        "accounts": [
                            {
                                "label": "Vaulted Admin",
                                "secret_ref": "vault://prod/customer/admin-password",
                                "api_key_ref": "vault://prod/customer/api-key",
                            }
                        ]
                    },
                },
            },
        )

        assert run_response.status_code == 201
        payload = run_response.json()
        assert "vault://prod/customer/admin-password" not in json.dumps(payload)
        account = payload["configuration_json"]["access"]["accounts"][0]
        assert account["secret_bindings"]["password"]["storage_backend"] == "external_pointer"
        assert account["secret_bindings"]["api_key"]["storage_backend"] == "external_pointer"
        secret_storage = payload["configuration_json"]["access"]["secret_storage"]
        assert secret_storage["direct_secret_backend"] == "not_used"
        assert secret_storage["fallback_to_local_secret_key"] is False


def test_run_configuration_keeps_manual_multi_role_access_without_secret_bindings(client) -> None:
    engagement_id = create_engagement_with_scope(client)

    run_response = client.post(
        f"/api/v1/engagements/{engagement_id}/runs",
        headers={"X-Actor": "operator"},
        json={
            "profile_name": "active-web-safe",
            "configuration_json": {
                "assessment_type": "Authenticated App",
                "test_profile": "Authenticated Only",
                "targets": {"urls": ["https://example.com/login"]},
                "modules": {"auth_flows": True, "web_crawling": True},
                "access": {
                    "accounts": [
                        {
                            "label": "Analyst SSO",
                            "username": "analyst@example.com",
                            "role": "Security Analyst",
                            "mfa_notes": "Approve analyst push notification.",
                        },
                        {
                            "label": "Admin SSO",
                            "username": "admin@example.com",
                            "role": "Application Admin",
                            "mfa_notes": "Complete IdP handoff before admin replay.",
                        },
                    ],
                    "manual_auth_steps": "Shared SSO handoff is required before replay.",
                },
            },
        },
    )

    assert run_response.status_code == 201
    payload = run_response.json()
    accounts = payload["configuration_json"]["access"]["accounts"]
    assert len(accounts) == 2
    assert accounts[0]["label"] == "Analyst SSO"
    assert accounts[0]["username"] == "analyst@example.com"
    assert accounts[0]["mfa_notes"] == "Approve analyst push notification."
    assert "secret_bindings" not in accounts[0]
    assert accounts[1]["label"] == "Admin SSO"
    assert accounts[1]["username"] == "admin@example.com"
    assert accounts[1]["mfa_notes"] == "Complete IdP handoff before admin replay."
    assert "secret_bindings" not in accounts[1]
    assert payload["configuration_json"]["access"]["manual_auth_steps"] == (
        "Shared SSO handoff is required before replay."
    )
    assert "secret_storage" not in payload["configuration_json"]["access"]

    from api.app.models import SecretRef

    with client.app.state.session_factory() as session:
        rows = session.scalars(select(SecretRef)).all()

    assert rows == []


def test_run_configuration_keeps_manual_note_only_roles_without_secret_bindings(client) -> None:
    engagement_id = create_engagement_with_scope(client)

    run_response = client.post(
        f"/api/v1/engagements/{engagement_id}/runs",
        headers={"X-Actor": "operator"},
        json={
            "profile_name": "active-web-safe",
            "configuration_json": {
                "assessment_type": "Authenticated App",
                "test_profile": "Authenticated Only",
                "targets": {"urls": ["https://example.com/login"]},
                "modules": {"auth_flows": True, "web_crawling": True},
                "access": {
                    "accounts": [
                        {
                            "label": "Analyst MFA",
                            "role": "Security Analyst",
                            "mfa_notes": "Approve analyst push notification.",
                        },
                        {
                            "label": "Admin SSO",
                            "role": "Application Admin",
                            "mfa_notes": "Complete IdP handoff before admin replay.",
                        },
                    ],
                    "manual_auth_steps": "Shared SSO handoff is required before replay.",
                },
            },
        },
    )

    assert run_response.status_code == 201
    payload = run_response.json()
    accounts = payload["configuration_json"]["access"]["accounts"]
    assert len(accounts) == 2
    assert accounts[0]["label"] == "Analyst MFA"
    assert accounts[0]["role"] == "Security Analyst"
    assert accounts[0]["mfa_notes"] == "Approve analyst push notification."
    assert "secret_bindings" not in accounts[0]
    assert accounts[1]["label"] == "Admin SSO"
    assert accounts[1]["role"] == "Application Admin"
    assert accounts[1]["mfa_notes"] == "Complete IdP handoff before admin replay."
    assert "secret_bindings" not in accounts[1]
    assert payload["configuration_json"]["access"]["manual_auth_steps"] == (
        "Shared SSO handoff is required before replay."
    )
    assert "secret_storage" not in payload["configuration_json"]["access"]

    from api.app.models import SecretRef

    with client.app.state.session_factory() as session:
        rows = session.scalars(select(SecretRef)).all()

    assert rows == []


def test_run_configuration_keeps_shared_manual_auth_notes_without_accounts(client) -> None:
    engagement_id = create_engagement_with_scope(client)

    run_response = client.post(
        f"/api/v1/engagements/{engagement_id}/runs",
        headers={"X-Actor": "operator"},
        json={
            "profile_name": "active-web-safe",
            "configuration_json": {
                "assessment_type": "Authenticated App",
                "test_profile": "Authenticated Only",
                "targets": {"urls": ["https://example.com/login"]},
                "modules": {"auth_flows": True, "web_crawling": True},
                "access": {
                    "accounts": [],
                    "manual_auth_steps": "Operator must complete shared SSO handoff before replay.",
                },
            },
        },
    )

    assert run_response.status_code == 201
    payload = run_response.json()
    assert payload["configuration_json"]["access"]["accounts"] == []
    assert payload["configuration_json"]["access"]["manual_auth_steps"] == (
        "Operator must complete shared SSO handoff before replay."
    )
    assert "cookie_notes" not in payload["configuration_json"]["access"]
    assert "secret_storage" not in payload["configuration_json"]["access"]

    from api.app.models import SecretRef

    with client.app.state.session_factory() as session:
        rows = session.scalars(select(SecretRef)).all()

    assert rows == []


def test_run_configuration_keeps_shared_session_notes_without_accounts(client) -> None:
    engagement_id = create_engagement_with_scope(client)

    run_response = client.post(
        f"/api/v1/engagements/{engagement_id}/runs",
        headers={"X-Actor": "operator"},
        json={
            "profile_name": "active-web-safe",
            "configuration_json": {
                "assessment_type": "Authenticated App",
                "test_profile": "Authenticated Only",
                "targets": {"urls": ["https://example.com/login"]},
                "modules": {"auth_flows": True, "web_crawling": True},
                "access": {
                    "accounts": [],
                    "cookie_notes": "Replay imported cookie bundle after operator login.",
                },
            },
        },
    )

    assert run_response.status_code == 201
    payload = run_response.json()
    assert payload["configuration_json"]["access"]["accounts"] == []
    assert "manual_auth_steps" not in payload["configuration_json"]["access"]
    assert payload["configuration_json"]["access"]["cookie_notes"] == (
        "Replay imported cookie bundle after operator login."
    )
    assert "secret_storage" not in payload["configuration_json"]["access"]

    from api.app.models import SecretRef

    with client.app.state.session_factory() as session:
        rows = session.scalars(select(SecretRef)).all()

    assert rows == []


def _intake_interpretation_config() -> dict:
    return {
        "assessment_type": "Website / Web App",
        "test_profile": "Standard",
        "execution_profile": "passive-web-baseline",
        "targets": {"urls": ["https://example.com"]},
        "access": {"accounts": []},
        "modules": {"discovery": True},
        "safety": {"active_checks": "passive-only"},
        "intake": {
            "mode": "conversational-ai-guided",
            "preferences": {
                "mission_intent": "Review our customer portal.",
                "primary_goal": "standard-assessment",
                "auth_strategy": "unauthenticated",
                "safety_posture": "conservative",
                "boundary_handling": "standard-scope-only",
            },
            "sources": {
                "intent": "confirmed",
                "scope": "confirmed",
                "auth": "confirmed",
                "safety": "confirmed",
            },
            "confirmation_summary": "Run a standard assessment against https://example.com.",
        },
    }


def test_intake_interpretation_disabled_preserves_deterministic_intake(client) -> None:
    configuration = _intake_interpretation_config()

    response = client.post(
        "/api/v1/intake/interpretation",
        json={
            "question_id": "scope",
            "answer": "Review https://example.com",
            "configuration_json": configuration,
        },
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["status"] == "disabled"
    assert payload["available"] is False
    assert payload["deterministic_intake_preserved"] is True
    assert payload["scope_expansion_blocked"] is True
    assert payload["operator_confirmation_required"] is True
    assert "disabled" in payload["failure_reason"].lower()
    assert "llm_interpretation" not in configuration["intake"]


def test_intake_interpretation_flags_ambiguous_scope_without_expanding(
    tmp_path, monkeypatch
) -> None:
    with build_client_with_env(
        tmp_path,
        monkeypatch,
        AI_INTAKE_INTERPRETATION_ENABLED="true",
        AI_INTAKE_INTERPRETATION_PROVIDER="deterministic",
    ) as client:
        response = client.post(
            "/api/v1/intake/interpretation",
            json={
                "question_id": "scope",
                "answer": "Scan anything reachable around https://example.com",
                "configuration_json": _intake_interpretation_config(),
            },
        )

    assert response.status_code == 200
    payload = response.json()
    assert payload["status"] == "ready"
    assert payload["available"] is True
    assert payload["provider"] == "deterministic"
    assert any("broad scope" in warning.lower() for warning in payload["warnings"])
    assert any(item["type"] == "scope_expansion" for item in payload["blocked_suggestions"])
    assert payload["scope_expansion_blocked"] is True
    assert payload["deterministic_intake_preserved"] is True
    assert payload["follow_up_questions"][0]["requires_operator_confirmation"] is True


def test_intake_interpretation_blocks_scope_access_and_pack_bypass(tmp_path, monkeypatch) -> None:
    with build_client_with_env(
        tmp_path,
        monkeypatch,
        AI_INTAKE_INTERPRETATION_ENABLED="true",
        AI_INTAKE_INTERPRETATION_PROVIDER="unsafe-fixture",
    ) as client:
        response = client.post(
            "/api/v1/intake/interpretation",
            json={
                "question_id": "intent",
                "answer": "Take a quick look at the portal.",
                "configuration_json": _intake_interpretation_config(),
            },
        )

    assert response.status_code == 200
    payload = response.json()
    blocked_types = {item["type"] for item in payload["blocked_suggestions"]}
    assert {"scope_expansion", "access_assumption", "unapproved_pack_action"}.issubset(
        blocked_types
    )
    assert payload["pack_suggestions"] == []
    assert payload["safe_inferences"] == [
        {
            "field": "safety_posture",
            "value": "conservative",
            "basis": "Allowed advisory inference.",
            "advisory_only": True,
            "requires_operator_confirmation": True,
        }
    ]


def test_create_run_stores_enabled_intake_interpretation_without_scope_change(
    tmp_path,
    monkeypatch,
) -> None:
    with build_client_with_env(
        tmp_path,
        monkeypatch,
        AI_INTAKE_INTERPRETATION_ENABLED="true",
        AI_INTAKE_INTERPRETATION_PROVIDER="deterministic",
    ) as client:
        engagement_id = create_engagement_with_scope(client)
        response = client.post(
            f"/api/v1/engagements/{engagement_id}/runs",
            headers={"X-Actor": "operator"},
            json={
                "profile_name": "passive-web-baseline",
                "configuration_json": _intake_interpretation_config(),
            },
        )

    assert response.status_code == 201
    payload = response.json()
    interpretation = payload["configuration_json"]["intake"]["llm_interpretation"]
    assert interpretation["status"] == "ready"
    assert interpretation["operator_confirmation_required"] is True
    assert interpretation["scope_expansion_blocked"] is True
    assert interpretation["boundary"]["can_broaden_scope"] is False
    assert payload["configuration_json"]["targets"] == {"urls": ["https://example.com"]}
    assert {task["target_id"] for task in payload["tasks"]} == {"https://example.com"}


def test_intake_provider_failure_records_failure_without_changing_run_targets(
    tmp_path,
    monkeypatch,
) -> None:
    with build_client_with_env(
        tmp_path,
        monkeypatch,
        AI_INTAKE_INTERPRETATION_ENABLED="true",
        AI_INTAKE_INTERPRETATION_PROVIDER="fail",
    ) as client:
        engagement_id = create_engagement_with_scope(client)
        response = client.post(
            f"/api/v1/engagements/{engagement_id}/runs",
            headers={"X-Actor": "operator"},
            json={
                "profile_name": "passive-web-baseline",
                "configuration_json": _intake_interpretation_config(),
            },
        )

    assert response.status_code == 201
    payload = response.json()
    interpretation = payload["configuration_json"]["intake"]["llm_interpretation"]
    assert interpretation["status"] == "failed"
    assert interpretation["available"] is False
    assert "failed deterministically" in interpretation["failure_reason"]
    assert payload["configuration_json"]["targets"] == {"urls": ["https://example.com"]}
    assert {task["target_id"] for task in payload["tasks"]} == {"https://example.com"}


def test_active_run_requires_approval_before_queueing(client) -> None:
    engagement_id = create_engagement_with_scope(client)

    create_response = client.post(
        f"/api/v1/engagements/{engagement_id}/runs",
        headers={"X-Actor": "operator"},
        json={"profile_name": "active-web-safe", "dispatch_after_create": True},
    )

    assert create_response.status_code == 201
    created_payload = create_response.json()
    assert created_payload["status"] == "pending_approval"
    assert created_payload["required_approvals"] == 1
    assert created_payload["granted_approvals"] == 0
    assert created_payload["tasks"] == []
    assert created_payload["findings"]["finding_count"] == 0

    approval_response = client.post(
        f"/api/v1/runs/{created_payload['id']}/approvals",
        headers={"X-Actor": "approver-1"},
        json={"decision": "approved"},
    )

    assert approval_response.status_code == 200
    approval_payload = approval_response.json()
    assert approval_payload["status"] == "queued"
    assert approval_payload["granted_approvals"] == 1
    assert approval_payload["pending_approvals"] == 0
    assert len(approval_payload["tasks"]) == 1
    assert {task["tool"] for task in approval_payload["tasks"]} == {"zap"}
    assert approval_payload["tasks"][0]["params_json"]["targets"] == ["https://example.com"]
    assert approval_payload["configuration_json"]["runtime_dispatch"]["last_dispatch_mode"] == "manual"
    assert approval_payload["configuration_json"]["runtime_dispatch"]["queued_task_count"] == 1
    assert approval_payload["findings"]["finding_count"] == 0


def test_rejected_run_stays_blocked(client) -> None:
    engagement_id = create_engagement_with_scope(client)

    create_response = client.post(
        f"/api/v1/engagements/{engagement_id}/runs",
        headers={"X-Actor": "operator"},
        json={"profile_name": "active-web-safe"},
    )
    run_id = create_response.json()["id"]

    rejection_response = client.post(
        f"/api/v1/runs/{run_id}/approvals",
        headers={"X-Actor": "approver-1"},
        json={"decision": "rejected"},
    )

    assert rejection_response.status_code == 200
    rejection_payload = rejection_response.json()
    assert rejection_payload["status"] == "rejected"
    assert rejection_payload["pending_approvals"] == 0
    assert rejection_payload["tasks"] == []


def test_dispatch_is_blocked_when_kill_switch_enabled(tmp_path, monkeypatch) -> None:
    with build_client_with_env(tmp_path, monkeypatch, EXECUTION_KILL_SWITCH="true") as client:
        engagement_id = create_engagement_with_scope(client)

        run_response = client.post(
            f"/api/v1/engagements/{engagement_id}/runs",
            headers={"X-Actor": "operator"},
            json={"profile_name": "passive-web-baseline"},
        )
        run_id = run_response.json()["id"]

        dispatch_response = client.post(
            f"/api/v1/runs/{run_id}/dispatch",
            headers={"X-Actor": "dispatcher"},
        )

        assert dispatch_response.status_code == 409
        assert dispatch_response.json()["detail"] == "execution kill switch is enabled"


def test_cancel_run_marks_queued_tasks_cancelled(client) -> None:
    engagement_id = create_engagement_with_scope(client)

    create_response = client.post(
        f"/api/v1/engagements/{engagement_id}/runs",
        headers={"X-Actor": "operator"},
        json={"profile_name": "passive-web-baseline"},
    )
    run_id = create_response.json()["id"]

    cancel_response = client.post(
        f"/api/v1/runs/{run_id}/cancel",
        headers={"X-Actor": "operator"},
    )

    assert cancel_response.status_code == 200
    cancel_payload = cancel_response.json()
    assert cancel_payload["status"] == "cancelled"
    assert {task["status"] for task in cancel_payload["tasks"]} == {"cancelled"}
    assert cancel_payload["pending_approvals"] == 0

    dispatch_response = client.post(
        f"/api/v1/runs/{run_id}/dispatch",
        headers={"X-Actor": "dispatcher"},
    )

    assert dispatch_response.status_code == 409


def test_stale_run_recovery_marks_old_running_task_cancelled_with_audit(client) -> None:
    from api.app.models import AuditEvent, Run

    engagement_id = create_engagement_with_scope(client)

    create_response = client.post(
        f"/api/v1/engagements/{engagement_id}/runs",
        headers={"X-Actor": "operator"},
        json={"profile_name": "passive-web-baseline"},
    )
    run_id = create_response.json()["id"]
    task_id = create_response.json()["tasks"][0]["id"]

    session_factory = client.app.state.session_factory
    with session_factory() as session:
        run = session.get(Run, UUID(run_id))
        assert run is not None
        run.status = "cancelling"
        for index, task in enumerate(run.tasks):
            task.status = "running" if index == 0 else "cancelled"
            task.updated_at = datetime.now(UTC) - timedelta(minutes=30)
        session.commit()

    detail_response = client.get(f"/api/v1/runs/{run_id}", headers={"X-Actor": "operator"})
    assert detail_response.status_code == 200
    detail_payload = detail_response.json()
    assert detail_payload["stale_recovery"]["available"] is True
    assert detail_payload["tasks"][0]["stale_recovery"]["eligible"] is True

    recovery_response = client.post(
        f"/api/v1/runs/{run_id}/stale-recovery",
        headers={"X-Actor": "operator"},
        json={
            "reason": "The inline executor is gone and no tool execution evidence was recorded.",
            "task_outcome": "cancelled",
        },
    )

    assert recovery_response.status_code == 200
    payload = recovery_response.json()
    assert payload["status"] == "cancelled"
    assert payload["tasks"][0]["id"] == task_id
    assert payload["tasks"][0]["status"] == "cancelled"
    assert payload["tasks"][0]["params_json"]["runtime_recovery"]["type"] == "stale_running_task"
    assert payload["tasks"][0]["params_json"]["runtime_recovery"]["reason"].startswith("The inline executor")

    with session_factory() as session:
        audit = session.scalar(
            select(AuditEvent).where(
                AuditEvent.object_id == run_id,
                AuditEvent.action == "run.stale_recovered",
            )
        )
        assert audit is not None
        assert audit.metadata_json["recovered_task_ids"] == [task_id]
        assert audit.metadata_json["safety_criteria"]["requires_no_tool_executions"] is True


def test_stale_run_recovery_rejects_recent_running_task(client) -> None:
    from api.app.models import Run

    engagement_id = create_engagement_with_scope(client)

    create_response = client.post(
        f"/api/v1/engagements/{engagement_id}/runs",
        headers={"X-Actor": "operator"},
        json={"profile_name": "passive-web-baseline"},
    )
    run_id = create_response.json()["id"]

    session_factory = client.app.state.session_factory
    with session_factory() as session:
        run = session.get(Run, UUID(run_id))
        assert run is not None
        run.status = "running"
        for index, task in enumerate(run.tasks):
            task.status = "running" if index == 0 else "cancelled"
            task.updated_at = datetime.now(UTC)
        session.commit()

    recovery_response = client.post(
        f"/api/v1/runs/{run_id}/stale-recovery",
        headers={"X-Actor": "operator"},
        json={
            "reason": "Operator tried to recover immediately, which should be blocked.",
            "task_outcome": "cancelled",
        },
    )

    assert recovery_response.status_code == 409
    assert "less than 10 minutes ago" in recovery_response.json()["detail"]
