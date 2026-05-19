from __future__ import annotations

import pytest
from sqlalchemy import select

from api.app.models import Run, Task
from api.app.services.artifact_storage import ArtifactStorageConfig, load_artifact_content


def _actor_headers(actor: str = "security-self-test") -> dict[str, str]:
    return {"X-Actor": actor, "X-Tenant-ID": "security-self-test"}


def _create_engagement(client, *, name: str = "Security Self-Test") -> str:
    response = client.post(
        "/api/v1/engagements",
        headers=_actor_headers(),
        json={"name": name, "client": "AegisPT", "roe_ref": "SELF-TEST"},
    )
    assert response.status_code == 201
    return response.json()["id"]


def _create_scope(client, engagement_id: str, allowlist: dict[str, list[str]]) -> None:
    response = client.post(
        f"/api/v1/engagements/{engagement_id}/scope",
        headers=_actor_headers(),
        json={"allowlist_json": allowlist, "denylist_json": {}},
    )
    assert response.status_code == 201


def test_engagement_create_rejects_oversized_and_null_byte_payloads(client) -> None:
    oversized = client.post(
        "/api/v1/engagements",
        headers=_actor_headers(),
        json={"name": "A" * 300, "client": "AegisPT", "roe_ref": "SELF-TEST"},
    )
    assert oversized.status_code == 422

    null_byte = client.post(
        "/api/v1/engagements",
        headers=_actor_headers(),
        json={"name": "Null byte \u0000 mission", "client": "AegisPT", "roe_ref": "SELF-TEST"},
    )
    assert null_byte.status_code == 422


def test_sql_injection_style_names_are_stored_as_data_without_breaking_queries(client) -> None:
    suspicious_name = "Selftest '; DROP TABLE engagements; --"
    engagement_id = _create_engagement(client, name=suspicious_name)

    list_response = client.get("/api/v1/engagements", headers=_actor_headers())

    assert list_response.status_code == 200
    stored = {item["id"]: item["name"] for item in list_response.json()}
    assert stored[engagement_id] == suspicious_name


@pytest.mark.parametrize(
    "target_map",
    [
        {"urls": ["http://169.254.169.254/latest/meta-data"]},
        {"urls": ["http://evil.example.test/admin"]},
        {"hosts": ["127.0.0.1 && id"]},
    ],
)
def test_run_creation_rejects_configured_targets_outside_scope(client, target_map) -> None:
    engagement_id = _create_engagement(client)
    _create_scope(client, engagement_id, {"urls": ["https://portal.example.test"]})

    response = client.post(
        f"/api/v1/engagements/{engagement_id}/runs",
        headers=_actor_headers(),
        json={
            "profile_name": "passive-web-baseline",
            "configuration_json": {"targets": target_map},
        },
    )

    assert response.status_code == 409
    assert "outside the approved engagement scope" in response.json()["detail"]
    with client.app.state.session_factory() as session:
        runs = session.scalars(select(Run)).all()
        tasks = session.scalars(select(Task)).all()
    assert runs == []
    assert tasks == []


def test_run_creation_allows_url_paths_under_approved_scope(client) -> None:
    engagement_id = _create_engagement(client)
    _create_scope(client, engagement_id, {"urls": ["https://portal.example.test"]})

    response = client.post(
        f"/api/v1/engagements/{engagement_id}/runs",
        headers=_actor_headers(),
        json={
            "profile_name": "passive-web-baseline",
            "configuration_json": {
                "targets": {"urls": ["https://portal.example.test/login"]},
            },
        },
    )

    assert response.status_code == 201
    payload = response.json()
    assert payload["status"] == "queued"
    assert payload["tasks"][0]["target_id"] == "https://portal.example.test/login"


def test_scheduled_run_rejects_ssrf_target_override(client) -> None:
    engagement_id = _create_engagement(client)
    _create_scope(client, engagement_id, {"urls": ["https://portal.example.test"]})

    response = client.post(
        f"/api/v1/engagements/{engagement_id}/schedules",
        headers=_actor_headers(),
        json={
            "profile_name": "passive-web-baseline",
            "cadence": "daily",
            "configuration_json": {
                "targets": {"urls": ["http://169.254.169.254/latest/meta-data"]},
            },
        },
    )

    assert response.status_code == 409
    assert "outside the approved engagement scope" in response.json()["detail"]


def test_tenant_scoping_blocks_idor_on_engagement_detail(client) -> None:
    tenant_a_headers = {"X-Actor": "tenant-a", "X-Tenant-ID": "tenant-a"}
    tenant_b_headers = {"X-Actor": "tenant-b", "X-Tenant-ID": "tenant-b"}
    response = client.post(
        "/api/v1/engagements",
        headers=tenant_a_headers,
        json={"name": "Tenant A self-test", "client": "AegisPT", "roe_ref": "SELF-TEST"},
    )
    assert response.status_code == 201

    denied = client.get(f"/api/v1/engagements/{response.json()['id']}", headers=tenant_b_headers)

    assert denied.status_code == 404


def test_inline_artifact_loader_rejects_path_traversal(tmp_path) -> None:
    config = ArtifactStorageConfig(
        mode="inline",
        endpoint="",
        bucket="",
        access_key="",
        secret_key="",
        inline_dir=str(tmp_path),
    )

    assert load_artifact_content(config=config, uri="inline://runs/one/../../etc/passwd") is None


def test_api_responses_include_baseline_security_headers(client) -> None:
    response = client.get("/")

    assert response.status_code == 200
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["referrer-policy"] == "no-referrer"
