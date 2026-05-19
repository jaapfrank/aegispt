from __future__ import annotations

from uuid import UUID

from sqlalchemy import select

from api.app.models import ApiKey, Engagement


def _create_engagement(client, *, roe_ref: str | None = None) -> str:
    response = client.post(
        "/api/v1/engagements",
        headers={"X-Actor": "roe-operator"},
        json={
            "name": "ROE Gate Validation",
            "client": "Acme Corp",
            "roe_ref": roe_ref,
        },
    )
    assert response.status_code == 201
    return response.json()["id"]


def _add_scope(client, engagement_id: str) -> None:
    response = client.post(
        f"/api/v1/engagements/{engagement_id}/scope",
        headers={"X-Actor": "roe-operator"},
        json={
            "allowlist_json": {"urls": ["https://example.com"]},
            "denylist_json": {},
        },
    )
    assert response.status_code == 201


def _run_payload() -> dict[str, object]:
    return {
        "profile_name": "passive-web-baseline",
        "configuration_json": {"targets": {"urls": ["https://example.com"]}},
    }


def _create_api_key(client, *, actor_name: str, role: str, headers: dict[str, str] | None = None) -> dict[str, object]:
    response = client.post(
        "/api/v1/auth/keys",
        headers=headers or {"X-Actor": "bootstrap-admin"},
        json={"actor_name": actor_name, "role": role},
    )
    assert response.status_code == 201, response.text
    return response.json()


def _bearer(api_key_payload: dict[str, object]) -> dict[str, str]:
    return {"Authorization": f"Bearer {api_key_payload['api_key']}"}


def test_api_key_creation_and_bearer_actor_resolution(client) -> None:
    payload = _create_api_key(client, actor_name="api-admin", role="admin")

    assert payload["actor_name"] == "api-admin"
    assert payload["role"] == "admin"
    assert payload["api_key"].startswith("aegispt_")
    assert "key_hash" not in payload

    list_response = client.get(
        "/api/v1/auth/keys",
        headers=_bearer(payload),
    )

    assert list_response.status_code == 200
    listed = list_response.json()
    assert listed[0]["actor_name"] == "api-admin"
    assert "api_key" not in listed[0]

    operator_payload = _create_api_key(
        client,
        actor_name="api-operator",
        role="operator",
        headers=_bearer(payload),
    )
    me_response = client.get("/api/v1/auth/me", headers=_bearer(operator_payload))
    assert me_response.status_code == 200
    assert me_response.json() == {
        "actor_name": "api-operator",
        "role": "operator",
        "auth_method": "api_key",
    }

    with client.app.state.session_factory() as session:
        record = session.scalar(select(ApiKey).where(ApiKey.actor_name == "api-operator"))
        assert record is not None
        assert record.last_used_at is not None


def test_x_actor_fallback_still_works_with_deprecation_warning(client) -> None:
    response = client.post(
        "/api/v1/engagements",
        headers={"X-Actor": "legacy-operator"},
        json={"name": "Legacy Actor", "client": "Acme Corp", "roe_ref": "ROE-LEGACY"},
    )

    assert response.status_code == 201
    assert response.headers["X-AegisPT-Auth-Warning"] == "x-actor-deprecated"


def test_run_creation_requires_roe_or_authorization_confirmation(client) -> None:
    engagement_id = _create_engagement(client, roe_ref=None)
    _add_scope(client, engagement_id)

    blocked_response = client.post(
        f"/api/v1/engagements/{engagement_id}/runs",
        headers={"X-Actor": "roe-operator"},
        json=_run_payload(),
    )

    assert blocked_response.status_code == 400
    assert "Written authorization is required before starting a scan" in blocked_response.json()["detail"]

    confirm_response = client.patch(
        f"/api/v1/engagements/{engagement_id}/confirm-authorization",
        headers={"X-Actor": "roe-approver"},
    )

    assert confirm_response.status_code == 200
    assert confirm_response.json()["authorization_confirmed_by"] == "roe-approver"

    allowed_response = client.post(
        f"/api/v1/engagements/{engagement_id}/runs",
        headers={"X-Actor": "roe-operator"},
        json=_run_payload(),
    )

    assert allowed_response.status_code == 201
    assert allowed_response.json()["requested_by"] == "roe-operator"

    with client.app.state.session_factory() as session:
        engagement = session.get(Engagement, UUID(engagement_id))
        assert engagement is not None
        assert engagement.authorization_confirmed_by == "roe-approver"
        assert engagement.authorization_confirmed_at is not None


def test_rbac_reviewer_cannot_create_runs_and_operator_can(client) -> None:
    admin_key = _create_api_key(client, actor_name="rbac-admin", role="admin")
    operator_key = _create_api_key(client, actor_name="rbac-operator", role="operator", headers=_bearer(admin_key))
    reviewer_key = _create_api_key(client, actor_name="rbac-reviewer", role="reviewer", headers=_bearer(admin_key))
    engagement_id = _create_engagement(client, roe_ref="ROE-RBAC")
    _add_scope(client, engagement_id)

    blocked_response = client.post(
        f"/api/v1/engagements/{engagement_id}/runs",
        headers=_bearer(reviewer_key),
        json=_run_payload(),
    )

    assert blocked_response.status_code == 403
    assert "reviewer" in blocked_response.json()["detail"]

    allowed_response = client.post(
        f"/api/v1/engagements/{engagement_id}/runs",
        headers=_bearer(operator_key),
        json=_run_payload(),
    )

    assert allowed_response.status_code == 201
    assert allowed_response.json()["requested_by"] == "rbac-operator"


def test_rbac_admin_required_for_settings_and_run_delete(client) -> None:
    admin_key = _create_api_key(client, actor_name="settings-admin", role="admin")
    operator_key = _create_api_key(client, actor_name="settings-operator", role="operator", headers=_bearer(admin_key))
    engagement_id = _create_engagement(client, roe_ref="ROE-ADMIN")
    _add_scope(client, engagement_id)
    run_response = client.post(
        f"/api/v1/engagements/{engagement_id}/runs",
        headers=_bearer(operator_key),
        json=_run_payload(),
    )
    assert run_response.status_code == 201
    run_id = run_response.json()["id"]

    settings_response = client.patch(
        "/api/v1/settings",
        headers=_bearer(operator_key),
        json={"settings": {"runtime.inline_task_workers": 3}},
    )
    assert settings_response.status_code == 403

    delete_response = client.delete(
        f"/api/v1/runs/{run_id}",
        headers=_bearer(operator_key),
        params={"dry_run": "true"},
    )
    assert delete_response.status_code == 403


def test_rbac_admin_can_revoke_keys(client) -> None:
    admin_key = _create_api_key(client, actor_name="key-admin", role="admin")
    reviewer_key = _create_api_key(client, actor_name="key-reviewer", role="reviewer", headers=_bearer(admin_key))

    revoke_response = client.post(
        f"/api/v1/auth/keys/{reviewer_key['id']}/revoke",
        headers=_bearer(admin_key),
    )
    assert revoke_response.status_code == 200
    assert revoke_response.json()["revoked_at"] is not None

    me_response = client.get("/api/v1/auth/me", headers=_bearer(reviewer_key))
    assert me_response.status_code == 401
