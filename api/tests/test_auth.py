from __future__ import annotations

from sqlalchemy import select

from api.app.models import AuditEvent, InstanceSetting


def test_auth_me_keeps_local_fallback_explicit(client) -> None:
    response = client.get("/api/v1/auth/me", headers={"X-Actor": "operator-ui"})

    assert response.status_code == 200
    assert response.json() == {
        "actor_name": "operator-ui",
        "role": "admin",
        "auth_method": "x_actor_fallback",
    }
    assert response.headers["X-AegisPT-Auth-Warning"] == "x-actor-deprecated"


def test_api_key_create_revoke_and_session_events_are_audited(client) -> None:
    create_response = client.post(
        "/api/v1/auth/keys",
        headers={"X-Actor": "identity-admin"},
        json={"actor_name": "integration-runner", "role": "operator"},
    )
    assert create_response.status_code == 201
    created = create_response.json()
    assert created["api_key"].startswith("aegispt_")
    assert created["token_exposed_once"] is True

    list_response = client.get("/api/v1/auth/keys", headers={"X-Actor": "identity-admin"})
    assert list_response.status_code == 200
    assert list_response.json()[0]["actor_name"] == "integration-runner"

    revoke_response = client.post(
        f"/api/v1/auth/keys/{created['id']}/revoke",
        headers={"X-Actor": "identity-admin"},
        json={},
    )
    assert revoke_response.status_code == 200
    assert revoke_response.json()["revoked_at"] is not None

    login_response = client.post("/api/v1/auth/session/start", headers={"X-Actor": "identity-admin"}, json={})
    assert login_response.status_code == 200
    assert login_response.json()["message"].startswith("Login event recorded")

    logout_response = client.post("/api/v1/auth/logout", headers={"X-Actor": "identity-admin"}, json={})
    assert logout_response.status_code == 200
    assert logout_response.json()["session_cleared"] is False
    assert "active runs were not changed" in logout_response.json()["message"]

    with client.app.state.session_factory() as session:
        actions = session.scalars(select(AuditEvent.action).order_by(AuditEvent.created_at)).all()

    assert "auth.api_key.created" in actions
    assert "auth.api_key.revoked" in actions
    assert "auth.login" in actions
    assert "auth.logout" in actions


def test_enterprise_identity_status_reports_disabled_configured_and_error_states(client) -> None:
    disabled_response = client.get("/api/v1/auth/identity/status", headers={"X-Actor": "local-admin"})
    assert disabled_response.status_code == 200
    disabled = disabled_response.json()
    assert disabled["status"] == "disabled"
    assert disabled["provider"] == "disabled"
    assert disabled["local_auth"]["x_actor_fallback_enabled"] is True
    assert disabled["session_policy"]["timeout_minutes"] == 480
    assert disabled["current_actor"]["auth_method"] == "x_actor_fallback"

    error_response = client.patch(
        "/api/v1/settings",
        headers={"X-Actor": "settings-admin"},
        json={"settings": {"identity.enterprise_sso_provider": "oidc"}},
    )
    assert error_response.status_code == 200

    missing_response = client.get("/api/v1/auth/identity/status", headers={"X-Actor": "settings-admin"})
    assert missing_response.status_code == 200
    missing = missing_response.json()
    assert missing["status"] == "error"
    assert "OIDC issuer URL" in missing["missing_fields"]
    assert "OIDC client ID" in missing["missing_fields"]

    configured_response = client.patch(
        "/api/v1/settings",
        headers={"X-Actor": "settings-admin"},
        json={
            "settings": {
                "identity.enterprise_sso_provider": "oidc",
                "identity.oidc_issuer_url": "https://idp.example.test/.well-known/openid-configuration",
                "identity.oidc_client_id": "aegispt-console",
                "identity.oidc_client_secret": "super-secret-client-value",
                "identity.session_timeout_minutes": 60,
            }
        },
    )
    assert configured_response.status_code == 200
    assert "super-secret-client-value" not in str(configured_response.json())

    status_response = client.get("/api/v1/auth/identity/status", headers={"X-Actor": "settings-admin"})
    assert status_response.status_code == 200
    status = status_response.json()
    assert status["status"] == "configured"
    assert status["provider"] == "oidc"
    assert status["configured_secret_labels"] == ["OIDC client secret"]
    assert status["session_policy"]["timeout_minutes"] == 60
    assert status["metadata"]["secrets_plaintext_exposed"] is False

    with client.app.state.session_factory() as session:
        row = session.scalar(
            select(InstanceSetting).where(InstanceSetting.setting_key == "identity.oidc_client_secret")
        )
        audit_events = session.scalars(
            select(AuditEvent).where(AuditEvent.action == "settings.enterprise_identity.updated")
        ).all()

    assert row is not None
    assert row.sensitive is True
    assert row.encrypted_value
    assert "super-secret-client-value" not in row.encrypted_value
    assert any("identity.oidc_client_secret" in event.metadata_json["setting_keys"] for event in audit_events)
