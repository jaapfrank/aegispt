from __future__ import annotations

import pytest
from fastapi.testclient import TestClient


def _fresh_client(tmp_path, monkeypatch) -> TestClient:
    database_path = tmp_path / "aegispt-security-hardening.db"
    monkeypatch.setenv("DATABASE_URL", f"sqlite+pysqlite:///{database_path}")
    monkeypatch.setenv("AUTO_CREATE_TABLES", "true")

    from api.app.config import get_settings
    from api.app.main import create_app

    get_settings.cache_clear()
    return TestClient(create_app())


def _create_scoped_engagement(client: TestClient) -> str:
    engagement_response = client.post(
        "/api/v1/engagements",
        headers={"X-Actor": "security-admin"},
        json={
            "name": "Security Hardening",
            "client": "Acme Corp",
            "roe_ref": "ROE-SECURITY-HARDENING",
        },
    )
    assert engagement_response.status_code == 201, engagement_response.text
    engagement_id = engagement_response.json()["id"]

    scope_response = client.post(
        f"/api/v1/engagements/{engagement_id}/scope",
        headers={"X-Actor": "security-admin"},
        json={
            "allowlist_json": {"urls": ["https://example.com"]},
            "denylist_json": {},
        },
    )
    assert scope_response.status_code == 201, scope_response.text
    return engagement_id


def test_cors_uses_configured_allowed_origins(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("AEGISPT_ALLOWED_ORIGINS", "https://console.example.test, http://127.0.0.1:8000")
    with _fresh_client(tmp_path, monkeypatch) as client:
        response = client.options(
            "/health/live",
            headers={
                "Origin": "https://console.example.test",
                "Access-Control-Request-Method": "GET",
            },
        )
        assert response.status_code == 200
        assert response.headers["access-control-allow-origin"] == "https://console.example.test"

        blocked_response = client.options(
            "/health/live",
            headers={
                "Origin": "https://untrusted.example.test",
                "Access-Control-Request-Method": "GET",
            },
        )
        assert "access-control-allow-origin" not in blocked_response.headers


def test_api_key_create_is_rate_limited_per_ip(tmp_path, monkeypatch) -> None:
    with _fresh_client(tmp_path, monkeypatch) as client:
        for index in range(5):
            response = client.post(
                "/api/v1/auth/keys",
                headers={"X-Actor": "security-admin"},
                json={"actor_name": f"integration-{index}", "role": "operator"},
            )
            assert response.status_code == 201, response.text
            assert response.headers["X-RateLimit-Limit"] == "5"

        limited_response = client.post(
            "/api/v1/auth/keys",
            headers={"X-Actor": "security-admin"},
            json={"actor_name": "integration-limited", "role": "operator"},
        )
        assert limited_response.status_code == 429
        assert limited_response.headers["Retry-After"]
        assert limited_response.json()["rate_limit"]["scope"] == "auth_api_key_create"


def test_run_creation_is_rate_limited_per_ip(tmp_path, monkeypatch) -> None:
    with _fresh_client(tmp_path, monkeypatch) as client:
        engagement_id = _create_scoped_engagement(client)
        payload = {
            "profile_name": "passive-web-baseline",
            "configuration_json": {"targets": {"urls": ["https://example.com"]}},
        }

        for _index in range(10):
            response = client.post(
                f"/api/v1/engagements/{engagement_id}/runs",
                headers={"X-Actor": "security-operator"},
                json=payload,
            )
            assert response.status_code == 201, response.text
            assert response.headers["X-RateLimit-Limit"] == "10"

        limited_response = client.post(
            f"/api/v1/engagements/{engagement_id}/runs",
            headers={"X-Actor": "security-operator"},
            json=payload,
        )
        assert limited_response.status_code == 429
        assert limited_response.json()["rate_limit"]["scope"] == "run_create"


def test_chatgpt_oauth_post_prefix_is_rate_limited_without_changing_get_routes(tmp_path, monkeypatch) -> None:
    with _fresh_client(tmp_path, monkeypatch) as client:
        engagement_id = _create_scoped_engagement(client)
        get_response = client.get(f"/api/v1/auth/chatgpt/status?engagement_id={engagement_id}")
        assert get_response.status_code == 200

        for _index in range(3):
            response = client.post(f"/api/v1/auth/chatgpt/status?engagement_id={engagement_id}")
            assert response.status_code == 405
            assert response.headers["X-RateLimit-Limit"] == "3"

        limited_response = client.post(f"/api/v1/auth/chatgpt/status?engagement_id={engagement_id}")
        assert limited_response.status_code == 429
        assert limited_response.json()["rate_limit"]["scope"] == "chatgpt_oauth_post"


def test_production_startup_requires_database_encryption_key(tmp_path, monkeypatch) -> None:
    database_path = tmp_path / "aegispt-production.db"
    monkeypatch.setenv("DATABASE_URL", f"sqlite+pysqlite:///{database_path}")
    monkeypatch.setenv("AUTO_CREATE_TABLES", "true")
    monkeypatch.setenv("AEGISPT_ENV", "production")
    monkeypatch.delenv("AEGISPT_DB_KEY", raising=False)

    from api.app.config import get_settings
    from api.app.main import create_app

    get_settings.cache_clear()
    with pytest.raises(RuntimeError, match="AEGISPT_DB_KEY is required"):
        with TestClient(create_app()):
            pass
    get_settings.cache_clear()


def test_auto_create_tables_false_requires_database_encryption_key(tmp_path, monkeypatch) -> None:
    database_path = tmp_path / "aegispt-auto-create-false.db"
    monkeypatch.setenv("DATABASE_URL", f"sqlite+pysqlite:///{database_path}")
    monkeypatch.setenv("APP_ENV", "development")
    monkeypatch.setenv("AUTO_CREATE_TABLES", "false")
    monkeypatch.delenv("AEGISPT_ENV", raising=False)
    monkeypatch.delenv("AEGISPT_DB_KEY", raising=False)

    from api.app.config import get_settings
    from api.app.main import create_app

    get_settings.cache_clear()
    with pytest.raises(RuntimeError, match="AEGISPT_DB_KEY is required"):
        with TestClient(create_app()):
            pass
    get_settings.cache_clear()
