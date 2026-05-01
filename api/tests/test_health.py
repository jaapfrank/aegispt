from __future__ import annotations


def test_live(client) -> None:
    response = client.get("/health/live")

    assert response.status_code == 200
    payload = response.json()
    assert payload["status"] == "ok"
    assert payload["detail"] == "service is running"


def test_ready(client) -> None:
    response = client.get("/health/ready")

    assert response.status_code == 200
    payload = response.json()
    assert payload["status"] == "ok"
    assert payload["detail"] == "database connection verified"


def test_api_docs_available(client) -> None:
    response = client.get("/api/docs")

    assert response.status_code == 200
    assert "swagger-ui" in response.text
    assert "/openapi.json" in response.text
