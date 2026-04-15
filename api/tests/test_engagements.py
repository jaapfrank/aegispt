from __future__ import annotations


def test_create_engagement_and_scope(client) -> None:
    engagement_response = client.post(
        "/api/v1/engagements",
        headers={"X-Actor": "tester"},
        json={
            "name": "Acme External Validation",
            "client": "Acme Corp",
            "roe_ref": "ROE-2026-001",
        },
    )

    assert engagement_response.status_code == 201
    engagement_payload = engagement_response.json()
    assert engagement_payload["name"] == "Acme External Validation"
    assert engagement_payload["status"] == "draft"

    scope_response = client.post(
        f"/api/v1/engagements/{engagement_payload['id']}/scope",
        headers={"X-Actor": "tester"},
        json={
            "allowlist_json": {"domains": ["example.com"], "cidrs": ["10.0.0.0/24"]},
            "denylist_json": {"domains": ["admin.example.com"]},
        },
    )

    assert scope_response.status_code == 201
    scope_payload = scope_response.json()
    assert scope_payload["engagement_id"] == engagement_payload["id"]
    assert scope_payload["allowlist_json"]["domains"] == ["example.com"]
