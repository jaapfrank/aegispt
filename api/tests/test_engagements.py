from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID

from sqlalchemy import select


def _create_engagement_scope_and_run(client, *, name: str = "Delete Me") -> tuple[str, str]:
    engagement_response = client.post(
        "/api/v1/engagements",
        headers={"X-Actor": "tester"},
        json={
            "name": name,
            "client": "Acme Corp",
            "roe_ref": "ROE-DELETE",
        },
    )
    assert engagement_response.status_code == 201
    engagement_id = engagement_response.json()["id"]
    scope_response = client.post(
        f"/api/v1/engagements/{engagement_id}/scope",
        headers={"X-Actor": "tester"},
        json={
            "allowlist_json": {"urls": ["https://example.com"]},
            "denylist_json": {},
        },
    )
    assert scope_response.status_code == 201
    run_response = client.post(
        f"/api/v1/engagements/{engagement_id}/runs",
        headers={"X-Actor": "tester"},
        json={"profile_name": "passive-web-baseline"},
    )
    assert run_response.status_code == 201
    return engagement_id, run_response.json()["id"]


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


def test_delete_engagement_requires_confirmation_and_excludes_cascade(client) -> None:
    from api.app.models import AuditEvent, Engagement, IntegrationConfiguration, Run, ScheduledRun

    engagement_id, run_id = _create_engagement_scope_and_run(client, name="Delete Me")
    with client.app.state.session_factory() as session:
        session.add(
            IntegrationConfiguration(
                engagement_id=UUID(engagement_id),
                integration_type="jira",
                display_name="Delete Impact Jira",
                base_url="https://jira.example.test",
                project_key="AEGIS",
            )
        )
        session.add(
            ScheduledRun(
                engagement_id=UUID(engagement_id),
                profile_name="passive-web-baseline",
                cadence="daily",
                cron_expression="0 0 * * *",
                timezone="UTC",
                status="enabled",
                next_run_at=datetime(2026, 4, 26, tzinfo=UTC),
                configuration_json={},
                created_by="tester",
                updated_by="tester",
            )
        )
        session.commit()

    preview_response = client.request(
        "DELETE",
        f"/api/v1/engagements/{engagement_id}?dry_run=true",
        headers={"X-Actor": "tester"},
    )
    assert preview_response.status_code == 200
    preview = preview_response.json()
    assert preview["counts"]["engagements"] == 1
    assert preview["counts"]["runs"] == 1
    assert preview["counts"]["scheduled_runs"] == 1
    assert preview["counts"]["integration_configs"] == 1

    missing_confirmation = client.request(
        "DELETE",
        f"/api/v1/engagements/{engagement_id}",
        headers={"X-Actor": "tester"},
        json={"confirmation": "Wrong Name"},
    )
    assert missing_confirmation.status_code == 409

    delete_response = client.request(
        "DELETE",
        f"/api/v1/engagements/{engagement_id}",
        headers={"X-Actor": "tester"},
        json={"confirmation": "Delete Me"},
    )
    assert delete_response.status_code == 200
    assert delete_response.json()["deleted_ids"] == [engagement_id]

    list_response = client.get("/api/v1/engagements")
    assert list_response.status_code == 200
    assert engagement_id not in {item["id"] for item in list_response.json()}
    assert client.get(f"/api/v1/engagements/{engagement_id}").status_code == 404
    assert client.get(f"/api/v1/runs/{run_id}").status_code == 404

    with client.app.state.session_factory() as session:
        engagement = session.get(Engagement, UUID(engagement_id))
        run = session.get(Run, UUID(run_id))
        assert engagement is not None and engagement.deleted_at is not None
        assert run is not None and run.deleted_at is not None
        audit = session.scalar(
            select(AuditEvent).where(
                AuditEvent.object_id == engagement_id,
                AuditEvent.action == "engagement.deleted",
            )
        )
        assert audit is not None
        assert audit.metadata_json["counts"]["runs"] == 1
        assert audit.metadata_json["item_count"] >= preview["total_items"]
