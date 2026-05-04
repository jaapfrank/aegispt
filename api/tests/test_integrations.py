from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread
from uuid import UUID, uuid4

import pytest
from sqlalchemy import select

from api.app.models import (
    AuditEvent,
    Finding,
    FindingIntegrationLink,
    IntegrationConfiguration,
    Run,
)


def _create_engagement(client) -> str:
    response = client.post(
        "/api/v1/engagements",
        headers={"X-Actor": "integration-tester"},
        json={
            "name": "Jira Integration Engagement",
            "client": "Acme Corp",
            "roe_ref": "ROE-JIRA-1",
        },
    )
    assert response.status_code == 201
    return response.json()["id"]


class JiraIssueHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802
        if self.path != "/rest/api/2/issue/AEGIS-42":
            self.send_response(404)
            self.end_headers()
            return

        status_code = getattr(self.server, "status_code", 200)
        body = getattr(
            self.server,
            "body",
            b'{"key":"AEGIS-42","fields":{"status":{"name":"Done"},"updated":"2026-04-21T12:00:00.000+0000"}}',
        )
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args) -> None:  # noqa: A003
        return


class WebhookHandoffHandler(BaseHTTPRequestHandler):
    def do_POST(self) -> None:  # noqa: N802
        if self.path != "/handoffs/findings":
            self.send_response(404)
            self.end_headers()
            return

        length = int(self.headers.get("Content-Length") or "0")
        raw_body = self.rfile.read(length)
        received_payloads = getattr(self.server, "received_payloads", [])
        received_payloads.append(
            {
                "headers": dict(self.headers.items()),
                "json": json.loads(raw_body.decode("utf-8")),
            }
        )
        self.server.received_payloads = received_payloads

        status_code = getattr(self.server, "status_code", 202)
        body = getattr(
            self.server,
            "body",
            b'{"reference_key":"WH-9001","reference_url":"https://workflow.example.test/handoffs/WH-9001","status":"accepted"}',
        )
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args) -> None:  # noqa: A003
        return


@pytest.fixture
def jira_server() -> tuple[ThreadingHTTPServer, str]:
    server = ThreadingHTTPServer(("127.0.0.1", 0), JiraIssueHandler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = server.server_address

    try:
        yield server, f"http://{host}:{port}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


@pytest.fixture
def webhook_server() -> tuple[ThreadingHTTPServer, str]:
    server = ThreadingHTTPServer(("127.0.0.1", 0), WebhookHandoffHandler)
    server.received_payloads = []
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = server.server_address

    try:
        yield server, f"http://{host}:{port}/handoffs/findings"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def _create_jira_configuration(client, engagement_id: str, base_url: str = "https://jira.example.test") -> dict:
    response = client.put(
        f"/api/v1/engagements/{engagement_id}/integrations/jira",
        headers={"X-Actor": "jira-admin"},
        json={
            "integration_type": "jira",
            "display_name": "Acme Jira",
            "base_url": base_url,
            "project_key": "AEGIS",
            "auth_ref": "secret://engagements/acme/jira-token",
            "settings_json": {
                "issue_type": "Bug",
                "priority": "High",
            },
        },
    )
    assert response.status_code == 200
    return response.json()


def _create_webhook_configuration(
    client,
    engagement_id: str,
    endpoint_url: str = "https://workflow.example.test/handoffs/findings",
) -> dict:
    response = client.put(
        f"/api/v1/engagements/{engagement_id}/integrations/webhook",
        headers={"X-Actor": "workflow-admin"},
        json={
            "integration_type": "webhook",
            "display_name": "Acme Workflow Webhook",
            "base_url": endpoint_url,
            "auth_ref": "secret://engagements/acme/workflow-webhook-token",
            "settings_json": {
                "event_type": "aegispt.finding.handoff.requested",
            },
        },
    )
    assert response.status_code == 200
    return response.json()


def _create_named_integration_configuration(
    client,
    engagement_id: str,
    provider: str,
    *,
    auth_ref: str | None = "vault://integrations/workflow-token",
    settings_json: dict | None = None,
) -> dict:
    default_settings = {
        "channel": "#remediation",
        "conversation": "security-remediation",
        "table": "sn_si_incident",
    }
    response = client.put(
        f"/api/v1/engagements/{engagement_id}/integrations/{provider}",
        headers={"X-Actor": "workflow-admin"},
        json={
            "integration_type": provider,
            "display_name": f"Acme {provider.title()}",
            "base_url": f"https://{provider}.example.test/acme",
            "project_key": "SECOPS",
            "auth_ref": auth_ref,
            "settings_json": settings_json if settings_json is not None else default_settings,
        },
    )
    assert response.status_code == 200
    return response.json()


def _seed_finding_for_engagement(client, engagement_id: str) -> str:
    with client.app.state.session_factory() as session:
        run = Run(
            engagement_id=UUID(engagement_id),
            requested_by="integration-test",
            status="completed",
            configuration_json={},
        )
        session.add(run)
        session.flush()
        finding = Finding(
            run_id=run.id,
            title="Missing security header",
            severity="medium",
            target_id="https://app.example.test",
            evidence_ref="artifact://headers/missing-security-header",
            status="open",
            summary="The target is missing a hardening header.",
        )
        session.add(finding)
        session.commit()
        return str(finding.id)


def test_jira_integration_configuration_can_be_created_listed_and_updated(client) -> None:
    engagement_id = _create_engagement(client)

    list_response = client.get(f"/api/v1/engagements/{engagement_id}/integrations")
    assert list_response.status_code == 200
    assert list_response.json() == []

    missing_response = client.get(f"/api/v1/engagements/{engagement_id}/integrations/jira")
    assert missing_response.status_code == 404
    assert missing_response.json()["detail"] == "jira integration configuration not found"

    create_response = client.put(
        f"/api/v1/engagements/{engagement_id}/integrations/jira",
        headers={"X-Actor": "jira-admin"},
        json={
            "integration_type": "jira",
            "display_name": "Acme Jira",
            "base_url": "https://jira.example.test/",
            "project_key": "AEGIS",
            "auth_ref": "secret://engagements/acme/jira-token",
            "settings_json": {
                "issue_type": "Bug",
                "priority": "High",
            },
        },
    )

    assert create_response.status_code == 200
    created = create_response.json()
    assert created["engagement_id"] == engagement_id
    assert created["integration_type"] == "jira"
    assert created["display_name"] == "Acme Jira"
    assert created["base_url"] == "https://jira.example.test"
    assert created["project_key"] == "AEGIS"
    assert created["auth_ref"] == "secret://engagements/acme/jira-token"
    assert created["settings_json"] == {"issue_type": "Bug", "priority": "High"}
    assert created["created_by"] == "jira-admin"
    assert created["updated_by"] == "jira-admin"

    read_response = client.get(f"/api/v1/engagements/{engagement_id}/integrations/jira")
    assert read_response.status_code == 200
    assert read_response.json() == created

    update_response = client.put(
        f"/api/v1/engagements/{engagement_id}/integrations/jira",
        headers={"X-Actor": "jira-owner"},
        json={
            "integration_type": "jira",
            "display_name": "Acme Security Jira",
            "base_url": "https://jira.example.test",
            "project_key": "SEC",
            "auth_ref": "secret://engagements/acme/security-jira-token",
            "settings_json": {
                "issue_type": "Task",
                "priority": "Medium",
            },
        },
    )

    assert update_response.status_code == 200
    updated = update_response.json()
    assert updated["id"] == created["id"]
    assert updated["project_key"] == "SEC"
    assert updated["settings_json"] == {"issue_type": "Task", "priority": "Medium"}
    assert updated["created_by"] == "jira-admin"
    assert updated["updated_by"] == "jira-owner"

    list_response = client.get(f"/api/v1/engagements/{engagement_id}/integrations")
    assert list_response.status_code == 200
    assert list_response.json() == [updated]

    with client.app.state.session_factory() as session:
        configurations = session.scalars(select(IntegrationConfiguration)).all()
        events = session.scalars(
            select(AuditEvent)
            .where(AuditEvent.object_type == "integration_configuration")
            .order_by(AuditEvent.created_at)
        ).all()

    assert len(configurations) == 1
    assert configurations[0].integration_type == "jira"
    assert len(events) == 2
    assert [event.action for event in events] == [
        "integration.configuration.created",
        "integration.configuration.updated",
    ]
    assert events[0].metadata_json["integration_type"] == "jira"
    assert events[1].metadata_json["project_key"] == "SEC"


def test_jira_integration_configuration_rejects_non_jira_payload_type(client) -> None:
    engagement_id = _create_engagement(client)

    response = client.put(
        f"/api/v1/engagements/{engagement_id}/integrations/jira",
        headers={"X-Actor": "jira-admin"},
        json={
            "integration_type": "slack",
            "base_url": "https://hooks.slack.example.test",
        },
    )

    assert response.status_code == 422


def test_jira_integration_configuration_requires_existing_engagement(client) -> None:
    response = client.put(
        f"/api/v1/engagements/{uuid4()}/integrations/jira",
        headers={"X-Actor": "jira-admin"},
        json={
            "integration_type": "jira",
            "base_url": "https://jira.example.test",
        },
    )

    assert response.status_code == 404
    assert response.json()["detail"] == "engagement not found"


def test_webhook_integration_configuration_can_be_created_listed_and_updated(client) -> None:
    engagement_id = _create_engagement(client)

    missing_response = client.get(f"/api/v1/engagements/{engagement_id}/integrations/webhook")
    assert missing_response.status_code == 404
    assert missing_response.json()["detail"] == "webhook integration configuration not found"

    create_response = client.put(
        f"/api/v1/engagements/{engagement_id}/integrations/webhook",
        headers={"X-Actor": "workflow-admin"},
        json={
            "integration_type": "webhook",
            "display_name": "Acme Workflow Webhook",
            "base_url": "https://workflow.example.test/handoffs/findings",
            "auth_ref": "secret://engagements/acme/workflow-webhook-token",
            "settings_json": {
                "event_type": "aegispt.finding.handoff.requested",
                "handoff_timeout_seconds": 5,
            },
        },
    )

    assert create_response.status_code == 200
    created = create_response.json()
    assert created["engagement_id"] == engagement_id
    assert created["integration_type"] == "webhook"
    assert created["display_name"] == "Acme Workflow Webhook"
    assert created["base_url"] == "https://workflow.example.test/handoffs/findings"
    assert created["project_key"] is None
    assert created["auth_ref"] == "secret://engagements/acme/workflow-webhook-token"
    assert created["settings_json"]["event_type"] == "aegispt.finding.handoff.requested"
    assert created["created_by"] == "workflow-admin"
    assert created["updated_by"] == "workflow-admin"

    read_response = client.get(f"/api/v1/engagements/{engagement_id}/integrations/webhook")
    assert read_response.status_code == 200
    assert read_response.json() == created

    update_response = client.put(
        f"/api/v1/engagements/{engagement_id}/integrations/webhook",
        headers={"X-Actor": "workflow-owner"},
        json={
            "integration_type": "webhook",
            "display_name": "Acme Workflow Intake",
            "base_url": "https://workflow.example.test/aegispt",
            "auth_ref": "env://AEGISPT_WORKFLOW_WEBHOOK_TOKEN",
            "settings_json": {
                "event_type": "aegispt.finding.handoff.acceptance",
            },
        },
    )

    assert update_response.status_code == 200
    updated = update_response.json()
    assert updated["id"] == created["id"]
    assert updated["display_name"] == "Acme Workflow Intake"
    assert updated["base_url"] == "https://workflow.example.test/aegispt"
    assert updated["auth_ref"] == "env://AEGISPT_WORKFLOW_WEBHOOK_TOKEN"
    assert updated["created_by"] == "workflow-admin"
    assert updated["updated_by"] == "workflow-owner"

    list_response = client.get(f"/api/v1/engagements/{engagement_id}/integrations")
    assert list_response.status_code == 200
    assert list_response.json() == [updated]

    with client.app.state.session_factory() as session:
        configurations = session.scalars(select(IntegrationConfiguration)).all()
        events = session.scalars(
            select(AuditEvent)
            .where(AuditEvent.object_type == "integration_configuration")
            .order_by(AuditEvent.created_at)
        ).all()

    assert len(configurations) == 1
    assert configurations[0].integration_type == "webhook"
    assert [event.action for event in events] == [
        "integration.configuration.created",
        "integration.configuration.updated",
    ]
    assert events[0].metadata_json["integration_type"] == "webhook"
    assert events[1].metadata_json["endpoint"] == "https://workflow.example.test/aegispt"


def test_webhook_integration_configuration_rejects_non_webhook_payload_type(client) -> None:
    engagement_id = _create_engagement(client)

    response = client.put(
        f"/api/v1/engagements/{engagement_id}/integrations/webhook",
        headers={"X-Actor": "workflow-admin"},
        json={
            "integration_type": "jira",
            "base_url": "https://workflow.example.test/handoffs/findings",
        },
    )

    assert response.status_code == 422


def test_jira_finding_link_can_be_created_read_and_updated(client) -> None:
    engagement_id = _create_engagement(client)
    configuration = _create_jira_configuration(client, engagement_id)
    finding_id = _seed_finding_for_engagement(client, engagement_id)

    missing_response = client.get(f"/api/v1/engagements/{engagement_id}/integrations/jira/findings/{finding_id}")
    assert missing_response.status_code == 404
    assert missing_response.json()["detail"] == "jira finding link not found"

    create_response = client.put(
        f"/api/v1/engagements/{engagement_id}/integrations/jira/findings/{finding_id}",
        headers={"X-Actor": "triage-operator"},
        json={
            "issue_key": "aegis-42",
            "issue_url": "https://jira.example.test/browse/AEGIS-42",
            "issue_status": "To Do",
        },
    )

    assert create_response.status_code == 200
    created = create_response.json()
    assert created["finding_id"] == finding_id
    assert created["integration_configuration_id"] == configuration["id"]
    assert created["issue_key"] == "AEGIS-42"
    assert created["issue_url"] == "https://jira.example.test/browse/AEGIS-42"
    assert created["issue_status"] == "To Do"
    assert created["last_sync_state"] == "not_synced"
    assert created["last_synced_at"] is None
    assert created["last_sync_error"] is None
    assert created["last_sync_payload_json"] == {}
    assert created["created_by"] == "triage-operator"
    assert created["updated_by"] == "triage-operator"

    read_response = client.get(f"/api/v1/engagements/{engagement_id}/integrations/jira/findings/{finding_id}")
    assert read_response.status_code == 200
    assert read_response.json() == created

    update_response = client.put(
        f"/api/v1/engagements/{engagement_id}/integrations/jira/findings/{finding_id}",
        headers={"X-Actor": "jira-owner"},
        json={
            "issue_key": "AEGIS-42",
            "issue_url": "https://jira.example.test/browse/AEGIS-42",
            "issue_status": "In Progress",
        },
    )

    assert update_response.status_code == 200
    updated = update_response.json()
    assert updated["id"] == created["id"]
    assert updated["issue_status"] == "In Progress"
    assert updated["last_sync_state"] == "not_synced"
    assert updated["created_by"] == "triage-operator"
    assert updated["updated_by"] == "jira-owner"

    with client.app.state.session_factory() as session:
        links = session.scalars(select(FindingIntegrationLink)).all()
        events = session.scalars(
            select(AuditEvent)
            .where(AuditEvent.object_type == "finding_integration_link")
            .order_by(AuditEvent.created_at)
        ).all()

    assert len(links) == 1
    assert links[0].issue_key == "AEGIS-42"
    assert len(events) == 2
    assert [event.action for event in events] == [
        "finding.integration_link.created",
        "finding.integration_link.updated",
    ]
    assert events[0].metadata_json["finding_id"] == finding_id
    assert events[0].metadata_json["integration_type"] == "jira"
    assert events[1].metadata_json["issue_key"] == "AEGIS-42"


def test_jira_finding_link_requires_jira_configuration(client) -> None:
    engagement_id = _create_engagement(client)
    finding_id = _seed_finding_for_engagement(client, engagement_id)

    response = client.put(
        f"/api/v1/engagements/{engagement_id}/integrations/jira/findings/{finding_id}",
        headers={"X-Actor": "triage-operator"},
        json={
            "issue_key": "AEGIS-42",
            "issue_url": "https://jira.example.test/browse/AEGIS-42",
        },
    )

    assert response.status_code == 409
    assert response.json()["detail"] == "jira integration configuration required before linking findings"


def test_jira_handoff_route_prepares_finding_link(client) -> None:
    engagement_id = _create_engagement(client)
    configuration = _create_jira_configuration(client, engagement_id, base_url="https://jira.example.test")
    finding_id = _seed_finding_for_engagement(client, engagement_id)

    response = client.post(
        f"/api/v1/findings/{finding_id}/handoff-jira",
        headers={"X-Actor": "triage-operator"},
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["finding_id"] == finding_id
    assert payload["integration_configuration_id"] == configuration["id"]
    assert payload["issue_key"].startswith("AEGIS-")
    assert payload["issue_url"] == f"https://jira.example.test/browse/{payload['issue_key']}"
    assert payload["issue_status"] == "Ready for Jira triage"
    assert payload["last_sync_state"] == "not_synced"
    assert payload["last_sync_payload_json"]["handoff_mode"] == "ui_prepared"
    assert payload["last_sync_payload_json"]["remote_issue_created"] is False

    theater_response = client.get(f"/api/v1/findings/{finding_id}/theater")
    assert theater_response.status_code == 200
    jira_issue = theater_response.json()["remediation"]["integrations"]["jira"]
    assert jira_issue["issue_key"] == payload["issue_key"]


def test_jira_handoff_route_requires_configuration(client) -> None:
    engagement_id = _create_engagement(client)
    finding_id = _seed_finding_for_engagement(client, engagement_id)

    response = client.post(
        f"/api/v1/findings/{finding_id}/handoff-jira",
        headers={"X-Actor": "triage-operator"},
    )

    assert response.status_code == 409
    assert response.json()["detail"] == "jira integration configuration required before handoff"


def test_jira_finding_link_rejects_findings_outside_engagement(client) -> None:
    engagement_id = _create_engagement(client)
    other_engagement_id = _create_engagement(client)
    _create_jira_configuration(client, engagement_id)
    finding_id = _seed_finding_for_engagement(client, other_engagement_id)

    response = client.put(
        f"/api/v1/engagements/{engagement_id}/integrations/jira/findings/{finding_id}",
        headers={"X-Actor": "triage-operator"},
        json={
            "issue_key": "AEGIS-42",
            "issue_url": "https://jira.example.test/browse/AEGIS-42",
        },
    )

    assert response.status_code == 404
    assert response.json()["detail"] == "finding not found for engagement"


def test_jira_finding_link_rejects_non_url_issue_reference(client) -> None:
    engagement_id = _create_engagement(client)
    _create_jira_configuration(client, engagement_id)
    finding_id = _seed_finding_for_engagement(client, engagement_id)

    response = client.put(
        f"/api/v1/engagements/{engagement_id}/integrations/jira/findings/{finding_id}",
        headers={"X-Actor": "triage-operator"},
        json={
            "issue_key": "AEGIS-42",
            "issue_url": "jira.example.test/browse/AEGIS-42",
        },
    )

    assert response.status_code == 422


def test_jira_finding_link_can_sync_issue_status_on_demand(client, jira_server) -> None:
    _, base_url = jira_server
    engagement_id = _create_engagement(client)
    _create_jira_configuration(client, engagement_id, base_url=base_url)
    finding_id = _seed_finding_for_engagement(client, engagement_id)

    link_response = client.put(
        f"/api/v1/engagements/{engagement_id}/integrations/jira/findings/{finding_id}",
        headers={"X-Actor": "triage-operator"},
        json={
            "issue_key": "AEGIS-42",
            "issue_url": f"{base_url}/browse/AEGIS-42",
            "issue_status": "To Do",
        },
    )
    assert link_response.status_code == 200

    sync_response = client.post(
        f"/api/v1/engagements/{engagement_id}/integrations/jira/findings/{finding_id}/sync",
        headers={"X-Actor": "sync-operator"},
    )

    assert sync_response.status_code == 200
    synced = sync_response.json()
    assert synced["issue_status"] == "Done"
    assert synced["last_sync_state"] == "synced"
    assert synced["last_synced_at"] is not None
    assert synced["last_sync_error"] is None
    assert synced["last_sync_payload_json"]["remote_key"] == "AEGIS-42"
    assert synced["last_sync_payload_json"]["remote_status"] == "Done"
    assert synced["last_sync_payload_json"]["remote_updated"] == "2026-04-21T12:00:00.000+0000"
    assert synced["last_sync_payload_json"]["source_url"].endswith("/rest/api/2/issue/AEGIS-42")
    assert synced["updated_by"] == "sync-operator"

    theater_response = client.get(f"/api/v1/findings/{finding_id}/theater")
    assert theater_response.status_code == 200
    jira_issue = theater_response.json()["remediation"]["integrations"]["jira"]
    assert jira_issue["issue_key"] == "AEGIS-42"
    assert jira_issue["issue_url"] == f"{base_url}/browse/AEGIS-42"
    assert jira_issue["issue_status"] == "Done"
    assert jira_issue["last_sync_state"] == "synced"
    assert jira_issue["last_sync_payload"]["remote_status"] == "Done"

    with client.app.state.session_factory() as session:
        event = session.scalar(
            select(AuditEvent).where(AuditEvent.action == "finding.integration_link.synced")
        )

    assert event is not None
    assert event.metadata_json["issue_key"] == "AEGIS-42"
    assert event.metadata_json["issue_status"] == "Done"
    assert event.metadata_json["last_sync_state"] == "synced"


def test_jira_finding_link_sync_failure_updates_link_state(client, jira_server) -> None:
    server, base_url = jira_server
    server.status_code = 500
    server.body = b'{"errorMessages":["Jira unavailable"]}'
    engagement_id = _create_engagement(client)
    _create_jira_configuration(client, engagement_id, base_url=base_url)
    finding_id = _seed_finding_for_engagement(client, engagement_id)

    link_response = client.put(
        f"/api/v1/engagements/{engagement_id}/integrations/jira/findings/{finding_id}",
        headers={"X-Actor": "triage-operator"},
        json={
            "issue_key": "AEGIS-42",
            "issue_url": f"{base_url}/browse/AEGIS-42",
            "issue_status": "To Do",
        },
    )
    assert link_response.status_code == 200

    sync_response = client.post(
        f"/api/v1/engagements/{engagement_id}/integrations/jira/findings/{finding_id}/sync",
        headers={"X-Actor": "sync-operator"},
    )

    assert sync_response.status_code == 502
    assert sync_response.json()["detail"] == "jira sync failed with HTTP 500"

    read_response = client.get(f"/api/v1/engagements/{engagement_id}/integrations/jira/findings/{finding_id}")
    assert read_response.status_code == 200
    link = read_response.json()
    assert link["issue_status"] == "To Do"
    assert link["last_sync_state"] == "failed"
    assert link["last_synced_at"] is not None
    assert link["last_sync_error"] == "jira sync failed with HTTP 500"
    assert link["last_sync_payload_json"]["error"] == "jira sync failed with HTTP 500"

    with client.app.state.session_factory() as session:
        event = session.scalar(
            select(AuditEvent).where(AuditEvent.action == "finding.integration_link.sync_failed")
        )

    assert event is not None
    assert event.metadata_json["issue_key"] == "AEGIS-42"
    assert event.metadata_json["last_sync_state"] == "failed"


def test_webhook_finding_handoff_is_operator_triggered_audited_and_visible(client, webhook_server) -> None:
    server, endpoint_url = webhook_server
    engagement_id = _create_engagement(client)
    configuration = _create_webhook_configuration(client, engagement_id, endpoint_url=endpoint_url)
    finding_id = _seed_finding_for_engagement(client, engagement_id)

    missing_response = client.get(f"/api/v1/engagements/{engagement_id}/integrations/webhook/findings/{finding_id}")
    assert missing_response.status_code == 404
    assert missing_response.json()["detail"] == "webhook finding handoff not found"

    handoff_response = client.post(
        f"/api/v1/engagements/{engagement_id}/integrations/webhook/findings/{finding_id}/handoff",
        headers={"X-Actor": "workflow-operator"},
        json={
            "handoff_key": "finding-42",
            "handoff_url": "https://workflow.example.test/intake/finding-42",
            "operator_note": "Please route this finding to the remediation queue.",
        },
    )

    assert handoff_response.status_code == 200
    delivered = handoff_response.json()
    assert delivered["finding_id"] == finding_id
    assert delivered["integration_configuration_id"] == configuration["id"]
    assert delivered["handoff_key"] == "WH-9001"
    assert delivered["handoff_url"] == "https://workflow.example.test/handoffs/WH-9001"
    assert delivered["handoff_status"] == "accepted"
    assert delivered["last_sync_state"] == "delivered"
    assert delivered["last_synced_at"] is not None
    assert delivered["last_sync_error"] is None
    assert delivered["last_sync_payload_json"]["http_status"] == 202
    assert delivered["last_sync_payload_json"]["remote_status"] == "accepted"
    assert delivered["created_by"] == "workflow-operator"
    assert delivered["updated_by"] == "workflow-operator"

    received = server.received_payloads[0]
    assert received["headers"]["X-AegisPT-Event"] == "aegispt.finding.handoff.requested"
    assert received["json"]["operator"] == "workflow-operator"
    assert received["json"]["engagement_id"] == engagement_id
    assert received["json"]["finding"]["id"] == finding_id
    assert received["json"]["finding"]["title"] == "Missing security header"
    assert received["json"]["finding"]["evidence_ref"] == "artifact://headers/missing-security-header"
    assert received["json"]["handoff"]["key"] == "finding-42"
    assert received["json"]["handoff"]["operator_note"] == "Please route this finding to the remediation queue."

    read_response = client.get(f"/api/v1/engagements/{engagement_id}/integrations/webhook/findings/{finding_id}")
    assert read_response.status_code == 200
    assert read_response.json() == delivered

    theater_response = client.get(f"/api/v1/findings/{finding_id}/theater")
    assert theater_response.status_code == 200
    webhook_link = theater_response.json()["remediation"]["integrations"]["webhook"]
    assert webhook_link["issue_key"] == "WH-9001"
    assert webhook_link["issue_url"] == "https://workflow.example.test/handoffs/WH-9001"
    assert webhook_link["issue_status"] == "accepted"
    assert webhook_link["last_sync_state"] == "delivered"
    assert webhook_link["last_sync_payload"]["remote_status"] == "accepted"

    with client.app.state.session_factory() as session:
        event = session.scalar(
            select(AuditEvent).where(AuditEvent.action == "finding.integration_link.webhook_delivered")
        )

    assert event is not None
    assert event.metadata_json["integration_type"] == "webhook"
    assert event.metadata_json["handoff_key"] == "WH-9001"
    assert event.metadata_json["handoff_status"] == "accepted"
    assert event.metadata_json["last_sync_state"] == "delivered"


def test_webhook_finding_handoff_failure_updates_link_state(client, webhook_server) -> None:
    server, endpoint_url = webhook_server
    server.status_code = 500
    server.body = b'{"error":"workflow unavailable"}'
    engagement_id = _create_engagement(client)
    _create_webhook_configuration(client, engagement_id, endpoint_url=endpoint_url)
    finding_id = _seed_finding_for_engagement(client, engagement_id)

    handoff_response = client.post(
        f"/api/v1/engagements/{engagement_id}/integrations/webhook/findings/{finding_id}/handoff",
        headers={"X-Actor": "workflow-operator"},
        json={
            "handoff_key": "finding-42",
            "operator_note": "Please route this finding to the remediation queue.",
        },
    )

    assert handoff_response.status_code == 502
    assert handoff_response.json()["detail"] == "webhook handoff failed with HTTP 500"

    read_response = client.get(f"/api/v1/engagements/{engagement_id}/integrations/webhook/findings/{finding_id}")
    assert read_response.status_code == 200
    link = read_response.json()
    assert link["handoff_key"] == "finding-42"
    assert link["handoff_url"] == endpoint_url
    assert link["handoff_status"] == "failed"
    assert link["last_sync_state"] == "failed"
    assert link["last_synced_at"] is not None
    assert link["last_sync_error"] == "webhook handoff failed with HTTP 500"
    assert link["last_sync_payload_json"]["http_status"] == 500
    assert link["last_sync_payload_json"]["error"] == "webhook handoff failed with HTTP 500"

    with client.app.state.session_factory() as session:
        event = session.scalar(
            select(AuditEvent).where(AuditEvent.action == "finding.integration_link.webhook_failed")
        )

    assert event is not None
    assert event.metadata_json["integration_type"] == "webhook"
    assert event.metadata_json["handoff_key"] == "finding-42"
    assert event.metadata_json["last_sync_state"] == "failed"
    assert event.metadata_json["error"] == "webhook handoff failed with HTTP 500"


def test_named_integration_configurations_are_represented_through_existing_patterns(client) -> None:
    engagement_id = _create_engagement(client)

    slack = _create_named_integration_configuration(
        client,
        engagement_id,
        "slack",
        settings_json={"channel": "#remediation"},
    )
    teams = _create_named_integration_configuration(
        client,
        engagement_id,
        "teams",
        settings_json={"conversation": "security-remediation"},
    )
    servicenow = _create_named_integration_configuration(
        client,
        engagement_id,
        "servicenow",
        settings_json={"table": "sn_si_incident"},
    )

    assert slack["integration_type"] == "slack"
    assert teams["integration_type"] == "teams"
    assert servicenow["integration_type"] == "servicenow"
    assert slack["auth_ref"] == "vault://integrations/workflow-token"

    list_response = client.get(f"/api/v1/engagements/{engagement_id}/integrations")
    assert list_response.status_code == 200
    listed_types = {item["integration_type"] for item in list_response.json()}
    assert {"slack", "teams", "servicenow"}.issubset(listed_types)

    unsupported_response = client.get(f"/api/v1/engagements/{engagement_id}/integrations/github")
    assert unsupported_response.status_code == 400
    assert unsupported_response.json()["detail"] == "unsupported integration provider: github"

    raw_secret_response = client.put(
        f"/api/v1/engagements/{engagement_id}/integrations/slack",
        headers={"X-Actor": "workflow-admin"},
        json={
            "integration_type": "slack",
            "display_name": "Unsafe Slack",
            "base_url": "https://slack.example.test/acme",
            "auth_ref": "xoxb-raw-token-material",
            "settings_json": {"channel": "#remediation"},
        },
    )
    assert raw_secret_response.status_code == 422


def test_named_provider_finding_handoff_is_prepared_and_visible(client) -> None:
    engagement_id = _create_engagement(client)
    configuration = _create_named_integration_configuration(
        client,
        engagement_id,
        "slack",
        settings_json={"channel": "#vulnerability-triage"},
    )
    finding_id = _seed_finding_for_engagement(client, engagement_id)

    missing_response = client.get(f"/api/v1/engagements/{engagement_id}/integrations/slack/findings/{finding_id}")
    assert missing_response.status_code == 404
    assert missing_response.json()["detail"] == "slack finding handoff not found"

    handoff_response = client.post(
        f"/api/v1/engagements/{engagement_id}/integrations/slack/findings/{finding_id}/handoff",
        headers={"X-Actor": "workflow-operator"},
        json={
            "handoff_key": "SLACK-42",
            "handoff_url": "https://slack.example.test/archives/CSEC/p42",
            "operator_note": "Route to the remediation channel for review.",
        },
    )

    assert handoff_response.status_code == 200
    prepared = handoff_response.json()
    assert prepared["finding_id"] == finding_id
    assert prepared["integration_configuration_id"] == configuration["id"]
    assert prepared["integration_type"] == "slack"
    assert prepared["handoff_key"] == "SLACK-42"
    assert prepared["handoff_url"] == "https://slack.example.test/archives/CSEC/p42"
    assert prepared["handoff_status"] == "prepared"
    assert prepared["last_sync_state"] == "prepared"
    assert prepared["last_sync_error"] is None
    assert prepared["last_sync_payload_json"]["external_delivery_attempted"] is False
    assert prepared["last_sync_payload_json"]["routing"]["target"] == "#vulnerability-triage"
    assert prepared["last_sync_payload_json"]["auth_ref_kind"] == "vault"

    read_response = client.get(f"/api/v1/engagements/{engagement_id}/integrations/slack/findings/{finding_id}")
    assert read_response.status_code == 200
    assert read_response.json() == prepared

    theater_response = client.get(f"/api/v1/findings/{finding_id}/theater")
    assert theater_response.status_code == 200
    slack_link = theater_response.json()["remediation"]["integrations"]["slack"]
    assert slack_link["integration_type"] == "slack"
    assert slack_link["display_name"] == "Acme Slack"
    assert slack_link["issue_key"] == "SLACK-42"
    assert slack_link["issue_status"] == "prepared"
    assert slack_link["last_sync_state"] == "prepared"

    with client.app.state.session_factory() as session:
        event = session.scalar(
            select(AuditEvent).where(AuditEvent.action == "finding.integration_link.provider_prepared")
        )

    assert event is not None
    assert event.metadata_json["integration_type"] == "slack"
    assert event.metadata_json["handoff_key"] == "SLACK-42"
    assert event.metadata_json["last_sync_state"] == "prepared"


def test_named_provider_finding_handoff_missing_credentials_is_visible(client) -> None:
    engagement_id = _create_engagement(client)
    _create_named_integration_configuration(
        client,
        engagement_id,
        "teams",
        auth_ref=None,
        settings_json={"conversation": "security-remediation"},
    )
    finding_id = _seed_finding_for_engagement(client, engagement_id)

    handoff_response = client.post(
        f"/api/v1/engagements/{engagement_id}/integrations/teams/findings/{finding_id}/handoff",
        headers={"X-Actor": "workflow-operator"},
        json={"handoff_key": "TEAMS-42"},
    )

    assert handoff_response.status_code == 409
    assert handoff_response.json()["detail"] == "Microsoft Teams handoff requires protected auth_ref before handoff"

    read_response = client.get(f"/api/v1/engagements/{engagement_id}/integrations/teams/findings/{finding_id}")
    assert read_response.status_code == 200
    link = read_response.json()
    assert link["handoff_key"] == "TEAMS-42"
    assert link["handoff_status"] == "missing_credentials"
    assert link["last_sync_state"] == "blocked"
    assert link["last_sync_payload_json"]["blocked_reason"] == "missing_credentials"
    assert link["last_sync_error"] == "Microsoft Teams handoff requires protected auth_ref before handoff"

    theater_response = client.get(f"/api/v1/findings/{finding_id}/theater")
    assert theater_response.status_code == 200
    teams_link = theater_response.json()["remediation"]["integrations"]["teams"]
    assert teams_link["issue_status"] == "missing_credentials"
    assert teams_link["last_sync_state"] == "blocked"

    with client.app.state.session_factory() as session:
        event = session.scalar(
            select(AuditEvent).where(AuditEvent.action == "finding.integration_link.provider_blocked")
        )

    assert event is not None
    assert event.metadata_json["integration_type"] == "teams"
    assert event.metadata_json["handoff_status"] == "missing_credentials"
    assert event.metadata_json["last_sync_state"] == "blocked"


def test_named_provider_finding_handoff_failure_updates_link_state(client) -> None:
    engagement_id = _create_engagement(client)
    _create_named_integration_configuration(
        client,
        engagement_id,
        "servicenow",
        settings_json={
            "table": "sn_si_incident",
            "handoff_failure_reason": "controlled broker rejected the request",
        },
    )
    finding_id = _seed_finding_for_engagement(client, engagement_id)

    handoff_response = client.post(
        f"/api/v1/engagements/{engagement_id}/integrations/servicenow/findings/{finding_id}/handoff",
        headers={"X-Actor": "workflow-operator"},
        json={"handoff_key": "SN-42"},
    )

    assert handoff_response.status_code == 502
    assert handoff_response.json()["detail"] == "ServiceNow handoff failed: controlled broker rejected the request"

    read_response = client.get(f"/api/v1/engagements/{engagement_id}/integrations/servicenow/findings/{finding_id}")
    assert read_response.status_code == 200
    link = read_response.json()
    assert link["handoff_key"] == "SN-42"
    assert link["handoff_status"] == "failed"
    assert link["last_sync_state"] == "failed"
    assert link["last_sync_error"] == "ServiceNow handoff failed: controlled broker rejected the request"
    assert link["last_sync_payload_json"]["external_delivery_attempted"] is False

    with client.app.state.session_factory() as session:
        event = session.scalar(
            select(AuditEvent).where(AuditEvent.action == "finding.integration_link.provider_failed")
        )

    assert event is not None
    assert event.metadata_json["integration_type"] == "servicenow"
    assert event.metadata_json["handoff_status"] == "failed"


def test_unsupported_provider_finding_handoff_returns_explicit_fallback(client) -> None:
    engagement_id = _create_engagement(client)
    finding_id = _seed_finding_for_engagement(client, engagement_id)

    response = client.post(
        f"/api/v1/engagements/{engagement_id}/integrations/github/findings/{finding_id}/handoff",
        headers={"X-Actor": "workflow-operator"},
        json={"handoff_key": "GH-42"},
    )

    assert response.status_code == 400
    assert response.json()["detail"] == "unsupported integration provider: github"
