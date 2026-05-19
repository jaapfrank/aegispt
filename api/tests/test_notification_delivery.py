from __future__ import annotations

import json
from email.message import EmailMessage
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread
from uuid import UUID

import pytest
from sqlalchemy import select

from api.app.config import Settings
from api.app.models import AssessmentChain, AuditEvent, Finding, InstanceSetting, Run
from api.app.services.notification_delivery import (
    deliver_critical_finding_notifications,
    deliver_phase_approval_needed_notifications,
    deliver_run_completion_notifications,
)


class NotificationWebhookHandler(BaseHTTPRequestHandler):
    def do_POST(self) -> None:  # noqa: N802
        length = int(self.headers.get("Content-Length") or "0")
        raw_body = self.rfile.read(length)
        received_requests = getattr(self.server, "received_requests", [])
        received_requests.append(
            {
                "path": self.path,
                "headers": dict(self.headers.items()),
                "json": json.loads(raw_body.decode("utf-8")),
            }
        )
        self.server.received_requests = received_requests

        status_code = getattr(self.server, "status_code", 200)
        body = b'{"accepted":true}'
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args) -> None:  # noqa: A003
        return


@pytest.fixture
def notification_server() -> tuple[ThreadingHTTPServer, str]:
    server = ThreadingHTTPServer(("127.0.0.1", 0), NotificationWebhookHandler)
    server.received_requests = []
    server.status_code = 200
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = server.server_address
    try:
        yield server, f"http://{host}:{port}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


class FakeSMTP:
    sent_messages: list[EmailMessage] = []
    connections: list[dict[str, object]] = []

    def __init__(self, host: str, port: int, *, timeout: float) -> None:
        self.host = host
        self.port = port
        self.timeout = timeout
        self.started_tls = False
        self.login_args: tuple[str, str] | None = None
        self.__class__.connections.append({"host": host, "port": port, "timeout": timeout})

    def __enter__(self) -> "FakeSMTP":
        return self

    def __exit__(self, exc_type, exc, traceback) -> None:  # noqa: ANN001
        return None

    def starttls(self) -> None:
        self.started_tls = True

    def login(self, username: str, password: str) -> None:
        self.login_args = (username, password)

    def send_message(self, message: EmailMessage) -> None:
        self.__class__.sent_messages.append(message)


def _create_engagement(client) -> str:
    response = client.post(
        "/api/v1/engagements",
        headers={"X-Actor": "notification-admin"},
        json={
            "name": "Notification Engagement",
            "client": "Acme Corp",
            "roe_ref": "ROE-NOTIFY-1",
        },
    )
    assert response.status_code == 201
    return response.json()["id"]


def _configure_notifications(client, base_url: str) -> dict:
    response = client.patch(
        "/api/v1/settings",
        headers={"X-Actor": "notification-admin"},
        json={
            "settings": {
                "notifications.email_enabled": True,
                "notifications.smtp_host": "smtp.example.test",
                "notifications.smtp_port": 2525,
                "notifications.smtp_username": "alerts@example.test",
                "notifications.smtp_password": "smtp-secret-value",
                "notifications.smtp_use_tls": True,
                "notifications.smtp_from": "aegispt@example.test",
                "notifications.smtp_to": ["secops@example.test", "owner@example.test"],
                "notifications.run_completion": True,
                "notifications.phase_approval_needed": True,
                "notifications.delivery_timeout_seconds": 3,
                "integrations.slack_webhook_url": f"{base_url}/slack",
                "integrations.teams_webhook_url": f"{base_url}/teams",
            }
        },
    )
    assert response.status_code == 200
    return response.json()


def _seed_run_and_finding(
    client,
    engagement_id: str,
    *,
    severity: str = "critical",
) -> tuple[str, str]:
    with client.app.state.session_factory() as session:
        run = Run(
            engagement_id=UUID(engagement_id),
            requested_by="notification-admin",
            status="completed",
            configuration_json={},
        )
        session.add(run)
        session.flush()
        finding = Finding(
            run_id=run.id,
            title="Critical SQL injection in search parameter",
            severity=severity,
            target_id="https://portal.example.test/search",
            evidence_ref="artifact://notification/test-evidence",
            status="open",
            summary="Search input triggers database errors with SQL control characters.",
            autofix_json={"remediation_summary": "Use parameterized queries and centralized input validation."},
            methodology_tags=["WSTG", "injection"],
            wstg_id="WSTG-INPV-05",
            control_family="input_validation",
        )
        session.add(finding)
        session.commit()
        return str(run.id), str(finding.id)


def _seed_pending_phase_chain(client, engagement_id: str, run_id: str) -> str:
    with client.app.state.session_factory() as session:
        chain = AssessmentChain(
            engagement_id=UUID(engagement_id),
            current_run_id=UUID(run_id),
            last_completed_run_id=UUID(run_id),
            assessment_mode="full-external-web",
            status="pending_phase_approval",
            current_phase_index=1,
            current_step_index=0,
            auto_advance_on_phase_complete=True,
            created_by="notification-admin",
            phases_json=[
                {
                    "key": "passive-recon",
                    "label": "Passive Recon",
                    "status": "completed",
                    "completed_at": "2026-05-05T08:00:00+00:00",
                    "requires_approval": False,
                },
                {
                    "key": "active-validation",
                    "label": "Active Validation",
                    "status": "pending_approval",
                    "requires_approval": True,
                },
            ],
            configuration_json={},
            metadata_json={},
        )
        session.add(chain)
        session.commit()
        return str(chain.id)


def test_settings_store_email_slack_and_teams_credentials_encrypted(client, notification_server) -> None:
    _server, base_url = notification_server
    payload = _configure_notifications(client, base_url)
    serialized = json.dumps(payload)

    assert "smtp-secret-value" not in serialized
    assert f"{base_url}/slack" not in serialized
    assert f"{base_url}/teams" not in serialized

    settings = {
        setting["key"]: setting
        for section in payload["sections"]
        for setting in section["settings"]
    }
    assert settings["notifications.smtp_password"]["configured"] is True
    assert settings["integrations.slack_webhook_url"]["configured"] is True
    assert settings["integrations.teams_webhook_url"]["configured"] is True

    with client.app.state.session_factory() as session:
        rows = {
            row.setting_key: row
            for row in session.scalars(
                select(InstanceSetting).where(
                    InstanceSetting.setting_key.in_(
                        [
                            "notifications.smtp_password",
                            "integrations.slack_webhook_url",
                            "integrations.teams_webhook_url",
                        ]
                    )
                )
            ).all()
        }

    assert rows["notifications.smtp_password"].sensitive is True
    assert rows["notifications.smtp_password"].encrypted_value
    assert "smtp-secret-value" not in rows["notifications.smtp_password"].encrypted_value
    assert rows["integrations.slack_webhook_url"].sensitive is True
    assert f"{base_url}/slack" not in rows["integrations.slack_webhook_url"].encrypted_value
    assert rows["integrations.teams_webhook_url"].sensitive is True
    assert f"{base_url}/teams" not in rows["integrations.teams_webhook_url"].encrypted_value


def test_critical_finding_notifications_deliver_email_slack_and_teams(client, notification_server) -> None:
    server, base_url = notification_server
    engagement_id = _create_engagement(client)
    _configure_notifications(client, base_url)
    _run_id, finding_id = _seed_run_and_finding(client, engagement_id)
    FakeSMTP.sent_messages = []
    FakeSMTP.connections = []

    with client.app.state.session_factory() as session:
        receipts = deliver_critical_finding_notifications(
            session=session,
            finding_ids=[UUID(finding_id)],
            actor="notification-bot",
            settings=Settings(app_public_base_url="https://aegispt.example.test"),
            smtp_factory=FakeSMTP,
        )
        session.commit()

    assert {receipt.channel for receipt in receipts} == {"email", "slack", "teams"}
    assert all(receipt.delivered for receipt in receipts)
    assert FakeSMTP.connections == [{"host": "smtp.example.test", "port": 2525, "timeout": 3.0}]
    assert len(FakeSMTP.sent_messages) == 1
    email = FakeSMTP.sent_messages[0]
    assert email["Subject"] == "[AegisPT] Critical finding: Critical SQL injection in search parameter"
    assert email["To"] == "secops@example.test, owner@example.test"
    assert "Use parameterized queries" in email.get_content()

    assert len(server.received_requests) == 2
    slack_request = next(request for request in server.received_requests if request["path"] == "/slack")
    teams_request = next(request for request in server.received_requests if request["path"] == "/teams")
    assert slack_request["json"]["metadata"]["event_kind"] == "critical_finding"
    assert "Open finding" in json.dumps(slack_request["json"])
    assert teams_request["json"]["attachments"][0]["contentType"] == "application/vnd.microsoft.card.adaptive"
    assert teams_request["json"]["attachments"][0]["content"]["metadata"]["event_kind"] == "critical_finding"

    with client.app.state.session_factory() as session:
        delivered_events = session.scalars(
            select(AuditEvent).where(AuditEvent.action == "notification.delivery.delivered")
        ).all()
    assert {event.metadata_json["channel"] for event in delivered_events} == {"email", "slack", "teams"}
    assert all(event.metadata_json["sensitive_plaintext_exposed"] is False for event in delivered_events)


def test_run_completion_and_phase_approval_notifications_trigger_configured_channels(
    client,
    notification_server,
) -> None:
    server, base_url = notification_server
    engagement_id = _create_engagement(client)
    _configure_notifications(client, base_url)
    run_id, _finding_id = _seed_run_and_finding(client, engagement_id, severity="high")
    chain_id = _seed_pending_phase_chain(client, engagement_id, run_id)

    with client.app.state.session_factory() as session:
        run_receipts = deliver_run_completion_notifications(
            session=session,
            run_id=UUID(run_id),
            actor="notification-bot",
            settings=Settings(app_public_base_url="https://aegispt.example.test"),
            smtp_factory=FakeSMTP,
        )
        phase_receipts = deliver_phase_approval_needed_notifications(
            session=session,
            chain_id=UUID(chain_id),
            actor="notification-bot",
            settings=Settings(app_public_base_url="https://aegispt.example.test"),
            smtp_factory=FakeSMTP,
        )
        session.commit()

    assert {receipt.event_kind for receipt in run_receipts} == {"run_completion"}
    assert {receipt.event_kind for receipt in phase_receipts} == {"phase_approval_needed"}
    assert all(receipt.delivered for receipt in [*run_receipts, *phase_receipts])

    phase_requests = [
        request
        for request in server.received_requests
        if request["headers"].get("X-AegisPT-Event") == "phase_approval_needed"
    ]
    assert len(phase_requests) == 2
    assert "Active Validation" in json.dumps([request["json"] for request in phase_requests])
    assert "assessment_chain_id" in json.dumps([request["json"] for request in phase_requests])


def test_notifications_are_noop_when_no_channels_configured(client) -> None:
    engagement_id = _create_engagement(client)
    run_id, finding_id = _seed_run_and_finding(client, engagement_id)

    with client.app.state.session_factory() as session:
        critical_receipts = deliver_critical_finding_notifications(
            session=session,
            finding_ids=[UUID(finding_id)],
            actor="notification-bot",
            settings=Settings(),
        )
        run_receipts = deliver_run_completion_notifications(
            session=session,
            run_id=UUID(run_id),
            actor="notification-bot",
            settings=Settings(),
        )
        session.commit()

    assert critical_receipts == []
    assert run_receipts == []
