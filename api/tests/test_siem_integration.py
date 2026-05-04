from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread
from uuid import UUID

import pytest
from sqlalchemy import select

from api.app.config import Settings
from api.app.models import (
    AuditEvent,
    Finding,
    FindingIntegrationLink,
    IntegrationConfiguration,
    Run,
    SecretRef,
)
from api.app.services.siem_push import (
    deliver_critical_findings_to_configured_siems,
    deliver_run_completion_to_configured_siems,
)


class SiemEventHandler(BaseHTTPRequestHandler):
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
        body = getattr(self.server, "body", b'{"accepted":true}')
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args) -> None:  # noqa: A003
        return


@pytest.fixture
def siem_server() -> tuple[ThreadingHTTPServer, str]:
    server = ThreadingHTTPServer(("127.0.0.1", 0), SiemEventHandler)
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


def _create_engagement(client) -> str:
    response = client.post(
        "/api/v1/engagements",
        headers={"X-Actor": "siem-admin"},
        json={
            "name": "SIEM Integration Engagement",
            "client": "Acme Corp",
            "roe_ref": "ROE-SIEM-1",
        },
    )
    assert response.status_code == 201
    return response.json()["id"]


def _create_siem_configuration(
    client,
    engagement_id: str,
    *,
    provider: str,
    base_url: str,
    credential: str | None = "super-secret-token",
    include_sigma: bool = False,
    extra: dict | None = None,
) -> dict:
    payload = {
        "integration_type": provider,
        "display_name": f"Acme {provider.title()}",
        "base_url": base_url,
        "credential": credential,
        "enabled": True,
        "push_on_run_completion": True,
        "push_on_critical_finding": True,
        "include_sigma": include_sigma,
    }
    payload.update(extra or {})
    response = client.put(
        f"/api/v1/engagements/{engagement_id}/integrations/siem/{provider}",
        headers={"X-Actor": "siem-admin"},
        json=payload,
    )
    assert response.status_code == 200
    return response.json()


def _seed_run_and_finding(
    client,
    engagement_id: str,
    *,
    severity: str,
    title: str,
    summary: str,
    target_id: str = "https://portal.example.test/search",
) -> tuple[str, str]:
    with client.app.state.session_factory() as session:
        run = Run(
            engagement_id=UUID(engagement_id),
            requested_by="siem-admin",
            status="completed",
            configuration_json={},
        )
        session.add(run)
        session.flush()
        finding = Finding(
            run_id=run.id,
            title=title,
            severity=severity,
            target_id=target_id,
            evidence_ref="artifact://siem/test-evidence",
            status="open",
            summary=summary,
            methodology_tags=["WSTG", "injection"],
            wstg_id="WSTG-INPV-05",
            control_family="input_validation",
        )
        session.add(finding)
        session.commit()
        return str(run.id), str(finding.id)


def test_siem_configuration_encrypts_credential_and_returns_masked_view(client) -> None:
    engagement_id = _create_engagement(client)
    secret = "splunk-hec-token-raw"

    response = client.put(
        f"/api/v1/engagements/{engagement_id}/integrations/siem/splunk",
        headers={"X-Actor": "siem-admin"},
        json={
            "integration_type": "splunk",
            "display_name": "Acme Splunk",
            "base_url": "https://splunk.example.test/services/collector/event",
            "credential": secret,
            "enabled": True,
            "push_on_run_completion": True,
            "push_on_critical_finding": True,
            "include_sigma": True,
            "index_name": "aegispt_pentest",
            "sourcetype": "aegispt:pentest:finding",
        },
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["integration_type"] == "splunk"
    assert payload["credential_configured"] is True
    assert payload["credential_display_label"]
    assert payload["token_exposed"] is False
    assert "credential" not in payload
    assert secret not in json.dumps(payload)

    listing = client.get(f"/api/v1/engagements/{engagement_id}/integrations/siem")
    assert listing.status_code == 200
    providers = {item["integration_type"] for item in listing.json()["providers"]}
    assert "splunk" in providers

    with client.app.state.session_factory() as session:
        configuration = session.scalar(
            select(IntegrationConfiguration).where(
                IntegrationConfiguration.engagement_id == UUID(engagement_id),
                IntegrationConfiguration.integration_type == "splunk",
            )
        )
        assert configuration is not None
        assert configuration.auth_ref.startswith("aegispt://secret-ref/")
        secret_ref = session.get(SecretRef, UUID(configuration.auth_ref.removeprefix("aegispt://secret-ref/")))

    assert secret_ref is not None
    assert secret_ref.encrypted_value
    assert secret not in secret_ref.encrypted_value


def test_critical_finding_push_delivers_splunk_event_and_updates_finding_link(client, siem_server) -> None:
    server, base_url = siem_server
    engagement_id = _create_engagement(client)
    _create_siem_configuration(
        client,
        engagement_id,
        provider="splunk",
        base_url=f"{base_url}/services/collector/event",
        include_sigma=True,
        extra={"index_name": "aegispt_pentest", "sourcetype": "aegispt:pentest:finding"},
    )
    _, finding_id = _seed_run_and_finding(
        client,
        engagement_id,
        severity="critical",
        title="SQL injection in search parameter",
        summary="Repeated SQL metacharacters trigger a server-side error on the search endpoint.",
    )

    with client.app.state.session_factory() as session:
        receipts = deliver_critical_findings_to_configured_siems(
            session=session,
            finding_ids=[UUID(finding_id)],
            actor="siem-bot",
            settings=Settings(),
        )
        session.commit()

    assert len(receipts) == 1
    assert receipts[0].provider == "splunk"
    assert receipts[0].delivered is True
    assert len(server.received_requests) == 1
    request = server.received_requests[0]
    assert request["path"] == "/services/collector/event"
    assert request["headers"]["Authorization"].startswith("Splunk ")
    assert request["json"]["source"] == "aegispt-pentest-finding"
    assert request["json"]["event"]["event_kind"] == "critical_finding"
    assert request["json"]["event"]["finding"]["severity"] == "critical"
    assert request["json"]["event"]["sigma_exports"]

    theater_response = client.get(f"/api/v1/findings/{finding_id}/theater")
    assert theater_response.status_code == 200
    splunk_link = theater_response.json()["remediation"]["integrations"]["splunk"]
    assert splunk_link["integration_type"] == "splunk"
    assert splunk_link["issue_status"] == "delivered"
    assert splunk_link["last_sync_state"] == "delivered"
    assert splunk_link["last_sync_payload"]["source"] == "aegispt-pentest-finding"

    with client.app.state.session_factory() as session:
        event = session.scalar(
            select(AuditEvent).where(AuditEvent.action == "finding.integration_link.siem_delivered")
        )
    assert event is not None
    assert event.metadata_json["integration_type"] == "splunk"


def test_run_completion_push_delivers_elastic_ecs_and_sentinel_log_entries(client, siem_server) -> None:
    server, base_url = siem_server
    engagement_id = _create_engagement(client)
    _create_siem_configuration(
        client,
        engagement_id,
        provider="elastic",
        base_url=base_url,
        extra={"index_name": "aegispt-findings"},
    )
    _create_siem_configuration(
        client,
        engagement_id,
        provider="sentinel",
        base_url=f"{base_url}/ingest",
        extra={"custom_log_table": "AegisPTFindings_CL", "stream_name": "Custom-AegisPTFindings"},
    )
    run_id, _ = _seed_run_and_finding(
        client,
        engagement_id,
        severity="high",
        title="Missing X-Frame-Options header",
        summary="The admin portal omits a browser hardening header on a privileged route.",
    )

    with client.app.state.session_factory() as session:
        receipts = deliver_run_completion_to_configured_siems(
            session=session,
            run_id=UUID(run_id),
            actor="siem-bot",
            settings=Settings(),
        )
        session.commit()

    assert len(receipts) == 4
    assert sum(1 for item in receipts if item.delivered) == 4
    elastic_request = next(item for item in server.received_requests if item["path"] == "/aegispt-findings/_doc")
    sentinel_request = next(item for item in server.received_requests if item["path"] == "/ingest")

    assert elastic_request["json"]["event"]["provider"] == "AegisPT"
    assert elastic_request["json"]["event"]["module"] == "aegispt-pentest-finding"
    assert "@timestamp" in elastic_request["json"]

    sentinel_entry = sentinel_request["json"][0]
    assert sentinel_entry["AegisPTSource"] == "aegispt-pentest-finding"
    assert sentinel_entry["AegisPTTable"] == "AegisPTFindings_CL"

    with client.app.state.session_factory() as session:
        events = session.scalars(
            select(AuditEvent).where(AuditEvent.action == "run.integration.siem_delivered")
        ).all()
    assert len(events) >= 2


def test_siem_delivery_failure_is_recorded_without_blocking_findings(client, siem_server) -> None:
    server, base_url = siem_server
    server.status_code = 500
    engagement_id = _create_engagement(client)
    _create_siem_configuration(
        client,
        engagement_id,
        provider="splunk",
        base_url=f"{base_url}/services/collector/event",
    )
    _, finding_id = _seed_run_and_finding(
        client,
        engagement_id,
        severity="critical",
        title="Critical configuration weakness",
        summary="Critical hardening gap for mock SIEM failure coverage.",
    )

    with client.app.state.session_factory() as session:
        receipts = deliver_critical_findings_to_configured_siems(
            session=session,
            finding_ids=[UUID(finding_id)],
            actor="siem-bot",
            settings=Settings(),
        )
        session.commit()
        link = session.scalar(
            select(FindingIntegrationLink)
            .join(IntegrationConfiguration)
            .where(
                FindingIntegrationLink.finding_id == UUID(finding_id),
                IntegrationConfiguration.integration_type == "splunk",
            )
        )

    assert len(receipts) == 1
    assert receipts[0].delivered is False
    assert "HTTP 500" in str(receipts[0].error)
    assert link is not None
    assert link.last_sync_state == "failed"
    assert "HTTP 500" in str(link.last_sync_error)

    with client.app.state.session_factory() as session:
        event = session.scalar(
            select(AuditEvent).where(AuditEvent.action == "finding.integration_link.siem_failed")
        )
    assert event is not None
    assert event.metadata_json["integration_type"] == "splunk"
