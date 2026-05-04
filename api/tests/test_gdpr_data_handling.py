from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from uuid import UUID

from sqlalchemy import select

from api.app.config import get_settings
from api.app.models import (
    AuditEvent,
    Engagement,
    EvidenceArtifact,
    Finding,
    InventorySnapshot,
    Run,
    SecretRef,
    Task,
    ToolExecution,
)
from api.app.services.secrets import encrypt_secret_value


def _create_engagement(client, *, retention_days: int = 90) -> dict:
    response = client.post(
        "/api/v1/engagements",
        headers={"X-Actor": "gdpr-operator"},
        json={
            "name": "AVG Client Review",
            "client": "Acme BV",
            "roe_ref": "ROE-AVG-1",
            "retention_days": retention_days,
        },
    )
    assert response.status_code == 201
    return response.json()


def _seed_assessment_data(client, engagement_id: str, *, old: bool = False) -> dict[str, str]:
    timestamp = datetime.now(tz=UTC) - timedelta(days=12 if old else 1)
    raw_secret = "CorrectHorseBatteryStaple!"
    with client.app.state.session_factory() as session:
        run = Run(
            engagement_id=UUID(engagement_id),
            requested_by="gdpr-operator",
            status="completed",
            configuration_json={
                "targets": {"cidr": ["10.0.20.0/24"]},
                "access": {
                    "accounts": [
                        {
                            "username": "alice@example.test",
                            "secret_ref": raw_secret,
                            "api_key_ref": "super-secret-api-key",
                        }
                    ]
                },
            },
            created_at=timestamp,
            updated_at=timestamp,
        )
        session.add(run)
        session.flush()
        task = Task(
            run_id=run.id,
            tool="nmap",
            target_id="10.0.20.1",
            params_json={"password": raw_secret, "targets": ["10.0.20.1"]},
            status="completed",
            created_at=timestamp,
            updated_at=timestamp,
        )
        session.add(task)
        session.flush()
        execution = ToolExecution(
            task_id=task.id,
            runner_digest="sha256:gdpr",
            tool_version="nmap/test",
            exit_code=0,
            stdout_text=f"discovered host with token={raw_secret}",
            stderr_text="",
            created_at=timestamp,
            updated_at=timestamp,
        )
        session.add(execution)
        session.flush()
        artifact = EvidenceArtifact(
            tool_execution_id=execution.id,
            kind="nmap-xml",
            uri="artifact://gdpr/nmap.xml",
            sha256="d" * 64,
            redaction_state="clean",
            metadata_json={"source": "test", "api_key": "must-not-export"},
            created_at=timestamp,
            updated_at=timestamp,
        )
        finding = Finding(
            run_id=run.id,
            title="Sensitive service banner",
            severity="medium",
            target_id="10.0.20.1",
            evidence_ref="artifact://gdpr/finding",
            status="open",
            summary="Host disclosed a personal-data-bearing service banner.",
            methodology_tags=["gdpr"],
            control_family="configuration",
            created_at=timestamp,
            updated_at=timestamp,
        )
        inventory = InventorySnapshot(
            engagement_id=UUID(engagement_id),
            requested_by="gdpr-operator",
            status="completed",
            source_tools_json=["nmap"],
            raw_inputs_json={"target": "10.0.20.0/24"},
            normalized_inventory_json={
                "hosts": [{"ip": "10.0.20.1", "username": "alice@example.test"}],
                "service_banners": ["OpenSSH test"],
            },
            summary_json={"host_count": 1},
            environment_notes_json=[],
            assumptions_json=[],
            confidence_score=0.9,
            created_at=timestamp,
            updated_at=timestamp,
        )
        secret_ref = SecretRef(
            engagement_id=UUID(engagement_id),
            vault_pointer="aegispt://secret-ref/gdpr-test",
            purpose="run.access.password",
            secret_kind="password",
            storage_backend="encrypted_local",
            display_label="password protected locally",
            encrypted_value=encrypt_secret_value(raw_secret, get_settings()),
            metadata_json={"raw_secret_material_exposed": False},
            created_at=timestamp,
            updated_at=timestamp,
        )
        session.add_all([artifact, finding, inventory, secret_ref])
        session.commit()
        return {
            "run_id": str(run.id),
            "task_id": str(task.id),
            "finding_id": str(finding.id),
            "inventory_id": str(inventory.id),
            "raw_secret": raw_secret,
        }


def test_engagement_retention_policy_soft_deletes_expired_run_data(client) -> None:
    engagement = _create_engagement(client, retention_days=7)
    seeded = _seed_assessment_data(client, engagement["id"], old=True)

    status_response = client.get(f"/api/v1/engagements/{engagement['id']}/data-retention")
    assert status_response.status_code == 200
    assert status_response.json()["retention_days"] == 7
    assert status_response.json()["eligible_run_count"] == 1

    cleanup_response = client.post(
        f"/api/v1/engagements/{engagement['id']}/data-retention/cleanup",
        headers={"X-Actor": "privacy-officer"},
    )
    assert cleanup_response.status_code == 200
    assert cleanup_response.json()["soft_deleted_runs"] == 1
    assert seeded["run_id"] in cleanup_response.json()["soft_deleted_run_ids"]

    with client.app.state.session_factory() as session:
        run = session.get(Run, UUID(seeded["run_id"]))
        assert run is not None
        assert run.deleted_at is not None
        audit = session.scalar(
            select(AuditEvent).where(
                AuditEvent.action == "engagement.retention_cleanup",
                AuditEvent.object_id == engagement["id"],
            )
        )
        assert audit is not None
        assert audit.metadata_json["retention_days"] == 7


def test_data_export_excludes_credential_material_and_records_audit(client) -> None:
    engagement = _create_engagement(client)
    seeded = _seed_assessment_data(client, engagement["id"])

    response = client.get(
        f"/api/v1/engagements/{engagement['id']}/data-export",
        headers={"X-Actor": "privacy-officer"},
    )
    assert response.status_code == 200
    payload = response.json()
    rendered = json.dumps(payload)
    assert payload["credential_material_included"] is False
    assert payload["engagement"]["retention_days"] == 90
    assert payload["runs"]
    assert payload["findings"]
    assert payload["artifacts"]
    assert payload["inventory_snapshots"]
    assert payload["secret_refs"][0]["credential_material_included"] is False
    assert seeded["raw_secret"] not in rendered
    assert "super-secret-api-key" not in rendered
    assert "must-not-export" not in rendered
    assert "encrypted_value" not in rendered
    assert "vault_pointer" not in rendered

    with client.app.state.session_factory() as session:
        audit = session.scalar(
            select(AuditEvent).where(
                AuditEvent.action == "engagement.data_exported",
                AuditEvent.object_id == engagement["id"],
            )
        )
        assert audit is not None
        assert audit.metadata_json["credential_material_included"] is False


def test_hard_purge_requires_confirmation_and_deletes_assessment_data(client) -> None:
    engagement = _create_engagement(client)
    seeded = _seed_assessment_data(client, engagement["id"])

    rejected = client.request(
        "DELETE",
        f"/api/v1/engagements/{engagement['id']}/purge",
        json={"confirmation": engagement["name"]},
    )
    assert rejected.status_code == 409

    response = client.request(
        "DELETE",
        f"/api/v1/engagements/{engagement['id']}/purge",
        headers={"X-Actor": "privacy-officer"},
        json={"confirmation": f"PURGE {engagement['name']}"},
    )
    assert response.status_code == 200
    payload = response.json()
    assert payload["credential_material_exported"] is False
    assert payload["counts"]["runs"] == 1
    assert payload["counts"]["findings"] == 1
    assert "engagement" in payload["retained_records"]

    with client.app.state.session_factory() as session:
        assert session.get(Engagement, UUID(engagement["id"])) is not None
        assert session.get(Run, UUID(seeded["run_id"])) is None
        assert session.get(Task, UUID(seeded["task_id"])) is None
        assert session.get(Finding, UUID(seeded["finding_id"])) is None
        assert session.get(InventorySnapshot, UUID(seeded["inventory_id"])) is None
        assert session.scalar(select(SecretRef).where(SecretRef.engagement_id == UUID(engagement["id"]))) is None
        audit = session.scalar(
            select(AuditEvent).where(
                AuditEvent.action == "engagement.assessment_data_purged",
                AuditEvent.object_id == engagement["id"],
            )
        )
        assert audit is not None
        assert audit.metadata_json["credential_material_exported"] is False


def test_retention_policy_update_is_per_engagement(client) -> None:
    first = _create_engagement(client, retention_days=30)
    second = _create_engagement(client, retention_days=90)

    response = client.patch(
        f"/api/v1/engagements/{first['id']}/data-retention",
        headers={"X-Actor": "privacy-officer"},
        json={"retention_days": 14},
    )
    assert response.status_code == 200
    assert response.json()["retention_days"] == 14

    first_read = client.get(f"/api/v1/engagements/{first['id']}").json()
    second_read = client.get(f"/api/v1/engagements/{second['id']}").json()
    assert first_read["retention_days"] == 14
    assert second_read["retention_days"] == 90
