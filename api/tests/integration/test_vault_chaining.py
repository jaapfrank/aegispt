from __future__ import annotations

import json
from uuid import UUID

from sqlalchemy import select

from api.app.config import get_settings
from api.app.models import AuditEvent, Run, RunProfile, SecretRef, Task
from api.app.services.run_credential_vault import (
    run_credential_vault_payload,
    store_protected_outputs_in_run_credential_vault,
)
from workers.orchestration.tasks import _runner_params_for_task
from workers.runners.base.contracts import ProtectedSecretMaterial

TARGET_URL = "https://vault-chain.example.test"
PLAINTEXT_SESSION = "sessionid=runner-discovered-super-secret"


def test_authenticated_runner_chaining_keeps_vault_secret_encrypted_and_redacted(client) -> None:
    engagement_id = _create_engagement_and_scope(client)
    run_id = _create_ai_loop_run(client, engagement_id)

    with client.app.state.session_factory() as session:
        run = session.get(Run, UUID(run_id))
        assert run is not None
        discovery_task = Task(
            run=run,
            tool="session-security",
            target_id=TARGET_URL,
            status="completed",
            params_json={
                "target_kind": "url",
                "profile_name": "autonomous-web",
                "run_class": "active",
                "assessment_loop": {
                    "enabled": True,
                    "run_mode": "ai_loop",
                    "iteration": 2,
                    "approval_effect": "operator_approved",
                    "scope_enforced": True,
                    "kill_switch_still_authoritative": True,
                },
            },
        )
        session.add(discovery_task)
        session.flush()

        stored = store_protected_outputs_in_run_credential_vault(
            session,
            task=discovery_task,
            protected_outputs=[
                ProtectedSecretMaterial(
                    artifact_name="session-security-protected-output.json",
                    purpose="run.ephemeral_credential_vault.session",
                    secret_kind="session",
                    value=PLAINTEXT_SESSION,
                    display_label="Discovered local-lab session",
                    metadata={"target": TARGET_URL, "username": "lab-user"},
                )
            ],
            settings=get_settings(),
        )
        assert len(stored) == 1

        follow_up_task = Task(
            run=run,
            tool="nuclei",
            target_id=TARGET_URL,
            status="queued",
            params_json={
                "target_kind": "url",
                "profile_name": "autonomous-web",
                "run_class": "active",
                "limits": {"tools": ["nuclei"]},
                "assessment_loop": {
                    "enabled": True,
                    "run_mode": "ai_loop",
                    "iteration": 3,
                    "approval_effect": "queued_after_operator_review",
                    "scope_enforced": True,
                    "kill_switch_still_authoritative": True,
                },
            },
        )
        session.add(follow_up_task)
        session.flush()

        from api.app.services.run_credential_vault import inject_run_credential_vault_into_task

        assert inject_run_credential_vault_into_task(
            session,
            run=run,
            task=follow_up_task,
            actor="vault-chain-test",
        )
        session.flush()

        secret_ref = session.scalar(select(SecretRef).where(SecretRef.id == stored[0].id))
        assert secret_ref is not None
        assert secret_ref.encrypted_value
        assert PLAINTEXT_SESSION not in secret_ref.encrypted_value
        assert PLAINTEXT_SESSION not in json.dumps(secret_ref.metadata_json or {})
        assert PLAINTEXT_SESSION not in json.dumps(run_credential_vault_payload(session, run=run))
        assert PLAINTEXT_SESSION not in json.dumps(follow_up_task.params_json)

        runner_params = _runner_params_for_task(session, follow_up_task)
        assert runner_params["auth_contexts"][0]["headers"]["Cookie"] == PLAINTEXT_SESSION
        assert runner_params["credential_vault"]["raw_secret_material_exposed"] is False

        redacted_audit_blob = json.dumps(
            {
                "vault_payload": run_credential_vault_payload(session, run=run),
                "stored_task_params": follow_up_task.params_json,
                "secret_ref_metadata": secret_ref.metadata_json,
                "audit_events": [
                    event.metadata_json
                    for event in session.scalars(
                        select(AuditEvent).where(AuditEvent.object_id.in_([str(secret_ref.id), str(follow_up_task.id)]))
                    ).all()
                ],
            },
            sort_keys=True,
        )
        assert PLAINTEXT_SESSION not in redacted_audit_blob
        assert str(secret_ref.id) in redacted_audit_blob
        assert follow_up_task.params_json["credential_vault"]["raw_secret_material_exposed"] is False
        assert follow_up_task.params_json["credential_vault"]["approval_gates_bypassed"] is False
        assert follow_up_task.params_json["credential_vault"]["runner_registry_bypassed"] is False


def _create_engagement_and_scope(client) -> str:
    response = client.post(
        "/api/v1/engagements",
        headers={"X-Actor": "vault-chain-test"},
        json={
            "name": "Vault Chaining Proof",
            "client": "AegisPT Local Lab",
            "roe_ref": "ROE-VAULT-CHAIN-LOCAL",
        },
    )
    assert response.status_code == 201
    engagement_id = response.json()["id"]
    scope_response = client.post(
        f"/api/v1/engagements/{engagement_id}/scope",
        headers={"X-Actor": "vault-chain-test"},
        json={"allowlist_json": {"urls": [TARGET_URL]}, "denylist_json": {}},
    )
    assert scope_response.status_code == 201
    return engagement_id


def _create_ai_loop_run(client, engagement_id: str) -> str:
    client.get("/api/v1/run-profiles")
    with client.app.state.session_factory() as session:
        profile = session.scalar(select(RunProfile).where(RunProfile.name == "autonomous-web"))
        assert profile is not None
        run = Run(
            engagement_id=UUID(engagement_id),
            profile_id=profile.id,
            requested_by="vault-chain-test",
            status="requested",
            autonomous_mode=True,
            autonomous_intrusive_allowed=False,
            configuration_json={
                "run_mode": "ai_loop",
                "targets": {"urls": [TARGET_URL]},
            },
        )
        session.add(run)
        session.commit()
        return str(run.id)
