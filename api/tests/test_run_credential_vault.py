from __future__ import annotations

import json
from uuid import UUID

from sqlalchemy import select

from api.app.config import get_settings
from api.app.models import Run, RunProfile, Task
from api.app.services.run_credential_vault import (
    inject_run_credential_vault_into_task,
    store_run_credential_vault_secret,
)
from workers.orchestration.tasks import _runner_params_for_task


def _create_engagement_and_scope(client) -> str:
    response = client.post(
        "/api/v1/engagements",
        headers={"X-Actor": "vault-tester"},
        json={
            "name": "AI Vault Validation",
            "client": "Acme Corp",
            "roe_ref": "ROE-VAULT-2026",
        },
    )
    assert response.status_code == 201
    engagement_id = response.json()["id"]
    scope_response = client.post(
        f"/api/v1/engagements/{engagement_id}/scope",
        headers={"X-Actor": "vault-tester"},
        json={"allowlist_json": {"urls": ["https://vault.example.test"]}, "denylist_json": {}},
    )
    assert scope_response.status_code == 201
    return engagement_id


def _create_ai_loop_run(client, engagement_id: str) -> str:
    profiles_response = client.get("/api/v1/run-profiles")
    assert profiles_response.status_code == 200
    with client.app.state.session_factory() as session:
        profile = session.scalar(select(RunProfile).where(RunProfile.name == "autonomous-web"))
        assert profile is not None
        run = Run(
            engagement_id=UUID(engagement_id),
            profile_id=profile.id,
            requested_by="vault-tester",
            status="requested",
            autonomous_mode=True,
            autonomous_intrusive_allowed=False,
            configuration_json={
                "run_mode": "ai_loop",
                "targets": {"urls": ["https://vault.example.test"]},
            },
        )
        session.add(run)
        session.commit()
        return str(run.id)


def test_ai_loop_credential_vault_api_stores_redacted_secret_and_clears_on_cancel(client) -> None:
    engagement_id = _create_engagement_and_scope(client)
    run_id = _create_ai_loop_run(client, engagement_id)
    secret_value = "gruyere_session=super-secret-token"

    response = client.post(
        f"/api/v1/runs/{run_id}/credential-vault",
        headers={"X-Actor": "vault-tester"},
        json={
            "secret_kind": "session",
            "value": secret_value,
            "label": "Gruyere admin session",
            "target": "https://vault.example.test",
            "discovery_source": "ai_loop_controlled_proof",
        },
    )

    assert response.status_code == 201
    payload = response.json()
    assert payload["entry_count"] == 1
    assert payload["entries"][0]["secret_kind"] == "session"
    assert payload["entries"][0]["raw_secret_material_exposed"] is False
    assert secret_value not in json.dumps(payload)

    read_response = client.get(
        f"/api/v1/runs/{run_id}/credential-vault",
        headers={"X-Actor": "vault-tester"},
    )
    assert read_response.status_code == 200
    assert read_response.json()["entry_count"] == 1
    assert secret_value not in json.dumps(read_response.json())

    cancel_response = client.post(
        f"/api/v1/runs/{run_id}/cancel",
        headers={"X-Actor": "vault-tester"},
    )
    assert cancel_response.status_code == 200
    assert cancel_response.json()["status"] == "cancelled"

    cleared_response = client.get(
        f"/api/v1/runs/{run_id}/credential-vault",
        headers={"X-Actor": "vault-tester"},
    )
    assert cleared_response.status_code == 200
    assert cleared_response.json()["entry_count"] == 0


def test_vault_injects_secret_binding_into_subsequent_runner_task_without_plaintext(client) -> None:
    engagement_id = _create_engagement_and_scope(client)
    run_id = _create_ai_loop_run(client, engagement_id)
    secret_value = "sessionid=runner-secret"

    with client.app.state.session_factory() as session:
        run = session.get(Run, UUID(run_id))
        assert run is not None
        store_run_credential_vault_secret(
            session,
            run=run,
            settings=get_settings(),
            secret_kind="session",
            value=secret_value,
            label="Authenticated app session",
            target="https://vault.example.test",
            actor="vault-tester",
            discovery_source="ai_loop_controlled_proof",
            source_tool="ai_loop",
        )
        task = Task(
            run=run,
            tool="nuclei",
            target_id="https://vault.example.test",
            status="queued",
            params_json={
                "target_kind": "url",
                "profile_name": "autonomous-web",
                "run_class": "passive",
                "limits": {"tools": ["nuclei"]},
            },
        )
        session.add(task)
        session.flush()

        assert inject_run_credential_vault_into_task(
            session,
            run=run,
            task=task,
            actor="vault-tester",
        )
        assert task.params_json["credential_vault"]["injected"] is True
        assert task.params_json["auth_contexts"][0]["source"] == "run_credential_vault"
        assert secret_value not in json.dumps(task.params_json)

        runner_params = _runner_params_for_task(session, task)
        assert runner_params["auth_contexts"][0]["headers"]["Cookie"] == secret_value
        assert runner_params["credential_vault"]["raw_secret_material_exposed"] is False
