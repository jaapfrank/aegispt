from __future__ import annotations

from uuid import UUID

from api.app.models import EvidenceArtifact, Finding, Task, ToolExecution


def _tenant_headers(tenant_id: str, actor: str = "tenant-operator") -> dict[str, str]:
    return {"X-Actor": actor, "X-Tenant-ID": tenant_id}


def _create_tenant_engagement(client, tenant_id: str, name: str) -> str:
    response = client.post(
        "/api/v1/engagements",
        headers=_tenant_headers(tenant_id),
        json={"name": name, "client": f"{tenant_id} Client", "roe_ref": f"ROE-{tenant_id}"},
    )
    assert response.status_code == 201
    payload = response.json()
    assert payload["tenant_id"] == tenant_id
    return payload["id"]


def _create_scope(client, tenant_id: str, engagement_id: str) -> None:
    response = client.post(
        f"/api/v1/engagements/{engagement_id}/scope",
        headers=_tenant_headers(tenant_id),
        json={
            "allowlist_json": {"urls": ["https://tenant-a.example.test"]},
            "denylist_json": {"domains": ["out-of-scope.example.test"]},
        },
    )
    assert response.status_code == 201


def _create_run(client, tenant_id: str, engagement_id: str) -> str:
    response = client.post(
        f"/api/v1/engagements/{engagement_id}/runs",
        headers=_tenant_headers(tenant_id),
        json={
            "profile_name": "passive-web-baseline",
            "configuration_json": {
                "assessment_type": "Website / Web App",
                "targets": {"urls": ["https://tenant-a.example.test"]},
            },
        },
    )
    assert response.status_code == 201
    return response.json()["id"]


def test_tenant_header_scopes_engagements_and_preserves_unscoped_local_view(client) -> None:
    tenant_a_engagement_id = _create_tenant_engagement(client, "tenant-a", "Tenant A Engagement")
    tenant_b_engagement_id = _create_tenant_engagement(client, "tenant-b", "Tenant B Engagement")

    tenant_a_list = client.get("/api/v1/engagements", headers=_tenant_headers("tenant-a"))
    assert tenant_a_list.status_code == 200
    assert [item["id"] for item in tenant_a_list.json()] == [tenant_a_engagement_id]

    tenant_b_list = client.get("/api/v1/engagements", headers=_tenant_headers("tenant-b"))
    assert tenant_b_list.status_code == 200
    assert [item["id"] for item in tenant_b_list.json()] == [tenant_b_engagement_id]

    unscoped_list = client.get("/api/v1/engagements")
    assert unscoped_list.status_code == 200
    assert {item["id"] for item in unscoped_list.json()} == {tenant_a_engagement_id, tenant_b_engagement_id}

    denied = client.get(f"/api/v1/engagements/{tenant_a_engagement_id}", headers=_tenant_headers("tenant-b"))
    assert denied.status_code == 404

    mismatch = client.post(
        "/api/v1/engagements",
        headers=_tenant_headers("tenant-a"),
        json={"name": "Mismatch", "client": "Acme", "tenant_id": "tenant-b"},
    )
    assert mismatch.status_code == 409

    invalid = client.get("/api/v1/engagements", headers=_tenant_headers("bad tenant id"))
    assert invalid.status_code == 400


def test_tenant_header_blocks_cross_tenant_run_finding_inventory_task_and_artifact_access(client) -> None:
    tenant_a_engagement_id = _create_tenant_engagement(client, "tenant-a", "Tenant A Engagement")
    tenant_b_engagement_id = _create_tenant_engagement(client, "tenant-b", "Tenant B Engagement")
    _create_scope(client, "tenant-a", tenant_a_engagement_id)
    run_id = _create_run(client, "tenant-a", tenant_a_engagement_id)

    inventory_response = client.post(
        "/api/v1/inventory/runs",
        headers=_tenant_headers("tenant-a"),
        json={
            "engagement_id": tenant_a_engagement_id,
            "source_tools": ["wizard-input"],
            "observations": [
                {
                    "tool": "tenant-test",
                    "kind": "inventory",
                    "data": {"hosts": [{"host": "10.0.0.5", "source": "tenant-test"}]},
                }
            ],
        },
    )
    assert inventory_response.status_code == 201
    inventory_id = inventory_response.json()["id"]

    with client.app.state.session_factory() as session:
        finding = Finding(
            run_id=UUID(run_id),
            title="Tenant scoped finding",
            severity="medium",
            target_id="https://tenant-a.example.test",
            evidence_ref="artifact://tenant-a/evidence",
            status="open",
            summary="Stored finding for tenant isolation coverage.",
            methodology_tags=["WSTG-CONF"],
        )
        task = Task(
            run_id=UUID(run_id),
            tool="tenant-test",
            target_id="https://tenant-a.example.test",
            params_json={},
            status="completed",
        )
        session.add_all([finding, task])
        session.flush()
        execution = ToolExecution(
            task_id=task.id,
            runner_digest="tenant-test",
            tool_version="1.0",
            exit_code=0,
            stdout_text="tenant test",
            stderr_text="",
        )
        session.add(execution)
        session.flush()
        artifact = EvidenceArtifact(
            tool_execution_id=execution.id,
            kind="stdout",
            uri="inline://missing-tenant-test",
            sha256="0" * 64,
            redaction_state="redacted",
            metadata_json={"name": "tenant-test.txt"},
        )
        session.add(artifact)
        session.commit()
        finding_id = str(finding.id)
        task_id = str(task.id)
        artifact_id = str(artifact.id)

    assert client.get(f"/api/v1/runs/{run_id}", headers=_tenant_headers("tenant-a")).status_code == 200
    assert client.get(f"/api/v1/engagements/{tenant_a_engagement_id}/runs", headers=_tenant_headers("tenant-a")).status_code == 200
    assert client.get(f"/api/v1/runs/{run_id}/reports", headers=_tenant_headers("tenant-a")).status_code == 200
    assert client.get(f"/api/v1/runs/{run_id}/findings", headers=_tenant_headers("tenant-a")).status_code == 200
    assert client.get(f"/api/v1/findings/{finding_id}", headers=_tenant_headers("tenant-a")).status_code == 200
    assert client.get(f"/api/v1/inventory/{inventory_id}", headers=_tenant_headers("tenant-a")).status_code == 200
    assert client.get(f"/api/v1/tasks/{task_id}", headers=_tenant_headers("tenant-a")).status_code == 200

    assert client.get(f"/api/v1/engagements/{tenant_a_engagement_id}/runs", headers=_tenant_headers("tenant-b")).status_code == 404
    assert client.get(f"/api/v1/runs/{run_id}", headers=_tenant_headers("tenant-b")).status_code == 404
    assert client.get(f"/api/v1/runs/{run_id}/reports", headers=_tenant_headers("tenant-b")).status_code == 404
    assert client.get(f"/api/v1/runs/{run_id}/findings", headers=_tenant_headers("tenant-b")).status_code == 404
    assert client.get(f"/api/v1/findings/{finding_id}", headers=_tenant_headers("tenant-b")).status_code == 404
    assert client.get(f"/api/v1/inventory/{inventory_id}", headers=_tenant_headers("tenant-b")).status_code == 404
    assert client.get(f"/api/v1/tasks/{task_id}", headers=_tenant_headers("tenant-b")).status_code == 404
    assert client.get(f"/api/v1/artifacts/{artifact_id}/content", headers=_tenant_headers("tenant-b")).status_code == 404

    cross_tenant_scope = client.post(
        f"/api/v1/engagements/{tenant_a_engagement_id}/scope",
        headers=_tenant_headers("tenant-b"),
        json={"allowlist_json": {"urls": ["https://tenant-b.example.test"]}},
    )
    assert cross_tenant_scope.status_code == 404

    cross_tenant_inventory = client.post(
        "/api/v1/inventory/runs",
        headers=_tenant_headers("tenant-b"),
        json={
            "engagement_id": tenant_a_engagement_id,
            "source_tools": ["wizard-input"],
            "observations": [],
        },
    )
    assert cross_tenant_inventory.status_code == 404

    tenant_b_runs = client.get(f"/api/v1/engagements/{tenant_b_engagement_id}/runs", headers=_tenant_headers("tenant-b"))
    assert tenant_b_runs.status_code == 200
    assert tenant_b_runs.json() == []
