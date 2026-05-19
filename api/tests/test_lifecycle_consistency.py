from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID

from sqlalchemy import select

from api.app.models import Finding, InventorySnapshot, Run, Task, ToolExecution


def _headers(tenant_id: str = "tenant-lifecycle") -> dict[str, str]:
    return {"X-Tenant-ID": tenant_id, "X-Actor": "lifecycle-operator"}


def _create_engagement(client, *, name: str = "Lifecycle Consistency") -> str:
    response = client.post(
        "/api/v1/engagements",
        headers=_headers(),
        json={"name": name, "client": "Lifecycle Client", "roe_ref": "ROE-LIFE-1"},
    )
    assert response.status_code == 201
    engagement_id = response.json()["id"]
    scope_response = client.post(
        f"/api/v1/engagements/{engagement_id}/scope",
        headers=_headers(),
        json={"allowlist_json": {"urls": ["https://life.example.test"]}, "denylist_json": {}},
    )
    assert scope_response.status_code == 201
    return engagement_id


def _create_run(client, engagement_id: str) -> str:
    response = client.post(
        f"/api/v1/engagements/{engagement_id}/runs",
        headers=_headers(),
        json={
            "profile_name": "passive-web-baseline",
            "configuration_json": {
                "assessment_type": "Website / Web App",
                "targets": {"urls": ["https://life.example.test"]},
            },
        },
    )
    assert response.status_code == 201
    return response.json()["id"]


def _complete_run_with_lifecycle_data(session, *, engagement_id: str, run_id: str) -> None:
    run = session.scalar(select(Run).where(Run.id == UUID(run_id)))
    assert run is not None
    run.status = "completed"
    run.updated_at = datetime.now(tz=UTC)
    inventory = InventorySnapshot(
        engagement_id=UUID(engagement_id),
        requested_by="lifecycle-operator",
        status="completed",
        source_tools_json=["httpx"],
        normalized_inventory_json={
            "hosts": [{"host": "life.example.test"}],
            "services": [{"host": "life.example.test", "port": 443, "service": "https"}],
            "http_endpoints": [{"url": "https://life.example.test/login"}],
        },
        summary_json={"host_count": 1, "service_count": 1, "endpoint_count": 1},
        confidence_score=0.9,
    )
    session.add(inventory)
    session.flush()
    run.source_inventory_snapshot_id = inventory.id
    task = session.scalars(select(Task).where(Task.run_id == UUID(run_id))).first()
    assert task is not None
    task.status = "completed"
    task.tool = "httpx"
    execution = ToolExecution(
        task_id=task.id,
        runner_digest="sha256:lifecycle",
        tool_version="httpx test",
        exit_code=0,
        stdout_text="https://life.example.test/login [200]",
    )
    session.add(execution)
    session.add_all(
        [
            Finding(
                run_id=UUID(run_id),
                title="Critical exposed admin panel",
                severity="critical",
                target_id="https://life.example.test/admin",
                evidence_ref="artifact://life/admin",
                status="open",
                summary="Administrative endpoint is exposed.",
                methodology_tags=["OWASP-WSTG"],
            ),
            Finding(
                run_id=UUID(run_id),
                title="Resolved stale TLS protocol",
                severity="high",
                target_id="https://life.example.test",
                evidence_ref="artifact://life/tls",
                status="resolved",
                summary="Legacy TLS protocol was remediated.",
                methodology_tags=["OWASP-WSTG"],
            ),
            Finding(
                run_id=UUID(run_id),
                title="False positive banner check",
                severity="medium",
                target_id="https://life.example.test",
                evidence_ref="artifact://life/banner",
                status="false_positive",
                summary="Banner evidence was reviewed and marked false positive.",
                methodology_tags=["OWASP-WSTG"],
            ),
        ]
    )
    session.commit()


def test_post_run_lifecycle_counts_are_consistent_across_api_surfaces(client) -> None:
    engagement_id = _create_engagement(client)
    run_id = _create_run(client, engagement_id)
    with client.app.state.session_factory() as session:
        _complete_run_with_lifecycle_data(session, engagement_id=engagement_id, run_id=run_id)

    run_response = client.get(f"/api/v1/runs/{run_id}", headers=_headers())
    findings_response = client.get(f"/api/v1/runs/{run_id}/findings", headers=_headers())
    problems_response = client.get(
        f"/api/v1/problems?engagement_id={engagement_id}",
        headers=_headers(),
    )
    reports_response = client.get(f"/api/v1/runs/{run_id}/reports", headers=_headers())
    history_response = client.get(f"/api/v1/engagements/{engagement_id}/runs", headers=_headers())
    dashboard_response = client.get(
        f"/api/v1/dashboard?engagement_id={engagement_id}",
        headers=_headers(),
    )

    assert run_response.status_code == 200
    assert findings_response.status_code == 200
    assert problems_response.status_code == 200
    assert reports_response.status_code == 200
    assert history_response.status_code == 200
    assert dashboard_response.status_code == 200

    run_payload = run_response.json()
    findings = findings_response.json()
    problems = problems_response.json()
    reports = reports_response.json()
    history = history_response.json()
    dashboard = dashboard_response.json()

    assert run_payload["findings"]["finding_count"] == 3
    assert len(findings) == 3
    assert problems["stats"]["total_findings"] == 3
    assert problems["stats"]["total_filtered"] == 1
    assert problems["lifecycle_summary"]["visible_findings"] == 1
    assert problems["lifecycle_summary"]["total_findings"] == 3
    assert all(report["included_findings"]["count"] == 3 for report in reports)
    assert all(report["availability_status"] == "export_ready" for report in reports)
    assert all(report["export_allowed"] is True for report in reports)
    assert all(report["lifecycle_summary"]["finding_count"] == 3 for report in reports)
    assert history[0]["id"] == run_id
    assert history[0]["findings"]["finding_count"] == 3
    assert dashboard["open_problems"]["total"] == 1
    assert dashboard["open_problems"]["critical"] == 1


def test_report_catalog_lifecycle_states_are_explicit(client) -> None:
    engagement_id = _create_engagement(client, name="Report Lifecycle")
    queued_run_id = _create_run(client, engagement_id)
    zero_run_id = _create_run(client, engagement_id)
    failed_run_id = _create_run(client, engagement_id)
    gap_run_id = _create_run(client, engagement_id)

    with client.app.state.session_factory() as session:
        zero_run = session.scalar(select(Run).where(Run.id == UUID(zero_run_id)))
        failed_run = session.scalar(select(Run).where(Run.id == UUID(failed_run_id)))
        gap_run = session.scalar(select(Run).where(Run.id == UUID(gap_run_id)))
        assert zero_run is not None
        assert failed_run is not None
        assert gap_run is not None
        zero_run.status = "completed"
        failed_run.status = "failed"
        gap_run.status = "completed_with_errors"
        for run_id, status, exit_code in (
            (zero_run_id, "completed", 0),
            (failed_run_id, "failed", 1),
            (gap_run_id, "failed", 1),
        ):
            task = session.scalars(select(Task).where(Task.run_id == UUID(run_id))).first()
            assert task is not None
            task.status = status
            execution = ToolExecution(
                task_id=task.id,
                runner_digest=f"sha256:{run_id}",
                tool_version="lifecycle test",
                exit_code=exit_code,
                stdout_text="stored lifecycle output",
            )
            session.add(execution)
        session.commit()

    queued_catalog = client.get(f"/api/v1/runs/{queued_run_id}/reports", headers=_headers()).json()
    zero_catalog = client.get(f"/api/v1/runs/{zero_run_id}/reports", headers=_headers()).json()
    failed_catalog = client.get(f"/api/v1/runs/{failed_run_id}/reports", headers=_headers()).json()
    gap_catalog = client.get(f"/api/v1/runs/{gap_run_id}/reports", headers=_headers()).json()

    assert {item["availability_status"] for item in queued_catalog} == {"unavailable"}
    assert {item["preview_allowed"] for item in queued_catalog} == {False}
    assert {item["export_allowed"] for item in queued_catalog} == {False}
    assert {item["lifecycle_summary"]["lifecycle_state"] for item in queued_catalog} == {"in_progress"}

    assert {item["availability_status"] for item in zero_catalog} == {"export_ready"}
    assert {item["lifecycle_summary"]["lifecycle_state"] for item in zero_catalog} == {"completed_zero_findings"}
    assert {item["included_findings"]["count"] for item in zero_catalog} == {0}

    assert {item["availability_status"] for item in failed_catalog} == {"draft_only"}
    assert {item["export_allowed"] for item in failed_catalog} == {False}
    assert {item["lifecycle_summary"]["lifecycle_state"] for item in failed_catalog} == {"completed_with_gaps"}

    assert {item["availability_status"] for item in gap_catalog} == {"draft_only"}
    assert {item["draft_allowed"] for item in gap_catalog} == {True}
    assert {item["lifecycle_summary"]["lifecycle_state"] for item in gap_catalog} == {"completed_with_gaps"}
