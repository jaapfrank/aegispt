from __future__ import annotations

from uuid import UUID

from sqlalchemy import select

from api.app.models import AuditEvent, EvidenceArtifact, Finding, Run, Task, ToolExecution


def _seed_finding(client) -> str:
    with client.app.state.session_factory() as session:
        finding = Finding(
            title="Missing security header",
            severity="medium",
            target_id="https://example.test",
            evidence_ref="artifact://headers/missing-security-header",
            status="open",
            summary="The target is missing a hardening header.",
        )
        session.add(finding)
        session.commit()
        return str(finding.id)


def _seed_source_run_finding(client) -> tuple[str, str]:
    engagement = client.post(
        "/api/v1/engagements",
        headers={"X-Actor": "source-operator"},
        json={"name": "Retest Engagement", "client": "Acme Corp", "roe_ref": "ROE-RETEST-1"},
    ).json()

    client.post(
        f"/api/v1/engagements/{engagement['id']}/scope",
        headers={"X-Actor": "source-operator"},
        json={"allowlist_json": {"urls": ["https://app.example.test"]}, "denylist_json": {}},
    )

    source_run = client.post(
        f"/api/v1/engagements/{engagement['id']}/runs",
        headers={"X-Actor": "source-operator"},
        json={
            "profile_name": "passive-web-baseline",
            "configuration_json": {
                "assessment_type": "Website / Web App",
                "test_profile": "Standard",
                "execution_profile": "passive-web-baseline",
                "targets": {"urls": ["https://app.example.test"]},
                "modules": {"web_crawling": True},
                "safety": {"rate_limit_rps": 1, "concurrency": 1, "time_budget_minutes": 30},
            },
        },
    ).json()

    with client.app.state.session_factory() as session:
        finding = Finding(
            run_id=UUID(source_run["id"]),
            title="Missing X-Frame-Options Header",
            severity="low",
            target_id="https://app.example.test",
            evidence_ref="artifact://headers/x-frame-options",
            status="open",
            summary="The target did not return X-Frame-Options.",
        )
        session.add(finding)
        session.commit()
        return source_run["id"], str(finding.id)


def test_finding_remediation_state_is_additive_to_finding_status(client) -> None:
    finding_id = _seed_finding(client)

    missing_response = client.get(f"/api/v1/findings/{finding_id}/remediation")
    assert missing_response.status_code == 404
    assert missing_response.json()["detail"] == "remediation not found"

    create_response = client.put(
        f"/api/v1/findings/{finding_id}/remediation",
        headers={"X-Actor": "remediation-owner"},
        json={
            "state": "in-progress",
            "notes": "Patch is staged under CHG-42.",
            "owner": "app-team",
        },
    )

    assert create_response.status_code == 200
    created = create_response.json()
    assert created["finding_id"] == finding_id
    assert created["state"] == "in_progress"
    assert created["notes"] == "Patch is staged under CHG-42."
    assert created["owner"] == "app-team"
    assert created["created_by"] == "remediation-owner"
    assert created["updated_by"] == "remediation-owner"

    finding_response = client.get(f"/api/v1/findings/{finding_id}")
    assert finding_response.status_code == 200
    assert finding_response.json()["status"] == "open"

    update_response = client.put(
        f"/api/v1/findings/{finding_id}/remediation",
        headers={"X-Actor": "retest-coordinator"},
        json={
            "state": "ready_for_retest",
            "notes": "Patch deployed to the approved assessment environment.",
            "owner": "app-team",
        },
    )

    assert update_response.status_code == 200
    updated = update_response.json()
    assert updated["id"] == created["id"]
    assert updated["state"] == "ready_for_retest"
    assert updated["notes"] == "Patch deployed to the approved assessment environment."
    assert updated["created_by"] == "remediation-owner"
    assert updated["updated_by"] == "retest-coordinator"

    read_response = client.get(f"/api/v1/findings/{finding_id}/remediation")
    assert read_response.status_code == 200
    assert read_response.json() == updated

    with client.app.state.session_factory() as session:
        events = session.scalars(
            select(AuditEvent)
            .where(AuditEvent.object_id == finding_id)
            .where(AuditEvent.action == "finding.remediation.updated")
            .order_by(AuditEvent.created_at)
        ).all()

    assert len(events) == 2
    assert events[0].metadata_json["previous_state"] is None
    assert events[0].metadata_json["state"] == "in_progress"
    assert events[1].metadata_json["previous_state"] == "in_progress"
    assert events[1].metadata_json["state"] == "ready_for_retest"


def test_finding_remediation_rejects_finding_status_values(client) -> None:
    finding_id = _seed_finding(client)

    response = client.put(
        f"/api/v1/findings/{finding_id}/remediation",
        headers={"X-Actor": "remediation-owner"},
        json={"state": "resolved", "notes": "Do not reuse finding status values."},
    )

    assert response.status_code == 422


def test_single_finding_retest_request_creates_linked_run_without_changing_finding_status(client) -> None:
    source_run_id, finding_id = _seed_source_run_finding(client)
    remediation_response = client.put(
        f"/api/v1/findings/{finding_id}/remediation",
        headers={"X-Actor": "remediation-owner"},
        json={
            "state": "ready_for_retest",
            "notes": "Patch deployed to the approved test environment.",
            "owner": "app-team",
        },
    )
    assert remediation_response.status_code == 200

    retest_response = client.post(
        f"/api/v1/findings/{finding_id}/retest",
        headers={"X-Actor": "retest-operator"},
        json={"notes": "Retest only the original affected endpoint."},
    )

    assert retest_response.status_code == 201
    retest = retest_response.json()
    assert retest["source_finding_id"] == finding_id
    assert retest["source_run_id"] == source_run_id
    assert retest["status"] == "queued"
    assert retest["profile_name"] == "passive-web-baseline"
    assert len(retest["queued_task_ids"]) == 1

    configuration = retest["configuration_json"]
    assert configuration["test_profile"] == "Single-Finding Retest"
    assert configuration["execution_profile"] == "passive-web-baseline"
    assert configuration["targets"] == {"urls": ["https://app.example.test"]}
    assert configuration["modules"]["single_finding_retest"] is True
    assert configuration["retest"]["mode"] == "single_finding"
    assert configuration["retest"]["source_finding_id"] == finding_id
    assert configuration["retest"]["source_run_id"] == source_run_id
    assert configuration["retest"]["remediation_state"] == "ready_for_retest"
    assert configuration["retest"]["operator_notes"] == "Retest only the original affected endpoint."

    retest_run_response = client.get(f"/api/v1/runs/{retest['retest_run_id']}")
    assert retest_run_response.status_code == 200
    assert retest_run_response.json()["configuration_json"]["retest"]["source_finding_id"] == finding_id
    assert retest_run_response.json()["findings"]["finding_count"] == 0

    theater_response = client.get(f"/api/v1/findings/{finding_id}/theater")
    assert theater_response.status_code == 200
    theater_remediation = theater_response.json()["remediation"]
    assert theater_remediation["record"]["state"] == "ready_for_retest"
    assert theater_remediation["record"]["notes"] == "Patch deployed to the approved test environment."
    assert theater_remediation["linked_retest_count"] == 1
    assert theater_remediation["latest_retest_status"] == "queued"
    assert theater_remediation["linked_retests"][0]["run_id"] == retest["retest_run_id"]
    assert theater_remediation["linked_retests"][0]["source_run_id"] == source_run_id
    assert theater_remediation["linked_retests"][0]["verification_state"] == "requested"
    assert theater_remediation["linked_retests"][0]["operator_notes"] == (
        "Retest only the original affected endpoint."
    )

    finding_response = client.get(f"/api/v1/findings/{finding_id}")
    assert finding_response.status_code == 200
    assert finding_response.json()["status"] == "open"

    with client.app.state.session_factory() as session:
        queued_task = session.scalar(select(Task).where(Task.id == UUID(retest["queued_task_ids"][0])))
        retest_run = session.scalar(select(Run).where(Run.id == UUID(retest["retest_run_id"])))
        events = session.scalars(
            select(AuditEvent)
            .where(AuditEvent.object_id == finding_id)
            .where(AuditEvent.action == "finding.retest_requested")
        ).all()

        assert retest_run is not None
        assert queued_task is not None
        assert queued_task.params_json["retest"]["source_finding_id"] == finding_id
        assert queued_task.params_json["retest"]["source_run_id"] == source_run_id
        assert len(events) == 1
        assert events[0].metadata_json["retest_run_id"] == retest["retest_run_id"]

        retest_run.status = "completed"
        queued_task.status = "completed"
        execution = ToolExecution(
            task_id=queued_task.id,
            runner_digest="sha256:retest-proof",
            tool_version="httpx test",
            exit_code=0,
            stdout_text="X-Frame-Options present",
            stderr_text="",
        )
        session.add(execution)
        session.flush()
        session.add(
            EvidenceArtifact(
                tool_execution_id=execution.id,
                kind="retest-proof",
                uri="artifact://retest/x-frame-options-fixed",
                sha256="a" * 64,
                redaction_state="clean",
                metadata_json={"name": "x-frame-options-fixed-proof"},
            )
        )
        session.commit()

    markdown_response = client.get(f"/api/v1/runs/{retest['retest_run_id']}/report?format=markdown&variant=retest")
    assert markdown_response.status_code == 200
    markdown = markdown_response.text
    assert "## Proof of Resolution" in markdown
    assert "Missing X-Frame-Options Header" in markdown
    assert "Patch deployed to the approved test environment." in markdown
    assert "x-frame-options-fixed-proof" in markdown
    assert "Verification Timestamp:" in markdown
    assert "artifact://retest/x-frame-options-fixed" in markdown

    html_response = client.get(f"/api/v1/runs/{retest['retest_run_id']}/report?format=html&variant=retest")
    assert html_response.status_code == 200
    html = html_response.text
    assert "Proof of Resolution" in html
    assert "x-frame-options-fixed-proof" in html
    assert "Patch deployed to the approved test environment." in html


def test_single_finding_retest_requires_source_run(client) -> None:
    finding_id = _seed_finding(client)

    response = client.post(
        f"/api/v1/findings/{finding_id}/retest",
        headers={"X-Actor": "retest-operator"},
        json={},
    )

    assert response.status_code == 409
    assert response.json()["detail"] == "finding has no source run to retest"
