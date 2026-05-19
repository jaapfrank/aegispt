from __future__ import annotations

from uuid import UUID

from sqlalchemy import select

from api.app.models import Finding, Run, Task


def _create_engagement_with_scope(client) -> str:
    engagement = client.post(
        "/api/v1/engagements",
        headers={"X-Actor": "cicd-ephemeral-admin"},
        json={
            "name": "Ephemeral CI Engagement",
            "client": "Acme Corp",
            "roe_ref": "ROE-CICD-EPHEMERAL",
        },
    )
    assert engagement.status_code == 201
    engagement_id = engagement.json()["id"]
    scope = client.post(
        f"/api/v1/engagements/{engagement_id}/scope",
        headers={"X-Actor": "cicd-ephemeral-admin"},
        json={
            "allowlist_json": {
                "urls": ["https://preview.example.test"],
                "domains": ["preview.example.test"],
            },
            "denylist_json": {},
        },
    )
    assert scope.status_code == 201
    return engagement_id


def test_ephemeral_cicd_scan_launches_lightweight_in_scope_run(client) -> None:
    engagement_id = _create_engagement_with_scope(client)

    response = client.post(
        f"/api/v1/engagements/{engagement_id}/cicd/ephemeral-scans",
        headers={"X-Actor": "github-action"},
        json={
            "target_url": "https://preview.example.test/pr-42",
            "ref": "refs/pull/42/head",
            "commit_sha": "abc123",
            "repository_url": "https://github.com/acme/app",
            "callback_url": "https://ci.example.test/aegispt/callback",
            "metadata_json": {"pull_request": 42},
        },
    )

    assert response.status_code == 202
    payload = response.json()
    assert payload["accepted"] is True
    assert payload["profile_name"] == "passive-web-baseline"
    assert payload["target_url"] == "https://preview.example.test/pr-42"
    assert payload["pass_fail_status"] == "pending"
    assert payload["scope_enforced"] is True
    assert payload["callback_url_configured"] is True
    assert payload["status_url"].endswith(f"/{payload['run_id']}")

    with client.app.state.session_factory() as session:
        run = session.scalar(select(Run).where(Run.id == UUID(payload["run_id"])))
        tasks = session.scalars(select(Task).where(Task.run_id == UUID(payload["run_id"]))).all()

    assert run is not None
    assert run.configuration_json["targets"] == {"urls": ["https://preview.example.test/pr-42"]}
    assert run.configuration_json["cicd_ephemeral"]["sast_enabled"] is False
    assert run.configuration_json["cicd_ephemeral"]["callback_pending"] is True
    assert any(task.tool == "httpx" for task in tasks)


def test_ephemeral_cicd_scan_rejects_target_outside_scope_without_run(client) -> None:
    engagement_id = _create_engagement_with_scope(client)

    response = client.post(
        f"/api/v1/engagements/{engagement_id}/cicd/ephemeral-scans",
        headers={"X-Actor": "github-action"},
        json={
            "target_url": "https://evil.example.test/pr-42",
            "ref": "refs/pull/42/head",
            "commit_sha": "abc123",
        },
    )

    assert response.status_code == 403
    assert "outside the approved engagement scope" in response.json()["detail"]

    with client.app.state.session_factory() as session:
        runs = session.scalars(select(Run).where(Run.engagement_id == UUID(engagement_id))).all()
    assert runs == []


def test_ephemeral_cicd_status_reports_fail_then_pass_from_stored_findings(client) -> None:
    engagement_id = _create_engagement_with_scope(client)
    response = client.post(
        f"/api/v1/engagements/{engagement_id}/cicd/ephemeral-scans",
        headers={"X-Actor": "github-action"},
        json={
            "target_url": "https://preview.example.test/pr-99",
            "ref": "refs/pull/99/head",
            "commit_sha": "def456",
        },
    )
    assert response.status_code == 202
    run_id = response.json()["run_id"]

    with client.app.state.session_factory() as session:
        run = session.scalar(select(Run).where(Run.id == UUID(run_id)))
        assert run is not None
        run.status = "completed"
        session.add(
            Finding(
                run_id=run.id,
                title="Preview admin exposure",
                severity="high",
                target_id="https://preview.example.test/pr-99/admin",
                evidence_ref="artifact://cicd-preview/admin",
                status="open",
            )
        )
        session.commit()

    failed = client.get(f"/api/v1/cicd/ephemeral-scans/{run_id}")
    assert failed.status_code == 200
    assert failed.json()["pass_fail_status"] == "fail"

    with client.app.state.session_factory() as session:
        finding = session.scalar(select(Finding).where(Finding.run_id == UUID(run_id)))
        assert finding is not None
        finding.status = "resolved"
        session.commit()

    passed = client.get(f"/api/v1/cicd/ephemeral-scans/{run_id}")
    assert passed.status_code == 200
    assert passed.json()["pass_fail_status"] == "pass"
