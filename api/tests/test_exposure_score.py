from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import UUID

from sqlalchemy import select

from api.app.models import ExposureScore, Finding, FindingRemediation, Run
from api.app.services.exposure_score import record_exposure_score
from workers.runners.base.contracts import RunnerExecution


def _create_engagement_with_scope(client) -> str:
    engagement = client.post(
        "/api/v1/engagements",
        headers={"X-Actor": "score-operator"},
        json={"name": "Exposure Engagement", "client": "Acme", "roe_ref": "ROE-EXPOSURE-1"},
    ).json()
    scope_response = client.post(
        f"/api/v1/engagements/{engagement['id']}/scope",
        headers={"X-Actor": "score-operator"},
        json={"allowlist_json": {"urls": ["https://app.example.test"]}, "denylist_json": {}},
    )
    assert scope_response.status_code == 201
    return engagement["id"]


def _create_run(client, engagement_id: str, *, profile_name: str = "passive-web-baseline") -> str:
    response = client.post(
        f"/api/v1/engagements/{engagement_id}/runs",
        headers={"X-Actor": "score-operator"},
        json={
            "profile_name": profile_name,
            "configuration_json": {
                "assessment_type": "Website / Web App",
                "test_profile": "Standard",
                "execution_profile": profile_name,
                "targets": {"urls": ["https://app.example.test"]},
                "modules": {"web_crawling": True},
                "safety": {"rate_limit_rps": 1, "concurrency": 1, "time_budget_minutes": 15},
            },
        },
    )
    assert response.status_code == 201
    return response.json()["id"]


def test_exposure_score_endpoint_returns_current_and_last_ten_points(client) -> None:
    engagement_id = _create_engagement_with_scope(client)
    run_id = _create_run(client, engagement_id)
    now = datetime.now(tz=UTC)

    with client.app.state.session_factory() as session:
        session.add_all(
            [
                Finding(
                    run_id=UUID(run_id),
                    title="Admin panel exposed",
                    severity="critical",
                    target_id="https://app.example.test/admin",
                    evidence_ref="artifact://critical",
                    status="open",
                    created_at=now - timedelta(hours=1),
                    updated_at=now - timedelta(hours=1),
                ),
                Finding(
                    run_id=UUID(run_id),
                    title="Stored XSS",
                    severity="high",
                    target_id="https://app.example.test/profile",
                    evidence_ref="artifact://high",
                    status="open",
                    created_at=now - timedelta(minutes=55),
                    updated_at=now - timedelta(minutes=55),
                ),
            ]
        )
        session.commit()

        for index in range(12):
            record_exposure_score(
                session=session,
                engagement_id=UUID(engagement_id),
                run_id=UUID(run_id),
                computed_at=now + timedelta(minutes=index),
            )
        session.commit()

    response = client.get(f"/api/v1/engagements/{engagement_id}/exposure-score")
    assert response.status_code == 200
    payload = response.json()
    assert payload["engagement_id"] == engagement_id
    assert len(payload["history"]) == 10
    assert payload["current"]["score"] == payload["history"][-1]["score"]
    assert payload["current"]["open_critical_count"] == 1
    assert payload["current"]["open_high_count"] == 1
    assert "advisory only" in payload["advisory_note"].lower()
    assert payload["history"][0]["computed_at"] < payload["history"][-1]["computed_at"]


def test_finding_status_update_recomputes_exposure_score(client) -> None:
    engagement_id = _create_engagement_with_scope(client)
    run_id = _create_run(client, engagement_id)

    with client.app.state.session_factory() as session:
        finding = Finding(
            run_id=UUID(run_id),
            title="Sensitive admin route",
            severity="high",
            target_id="https://app.example.test/admin",
            evidence_ref="artifact://admin",
            status="open",
            summary="Admin route is reachable without the expected control.",
        )
        session.add(finding)
        session.flush()
        record_exposure_score(session=session, engagement_id=UUID(engagement_id), run_id=UUID(run_id))
        session.commit()
        finding_id = str(finding.id)

    patch_response = client.patch(
        f"/api/v1/findings/{finding_id}",
        headers={"X-Actor": "score-operator"},
        json={"status": "resolved"},
    )
    assert patch_response.status_code == 200

    with client.app.state.session_factory() as session:
        history = session.scalars(
            select(ExposureScore)
            .where(ExposureScore.engagement_id == UUID(engagement_id))
            .order_by(ExposureScore.computed_at.asc(), ExposureScore.id.asc())
        ).all()

    assert len(history) == 2
    assert history[0].score > history[1].score
    assert history[1].trend == "improving"
    assert history[1].remediated_count == 1


def test_verified_remediation_recomputes_exposure_score(client) -> None:
    engagement_id = _create_engagement_with_scope(client)
    run_id = _create_run(client, engagement_id)

    with client.app.state.session_factory() as session:
        finding = Finding(
            run_id=UUID(run_id),
            title="Session cookie missing hardening",
            severity="medium",
            target_id="https://app.example.test/session",
            evidence_ref="artifact://cookie",
            status="open",
        )
        session.add(finding)
        session.flush()
        session.add(
            FindingRemediation(
                finding_id=finding.id,
                state="in_progress",
                notes="Patch is staged.",
                owner="app-team",
                created_by="score-operator",
                updated_by="score-operator",
            )
        )
        session.flush()
        record_exposure_score(session=session, engagement_id=UUID(engagement_id), run_id=UUID(run_id))
        session.commit()
        finding_id = str(finding.id)

    response = client.put(
        f"/api/v1/findings/{finding_id}/remediation",
        headers={"X-Actor": "score-operator"},
        json={"state": "verified", "notes": "Retest proof reviewed.", "owner": "app-team"},
    )
    assert response.status_code == 200

    with client.app.state.session_factory() as session:
        history = session.scalars(
            select(ExposureScore)
            .where(ExposureScore.engagement_id == UUID(engagement_id))
            .order_by(ExposureScore.computed_at.asc(), ExposureScore.id.asc())
        ).all()

    assert len(history) == 2
    assert history[-1].verified_count == 1
    assert history[-1].score < history[0].score
    assert history[-1].trend == "improving"


def test_run_completion_records_exposure_score_history(inline_client, monkeypatch) -> None:
    def fake_dispatch_runner(request):
        return RunnerExecution(
            tool=request.tool,
            exit_code=0,
            stdout="httpx completed successfully",
            stderr="",
            metadata={"runner_digest": "sha256:fake-httpx", "tool_version": "httpx test"},
            artifacts=[],
        )

    monkeypatch.setattr("workers.orchestration.tasks.dispatch_runner", fake_dispatch_runner)

    engagement_id = _create_engagement_with_scope(inline_client)
    run_id = _create_run(inline_client, engagement_id)

    dispatch_response = inline_client.post(
        f"/api/v1/runs/{run_id}/dispatch",
        headers={"X-Actor": "score-operator"},
    )
    assert dispatch_response.status_code == 200

    score_response = inline_client.get(f"/api/v1/engagements/{engagement_id}/exposure-score")
    assert score_response.status_code == 200
    payload = score_response.json()
    assert payload["current"]["run_id"] == run_id
    assert payload["current"]["score"] == 0
    assert len(payload["history"]) >= 1

    with inline_client.app.state.session_factory() as session:
        run = session.scalar(select(Run).where(Run.id == UUID(run_id)))
        assert run is not None
        assert run.status == "completed"
