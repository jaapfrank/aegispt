from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import UUID

from sqlalchemy import select

from api.app.models import AuditEvent, Engagement, ExposureScore, Finding, Run, Task
from api.app.services.exposure_score import record_exposure_score


def _tenant_headers(tenant_id: str, actor: str = "dashboard-operator") -> dict[str, str]:
    return {"X-Tenant-ID": tenant_id, "X-Actor": actor}


def _create_engagement(client, *, tenant_id: str, name: str) -> str:
    response = client.post(
        "/api/v1/engagements",
        headers=_tenant_headers(tenant_id),
        json={"name": name, "client": f"{tenant_id} Client", "roe_ref": f"ROE-{tenant_id}"},
    )
    assert response.status_code == 201
    engagement_id = response.json()["id"]
    scope_response = client.post(
        f"/api/v1/engagements/{engagement_id}/scope",
        headers=_tenant_headers(tenant_id),
        json={
            "allowlist_json": {"urls": [f"https://{tenant_id}.example.test"]},
            "denylist_json": {},
        },
    )
    assert scope_response.status_code == 201
    return engagement_id


def _create_run(client, *, tenant_id: str, engagement_id: str) -> str:
    response = client.post(
        f"/api/v1/engagements/{engagement_id}/runs",
        headers=_tenant_headers(tenant_id),
        json={
            "profile_name": "passive-web-baseline",
            "configuration_json": {
                "assessment_type": "Website / Web App",
                "targets": {"urls": [f"https://{tenant_id}.example.test"]},
            },
        },
    )
    assert response.status_code == 201
    return response.json()["id"]


def test_dashboard_empty_state_is_read_only_and_actionable(client) -> None:
    response = client.get("/api/v1/dashboard")

    assert response.status_code == 200
    payload = response.json()
    assert payload["has_engagements"] is False
    assert payload["active_run"] is None
    assert payload["risk_score"]["score"] == 0
    assert "advisory only" in payload["risk_score"]["advisory_note"].lower()
    assert payload["open_problems"] == {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "total": 0,
        "overdue_critical_count": 0,
        "overdue_high_count": 0,
    }
    assert payload["upcoming_scans"] == []
    assert payload["engagements"] == []
    assert payload["setup_checklist"] == []
    assert payload["setup_checklist_dismissed"] is False
    assert payload["first_run_onboarding"]["show"] is True
    assert {item["id"] for item in payload["first_run_onboarding"]["cards"]} == {
        "chatgpt-oauth",
        "create-engagement",
        "run-first-scan",
    }
    new_mission = next(action for action in payload["quick_actions"] if action["id"] == "new-mission")
    assert new_mission["enabled"] is True


def test_dashboard_aggregates_tenant_scoped_live_work_without_writes(client) -> None:
    tenant_a = "tenant-a"
    tenant_b = "tenant-b"
    now = datetime.now(tz=UTC)
    engagement_a = _create_engagement(client, tenant_id=tenant_a, name="Tenant A Dashboard")
    engagement_b = _create_engagement(client, tenant_id=tenant_b, name="Tenant B Dashboard")
    run_a = _create_run(client, tenant_id=tenant_a, engagement_id=engagement_a)
    run_b = _create_run(client, tenant_id=tenant_b, engagement_id=engagement_b)

    settings_response = client.patch(
        "/api/v1/settings",
        headers=_tenant_headers(tenant_a),
        json={
            "settings": {
                "ai.provider": "chatgpt_oauth",
                "network.default_lan_cidr": "10.10.0.0/16",
            }
        },
    )
    assert settings_response.status_code == 200

    schedule_response = client.post(
        f"/api/v1/engagements/{engagement_a}/schedules",
        headers=_tenant_headers(tenant_a),
        json={
            "profile_name": "passive-web-baseline",
            "cadence": "daily",
            "timezone": "UTC",
            "starts_at": (now + timedelta(hours=3)).isoformat(),
            "configuration_json": {"targets": {"urls": ["https://tenant-a.example.test"]}},
        },
    )
    assert schedule_response.status_code == 201

    with client.app.state.session_factory() as session:
        run = session.scalar(select(Run).where(Run.id == UUID(run_a)))
        assert run is not None
        run.status = "running"
        run.updated_at = now + timedelta(minutes=1)
        tasks = session.scalars(select(Task).where(Task.run_id == UUID(run_a))).all()
        assert tasks
        tasks[0].status = "running"
        if len(tasks) > 1:
            tasks[1].status = "completed"
        session.add_all(
            [
                AuditEvent(
                    actor="dashboard-operator",
                    action="run.dispatched",
                    object_type="run",
                    object_id=run_a,
                    metadata_json={"engagement_id": engagement_a, "profile_name": "passive-web-baseline"},
                    created_at=now + timedelta(minutes=2),
                    updated_at=now + timedelta(minutes=2),
                ),
                Finding(
                    run_id=UUID(run_a),
                    title="Admin panel exposed",
                    severity="critical",
                    target_id="https://tenant-a.example.test/admin",
                    evidence_ref="artifact://tenant-a/critical",
                    status="open",
                    created_at=now - timedelta(minutes=20),
                    updated_at=now - timedelta(minutes=20),
                ),
                Finding(
                    run_id=UUID(run_a),
                    title="Weak TLS policy",
                    severity="medium",
                    target_id="https://tenant-a.example.test",
                    evidence_ref="artifact://tenant-a/medium",
                    status="open",
                    created_at=now - timedelta(minutes=18),
                    updated_at=now - timedelta(minutes=18),
                ),
                Finding(
                    run_id=UUID(run_a),
                    title="Accepted legacy redirect",
                    severity="high",
                    target_id="https://tenant-a.example.test/redirect",
                    evidence_ref="artifact://tenant-a/accepted",
                    status="accepted_risk",
                    created_at=now - timedelta(minutes=17),
                    updated_at=now - timedelta(minutes=17),
                ),
                Finding(
                    run_id=UUID(run_b),
                    title="Cross tenant critical",
                    severity="critical",
                    target_id="https://tenant-b.example.test/admin",
                    evidence_ref="artifact://tenant-b/critical",
                    status="open",
                    created_at=now - timedelta(minutes=16),
                    updated_at=now - timedelta(minutes=16),
                ),
            ]
        )
        session.flush()
        record_exposure_score(
            session=session,
            engagement_id=UUID(engagement_a),
            run_id=UUID(run_a),
            computed_at=now - timedelta(minutes=10),
        )
        session.commit()

    before_count_response = client.get(
        f"/api/v1/engagements/{engagement_a}/exposure-score",
        headers=_tenant_headers(tenant_a),
    )
    assert before_count_response.status_code == 200
    before_history_len = len(before_count_response.json()["history"])

    response = client.get("/api/v1/dashboard", headers=_tenant_headers(tenant_a))

    assert response.status_code == 200
    payload = response.json()
    assert payload["has_engagements"] is True
    assert payload["active_run"]["id"] == run_a
    assert payload["active_run"]["engagement_id"] == engagement_a
    assert payload["active_run"]["status"] == "running"
    assert payload["active_run"]["tasks_total"] >= 1
    assert payload["open_problems"] == {
        "critical": 1,
        "high": 0,
        "medium": 1,
        "total": 2,
        "overdue_critical_count": 0,
        "overdue_high_count": 0,
    }
    assert payload["risk_score"]["severity_breakdown"]["critical"] == 1
    assert payload["risk_score"]["severity_breakdown"]["medium"] == 1
    assert payload["risk_score"]["score"] > 0
    assert [item["engagement_id"] for item in payload["upcoming_scans"]] == [engagement_a]
    assert payload["recent_activity"]
    assert payload["activity_feed"]
    assert payload["activity_feed"][0]["label"] == "Run started"
    assert payload["activity_feed"][0]["icon"] == "play"
    assert "run.dispatched" not in payload["activity_feed"][0]["label"]
    assert payload["engagements"][0]["id"] == engagement_a
    assert payload["engagements"][0]["open_critical_count"] == 1
    assert payload["engagements"][0]["run_count"] == 1
    checklist = {item["id"]: item for item in payload["setup_checklist"]}
    assert set(checklist) == {"ai-provider", "first-mission", "first-run", "problem-review"}
    assert checklist["ai-provider"]["done"] is True
    assert checklist["first-run"]["done"] is False
    assert checklist["problem-review"]["done"] is False
    assert payload["first_run_onboarding"] is None
    assert any(action["id"] == "mission-control" and action["enabled"] for action in payload["quick_actions"])

    after_count_response = client.get(
        f"/api/v1/engagements/{engagement_a}/exposure-score",
        headers=_tenant_headers(tenant_a),
    )
    assert after_count_response.status_code == 200
    assert len(after_count_response.json()["history"]) == before_history_len


def test_dashboard_hides_soft_deleted_engagements(client) -> None:
    engagement_id = _create_engagement(client, tenant_id="tenant-a", name="Deleted Dashboard")
    run_id = _create_run(client, tenant_id="tenant-a", engagement_id=engagement_id)

    with client.app.state.session_factory() as session:
        engagement = session.scalar(select(Engagement).where(Engagement.id == UUID(engagement_id)))
        run = session.scalar(select(Run).where(Run.id == UUID(run_id)))
        assert engagement is not None
        assert run is not None
        engagement.deleted_at = datetime.now(tz=UTC)
        run.status = "running"
        session.add(ExposureScore(engagement_id=engagement.id, run_id=run.id, score=90, computed_at=datetime.now(tz=UTC)))
        session.commit()

    response = client.get("/api/v1/dashboard", headers=_tenant_headers("tenant-a"))

    assert response.status_code == 200
    payload = response.json()
    assert payload["has_engagements"] is False
    assert payload["engagements"] == []
    assert payload["active_run"] is None


def test_dashboard_can_scope_to_one_tenant_engagement(client) -> None:
    tenant_id = "tenant-scope"
    engagement_one = _create_engagement(client, tenant_id=tenant_id, name="Scoped Dashboard One")
    engagement_two = _create_engagement(client, tenant_id=tenant_id, name="Scoped Dashboard Two")
    run_one = _create_run(client, tenant_id=tenant_id, engagement_id=engagement_one)
    run_two = _create_run(client, tenant_id=tenant_id, engagement_id=engagement_two)

    with client.app.state.session_factory() as session:
        session.add_all(
            [
                Finding(
                    run_id=UUID(run_one),
                    title="Scoped critical",
                    severity="critical",
                    target_id="https://one.example.test",
                    evidence_ref="artifact://one/critical",
                    status="open",
                ),
                Finding(
                    run_id=UUID(run_two),
                    title="Other medium",
                    severity="medium",
                    target_id="https://two.example.test",
                    evidence_ref="artifact://two/medium",
                    status="open",
                ),
            ]
        )
        session.commit()

    response = client.get(
        f"/api/v1/dashboard?engagement_id={engagement_one}",
        headers=_tenant_headers(tenant_id),
    )

    assert response.status_code == 200
    payload = response.json()
    assert [item["id"] for item in payload["engagements"]] == [engagement_one]
    assert payload["open_problems"] == {
        "critical": 1,
        "high": 0,
        "medium": 0,
        "total": 1,
        "overdue_critical_count": 0,
        "overdue_high_count": 0,
    }
    assert payload["risk_score"]["severity_breakdown"]["critical"] == 1
    assert payload["risk_score"]["severity_breakdown"]["medium"] == 0


def test_dashboard_setup_checklist_review_finding_uses_completed_engagement_runs(client) -> None:
    tenant_id = "tenant-checklist"
    engagement_id = _create_engagement(client, tenant_id=tenant_id, name="Checklist Mission")
    active_run_id = _create_run(client, tenant_id=tenant_id, engagement_id=engagement_id)
    completed_run_id = _create_run(client, tenant_id=tenant_id, engagement_id=engagement_id)

    settings_response = client.patch(
        "/api/v1/settings",
        headers=_tenant_headers(tenant_id),
        json={"settings": {"ai.provider": "chatgpt_oauth"}},
    )
    assert settings_response.status_code == 200

    with client.app.state.session_factory() as session:
        active_run = session.scalar(select(Run).where(Run.id == UUID(active_run_id)))
        completed_run = session.scalar(select(Run).where(Run.id == UUID(completed_run_id)))
        assert active_run is not None
        assert completed_run is not None
        active_run.status = "running"
        completed_run.status = "completed"
        session.add(
            Finding(
                run_id=UUID(completed_run_id),
                title="Completed run finding",
                severity="high",
                target_id="https://checklist.example.test",
                evidence_ref="artifact://checklist/finding",
                status="resolved",
            )
        )
        session.commit()

    response = client.get(
        f"/api/v1/dashboard?engagement_id={engagement_id}",
        headers=_tenant_headers(tenant_id),
    )

    assert response.status_code == 200
    checklist = {item["id"]: item for item in response.json()["setup_checklist"]}
    assert checklist["first-mission"]["done"] is True
    assert checklist["first-run"]["done"] is True
    assert checklist["problem-review"]["done"] is True
    assert all(item["done"] for item in checklist.values())


def test_dashboard_setup_checklist_dismissal_persists(client) -> None:
    tenant_id = "tenant-dismiss"
    engagement_id = _create_engagement(client, tenant_id=tenant_id, name="Dismiss Mission")
    _create_run(client, tenant_id=tenant_id, engagement_id=engagement_id)

    before = client.get("/api/v1/dashboard", headers=_tenant_headers(tenant_id))
    assert before.status_code == 200
    assert before.json()["setup_checklist"]

    patch_response = client.patch(
        "/api/v1/settings",
        headers=_tenant_headers(tenant_id),
        json={"settings": {"instance.setup_checklist_dismissed": True}},
    )
    assert patch_response.status_code == 200

    after = client.get("/api/v1/dashboard", headers=_tenant_headers(tenant_id))
    assert after.status_code == 200
    payload = after.json()
    assert payload["setup_checklist_dismissed"] is True
    assert payload["setup_checklist"] == []
    assert payload["first_run_onboarding"] is None


def test_dashboard_first_run_onboarding_hides_after_first_completed_scan(client) -> None:
    tenant_id = "tenant-first-scan"
    empty_response = client.get("/api/v1/dashboard", headers=_tenant_headers(tenant_id))
    assert empty_response.status_code == 200
    assert empty_response.json()["first_run_onboarding"]["show"] is True

    engagement_id = _create_engagement(client, tenant_id=tenant_id, name="First Scan Mission")
    run_id = _create_run(client, tenant_id=tenant_id, engagement_id=engagement_id)
    with client.app.state.session_factory() as session:
        run = session.scalar(select(Run).where(Run.id == UUID(run_id)))
        assert run is not None
        run.status = "completed"
        session.commit()

    completed_response = client.get("/api/v1/dashboard", headers=_tenant_headers(tenant_id))
    assert completed_response.status_code == 200
    payload = completed_response.json()
    assert payload["has_engagements"] is True
    assert payload["first_run_onboarding"] is None
