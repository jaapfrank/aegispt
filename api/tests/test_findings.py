from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import UUID

from sqlalchemy import select

from api.app.models import AuditEvent, Finding, FindingRemediation, Run


def _create_engagement_with_scope(client, *, tenant_id: str | None = None) -> str:
    headers = {"X-Actor": "portfolio-operator"}
    if tenant_id is not None:
        headers["X-Tenant-ID"] = tenant_id
    engagement_response = client.post(
        "/api/v1/engagements",
        headers=headers,
        json={"name": "Portfolio Engagement", "client": "Acme Corp", "roe_ref": "ROE-PORTFOLIO-1"},
    )
    assert engagement_response.status_code == 201
    engagement = engagement_response.json()
    scope_response = client.post(
        f"/api/v1/engagements/{engagement['id']}/scope",
        headers=headers,
        json={"allowlist_json": {"urls": ["https://app.example.test"]}, "denylist_json": {}},
    )
    assert scope_response.status_code == 201
    return engagement["id"]


def _create_run(client, engagement_id: str, profile_name: str = "passive-web-baseline") -> str:
    response = client.post(
        f"/api/v1/engagements/{engagement_id}/runs",
        headers={"X-Actor": "portfolio-operator"},
        json={
            "profile_name": profile_name,
            "configuration_json": {
                "assessment_type": "Website / Web App",
                "test_profile": "Standard",
                "execution_profile": profile_name,
                "targets": {"urls": ["https://app.example.test"]},
                "modules": {"web_crawling": True},
                "safety": {"rate_limit_rps": 1, "concurrency": 1, "time_budget_minutes": 30},
            },
        },
    )
    assert response.status_code == 201
    return response.json()["id"]


def _seed_portfolio_findings(client, engagement_id: str) -> dict[str, str]:
    passive_run_id = _create_run(client, engagement_id)
    active_run_id = _create_run(client, engagement_id, profile_name="active-web-safe")
    now = datetime.now(tz=UTC)
    with client.app.state.session_factory() as session:
        findings = {
            "ready": Finding(
                run_id=UUID(active_run_id),
                title="Admin endpoint fixed and ready",
                severity="high",
                target_id="https://app.example.test/admin",
                evidence_ref="artifact://findings/admin-endpoint",
                status="open",
                summary="The control owner has staged a fix for retest.",
                created_at=now - timedelta(days=10),
                updated_at=now - timedelta(days=10),
            ),
            "blocked": Finding(
                run_id=UUID(passive_run_id),
                title="Blocked dependency upgrade",
                severity="medium",
                target_id="https://app.example.test/login",
                evidence_ref="artifact://findings/dependency",
                status="open",
                summary="The remediation owner is waiting on a dependency upgrade.",
                created_at=now - timedelta(days=20),
                updated_at=now - timedelta(days=20),
            ),
            "verified": Finding(
                run_id=UUID(passive_run_id),
                title="Header remediation verified",
                severity="low",
                target_id="https://app.example.test",
                evidence_ref="artifact://findings/header",
                status="resolved",
                summary="Retest evidence confirmed closure.",
                created_at=now - timedelta(days=8),
                updated_at=now - timedelta(days=8),
            ),
            "overdue": Finding(
                run_id=UUID(passive_run_id),
                title="Overdue cookie hardening",
                severity="medium",
                target_id="https://app.example.test/session",
                evidence_ref="artifact://findings/cookie",
                status="open",
                summary="The remediation window has passed.",
                created_at=now - timedelta(days=40),
                updated_at=now - timedelta(days=40),
            ),
            "due_soon": Finding(
                run_id=UUID(passive_run_id),
                title="Due soon CSP update",
                severity="low",
                target_id="https://app.example.test/content",
                evidence_ref="artifact://findings/csp",
                status="open",
                summary="The due date is inside the warning window.",
                created_at=now - timedelta(days=27),
                updated_at=now - timedelta(days=27),
            ),
        }
        session.add_all(findings.values())
        session.flush()
        session.add_all(
            [
                FindingRemediation(
                    finding_id=findings["ready"].id,
                    state="ready_for_retest",
                    notes="Fix deployed to the approved test environment.",
                    owner="app-team",
                    created_by="portfolio-owner",
                    updated_by="portfolio-owner",
                    created_at=now - timedelta(days=10),
                    updated_at=now - timedelta(days=1),
                ),
                FindingRemediation(
                    finding_id=findings["blocked"].id,
                    state="blocked",
                    notes="Waiting on an upstream package owner.",
                    owner="platform-team",
                    created_by="portfolio-owner",
                    updated_by="portfolio-owner",
                    created_at=now - timedelta(days=20),
                    updated_at=now - timedelta(days=2),
                ),
                FindingRemediation(
                    finding_id=findings["verified"].id,
                    state="verified",
                    notes="Proof-of-resolution has been reviewed.",
                    owner="app-team",
                    created_by="portfolio-owner",
                    updated_by="portfolio-owner",
                    created_at=now - timedelta(days=8),
                    updated_at=now - timedelta(days=1),
                ),
                FindingRemediation(
                    finding_id=findings["overdue"].id,
                    state="in_progress",
                    notes="Still being remediated.",
                    owner="app-team",
                    created_by="portfolio-owner",
                    updated_by="portfolio-owner",
                    created_at=now - timedelta(days=40),
                    updated_at=now - timedelta(days=3),
                ),
                FindingRemediation(
                    finding_id=findings["due_soon"].id,
                    state="planned",
                    notes="Scheduled this week.",
                    owner="app-team",
                    created_by="portfolio-owner",
                    updated_by="portfolio-owner",
                    created_at=now - timedelta(days=27),
                    updated_at=now - timedelta(days=2),
                ),
            ]
        )
        session.commit()
        return {name: str(finding.id) for name, finding in findings.items()} | {
            "active_run_id": active_run_id,
            "passive_run_id": passive_run_id,
        }


def test_remediation_portfolio_surfaces_owner_sla_and_retest_planning(client) -> None:
    engagement_id = _create_engagement_with_scope(client)
    seeded = _seed_portfolio_findings(client, engagement_id)

    response = client.get(
        f"/api/v1/engagements/{engagement_id}/remediation/portfolio?sla_days=30&due_soon_days=7"
    )

    assert response.status_code == 200
    portfolio = response.json()
    assert portfolio["policy"]["contractual_enforcement"] is False
    assert "planning signals" in portfolio["policy"]["note"]
    assert portfolio["summary"]["total_items"] == 5
    assert portfolio["summary"]["eligible_for_retest"] == 1
    assert portfolio["summary"]["blocked"] == 1
    assert portfolio["summary"]["verified"] == 1
    assert portfolio["summary"]["overdue"] == 1
    assert portfolio["summary"]["due_soon"] == 1

    items_by_id = {item["finding"]["id"]: item for item in portfolio["items"]}
    assert items_by_id[seeded["ready"]]["eligible_for_retest"] is True
    assert items_by_id[seeded["ready"]]["approval_required_count"] == 1
    assert items_by_id[seeded["ready"]]["sla_status"] == "on_track"
    assert items_by_id[seeded["blocked"]]["sla_status"] == "blocked"
    assert items_by_id[seeded["verified"]]["verification_state"] == "verified"
    assert items_by_id[seeded["overdue"]]["sla_status"] == "overdue"
    assert items_by_id[seeded["due_soon"]]["sla_status"] == "due_soon"

    plan = portfolio["retest_plan"]
    assert plan["plan_mode"] == "planning_only"
    assert plan["automatic_dispatch_performed"] is False
    assert plan["created_run_ids"] == []
    assert len(plan["groups"]) == 1
    assert plan["groups"][0]["source_run_id"] == seeded["active_run_id"]
    assert plan["groups"][0]["approval_required_count"] == 1
    assert plan["groups"][0]["finding_ids"] == [seeded["ready"]]
    assert "requires 1 approval" in plan["groups"][0]["next_operator_action"]

    owner_response = client.get(
        f"/api/v1/engagements/{engagement_id}/remediation/portfolio?owner=app-team"
    )
    assert owner_response.status_code == 200
    assert owner_response.json()["summary"]["total_items"] == 4

    overdue_response = client.get(
        f"/api/v1/engagements/{engagement_id}/remediation/portfolio?sla_status=overdue"
    )
    assert overdue_response.status_code == 200
    assert [item["finding"]["id"] for item in overdue_response.json()["items"]] == [seeded["overdue"]]

    eligible_response = client.get(
        f"/api/v1/engagements/{engagement_id}/remediation/portfolio?eligible_for_retest=true"
    )
    assert eligible_response.status_code == 200
    assert [item["finding"]["id"] for item in eligible_response.json()["items"]] == [seeded["ready"]]


def test_remediation_retest_plan_is_planning_only_and_does_not_create_runs(client) -> None:
    engagement_id = _create_engagement_with_scope(client)
    seeded = _seed_portfolio_findings(client, engagement_id)

    with client.app.state.session_factory() as session:
        run_count_before = len(session.scalars(select(Run).where(Run.engagement_id == UUID(engagement_id))).all())

    plan_response = client.post(
        f"/api/v1/engagements/{engagement_id}/remediation/retest-plan",
        json={
            "finding_ids": [seeded["ready"], seeded["blocked"]],
            "sla_days": 30,
            "due_soon_days": 7,
            "notes": "Plan a batch, but do not dispatch it.",
        },
    )

    assert plan_response.status_code == 200
    plan = plan_response.json()
    assert plan["automatic_dispatch_performed"] is False
    assert plan["explicit_operator_action_required"] is True
    assert plan["created_run_ids"] == []
    assert len(plan["groups"]) == 1
    assert plan["groups"][0]["finding_ids"] == [seeded["ready"]]
    assert plan["excluded_items"][0]["finding_id"] == seeded["blocked"]
    assert "does not create runs" in plan["approval_boundary"]

    with client.app.state.session_factory() as session:
        run_count_after = len(session.scalars(select(Run).where(Run.engagement_id == UUID(engagement_id))).all())

    assert run_count_after == run_count_before


def test_remediation_portfolio_respects_tenant_boundary(client) -> None:
    engagement_id = _create_engagement_with_scope(client, tenant_id="tenant-a")
    _seed_portfolio_findings(client, engagement_id)

    allowed = client.get(
        f"/api/v1/engagements/{engagement_id}/remediation/portfolio",
        headers={"X-Tenant-ID": "tenant-a"},
    )
    denied = client.get(
        f"/api/v1/engagements/{engagement_id}/remediation/portfolio",
        headers={"X-Tenant-ID": "tenant-b"},
    )

    assert allowed.status_code == 200
    assert denied.status_code == 404


def test_finding_status_change_and_false_positive_are_audited(client) -> None:
    engagement_id = _create_engagement_with_scope(client)
    run_id = _create_run(client, engagement_id)
    with client.app.state.session_factory() as session:
        finding = Finding(
            run_id=UUID(run_id),
            title="False positive audit candidate",
            severity="medium",
            target_id="https://app.example.test/audit",
            evidence_ref="artifact://findings/audit",
            status="open",
            summary="Synthetic finding for audit lifecycle validation.",
        )
        session.add(finding)
        session.commit()
        finding_id = str(finding.id)

    response = client.patch(
        f"/api/v1/findings/{finding_id}",
        headers={"X-Actor": "reviewer"},
        json={"status": "false_positive", "false_positive_reason": "Control is not reachable."},
    )
    assert response.status_code == 200
    assert response.json()["status"] == "false_positive"
    assert response.json()["false_positive_reason"] == "Control is not reachable."
    assert response.json()["false_positive_confirmed_by"] == "reviewer"
    assert response.json()["sla_breached"] is False

    with client.app.state.session_factory() as session:
        stored_finding = session.scalar(select(Finding).where(Finding.id == UUID(finding_id)))
        status_event = session.scalar(
            select(AuditEvent).where(
                AuditEvent.object_id == finding_id,
                AuditEvent.action == "finding.status_changed",
            )
        )
        false_positive_event = session.scalar(
            select(AuditEvent).where(
                AuditEvent.object_id == finding_id,
                AuditEvent.action == "finding.false_positive_marked",
            )
        )
        assert status_event is not None
        assert status_event.metadata_json == {"old_status": "open", "new_status": "false_positive"}
        assert false_positive_event is not None
        assert false_positive_event.metadata_json["reason"] == "Control is not reachable."
        assert stored_finding.false_positive_reason == "Control is not reachable."
        assert stored_finding.false_positive_confirmed_by == "reviewer"


def test_false_positive_requires_documented_reason(client) -> None:
    engagement_id = _create_engagement_with_scope(client)
    run_id = _create_run(client, engagement_id)
    with client.app.state.session_factory() as session:
        finding = Finding(
            run_id=UUID(run_id),
            title="Missing reason candidate",
            severity="low",
            target_id="https://app.example.test/reason",
            evidence_ref="artifact://findings/reason",
            status="open",
            summary="Synthetic finding for reason enforcement.",
        )
        session.add(finding)
        session.commit()
        finding_id = str(finding.id)

    response = client.patch(
        f"/api/v1/findings/{finding_id}",
        headers={"X-Actor": "reviewer"},
        json={"status": "false_positive"},
    )

    assert response.status_code == 422
    assert "false_positive_reason" in response.json()["detail"]


def test_finding_sla_is_lazy_computed_and_dashboard_counts_overdue(client) -> None:
    tenant_id = "sla-tenant"
    engagement_id = _create_engagement_with_scope(client, tenant_id=tenant_id)
    run_id = _create_run(client, engagement_id)
    now = datetime.now(tz=UTC)
    with client.app.state.session_factory() as session:
        session.add_all(
            [
                Finding(
                    run_id=UUID(run_id),
                    title="Critical overdue finding",
                    severity="critical",
                    target_id="https://app.example.test/critical",
                    evidence_ref="artifact://findings/critical-overdue",
                    status="open",
                    summary="Synthetic critical overdue finding.",
                    created_at=now - timedelta(days=2),
                    updated_at=now - timedelta(days=2),
                ),
                Finding(
                    run_id=UUID(run_id),
                    title="High overdue finding",
                    severity="high",
                    target_id="https://app.example.test/high",
                    evidence_ref="artifact://findings/high-overdue",
                    status="open",
                    summary="Synthetic high overdue finding.",
                    created_at=now - timedelta(days=8),
                    updated_at=now - timedelta(days=8),
                ),
                Finding(
                    run_id=UUID(run_id),
                    title="Resolved old critical finding",
                    severity="critical",
                    target_id="https://app.example.test/resolved",
                    evidence_ref="artifact://findings/resolved",
                    status="resolved",
                    summary="Closed findings do not breach SLA.",
                    created_at=now - timedelta(days=9),
                    updated_at=now - timedelta(days=9),
                ),
            ]
        )
        session.commit()

    list_response = client.get(f"/api/v1/runs/{run_id}/findings", headers={"X-Tenant-ID": tenant_id})
    assert list_response.status_code == 200
    findings = {item["title"]: item for item in list_response.json()}
    assert findings["Critical overdue finding"]["remediation_due_date"] is not None
    assert findings["Critical overdue finding"]["sla_breached"] is True
    assert findings["High overdue finding"]["sla_breached"] is True
    assert findings["Resolved old critical finding"]["sla_breached"] is False

    dashboard_response = client.get("/api/v1/dashboard", headers={"X-Tenant-ID": tenant_id})
    assert dashboard_response.status_code == 200
    open_problems = dashboard_response.json()["open_problems"]
    assert open_problems["overdue_critical_count"] == 1
    assert open_problems["overdue_high_count"] == 1
