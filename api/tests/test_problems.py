from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import UUID

from sqlalchemy import select

from api.app.models import Finding, FindingRemediation, Run


def _headers(tenant_id: str, actor: str = "problems-operator") -> dict[str, str]:
    return {"X-Tenant-ID": tenant_id, "X-Actor": actor}


def _create_engagement(client, *, tenant_id: str, name: str, target: str = "https://app.example.test") -> str:
    response = client.post(
        "/api/v1/engagements",
        headers=_headers(tenant_id),
        json={"name": name, "client": f"{tenant_id} Client", "roe_ref": f"ROE-{tenant_id}"},
    )
    assert response.status_code == 201
    engagement_id = response.json()["id"]
    scope_response = client.post(
        f"/api/v1/engagements/{engagement_id}/scope",
        headers=_headers(tenant_id),
        json={"allowlist_json": {"urls": [target]}, "denylist_json": {}},
    )
    assert scope_response.status_code == 201
    return engagement_id


def _create_run(client, *, tenant_id: str, engagement_id: str, target: str = "https://app.example.test") -> str:
    response = client.post(
        f"/api/v1/engagements/{engagement_id}/runs",
        headers=_headers(tenant_id),
        json={
            "profile_name": "passive-web-baseline",
            "configuration_json": {
                "assessment_type": "Website / Web App",
                "targets": {"urls": [target]},
            },
        },
    )
    assert response.status_code == 201
    return response.json()["id"]


def _seed_problem(
    session,
    *,
    run_id: str,
    title: str,
    severity: str,
    status: str = "open",
    age_days: int = 3,
    owner: str | None = None,
    remediation_state: str | None = None,
    tags: list[str] | None = None,
) -> Finding:
    now = datetime.now(tz=UTC)
    finding = Finding(
        run_id=UUID(run_id),
        title=title,
        severity=severity,
        target_id="https://app.example.test",
        evidence_ref=f"artifact://problems/{title.lower().replace(' ', '-')}",
        status=status,
        summary=f"{title} summary",
        methodology_tags=tags or ["OWASP-WSTG"],
        created_at=now - timedelta(days=age_days),
        updated_at=now - timedelta(days=max(age_days - 1, 0)),
    )
    session.add(finding)
    session.flush()
    if owner is not None or remediation_state is not None:
        session.add(
            FindingRemediation(
                finding_id=finding.id,
                state=remediation_state or "not_started",
                owner=owner,
                notes=f"{title} remediation",
                created_by="seed",
                updated_by="seed",
                created_at=now - timedelta(days=age_days),
                updated_at=now - timedelta(days=max(age_days - 1, 0)),
            )
        )
    return finding


def test_problems_center_defaults_are_tenant_scoped_and_cursor_paginated(client) -> None:
    tenant_a = "tenant-a"
    tenant_b = "tenant-b"
    engagement_a = _create_engagement(client, tenant_id=tenant_a, name="Tenant A Problems")
    engagement_b = _create_engagement(client, tenant_id=tenant_b, name="Tenant B Problems")
    run_a = _create_run(client, tenant_id=tenant_a, engagement_id=engagement_a)
    run_b = _create_run(client, tenant_id=tenant_b, engagement_id=engagement_b)

    with client.app.state.session_factory() as session:
        critical = _seed_problem(
            session,
            run_id=run_a,
            title="Critical admin takeover",
            severity="critical",
            age_days=35,
            owner="app-team",
            tags=["OWASP-WSTG", "PTES"],
        )
        high = _seed_problem(session, run_id=run_a, title="High session weakness", severity="high", age_days=8)
        _seed_problem(session, run_id=run_a, title="Medium informational gap", severity="medium", age_days=2)
        _seed_problem(
            session,
            run_id=run_a,
            title="Resolved TLS gap",
            severity="high",
            status="resolved",
            age_days=12,
            owner="infra-team",
            remediation_state="verified",
        )
        _seed_problem(session, run_id=run_b, title="Cross tenant critical", severity="critical", age_days=1)
        session.commit()

    default_response = client.get("/api/v1/problems", headers=_headers(tenant_a))

    assert default_response.status_code == 200
    default_payload = default_response.json()
    assert [item["title"] for item in default_payload["items"]] == [
        "Critical admin takeover",
        "High session weakness",
    ]
    assert default_payload["items"][0]["engagement_name"] == "Tenant A Problems"
    assert default_payload["items"][0]["age_bucket"] == "overdue"
    assert default_payload["items"][0]["problem_status"] == "open"
    assert default_payload["items"][0]["assignee"] == "app-team"
    assert default_payload["stats"]["open_critical"] == 1
    assert default_payload["stats"]["open_high"] == 1
    assert default_payload["stats"]["open_medium"] == 1
    assert default_payload["stats"]["total_filtered"] == 2
    assert default_payload["stats"]["total_findings"] == 4
    assert default_payload["stats"]["total_resolved"] == 0
    assert default_payload["stats"]["total_verified"] == 1
    assert default_payload["stats"]["by_severity"]["critical"] == 1
    assert default_payload["stats"]["by_severity"]["high"] == 2
    assert default_payload["stats"]["by_severity"]["medium"] == 1
    assert default_payload["stats"]["by_finding_status"]["open"] == 3
    assert default_payload["lifecycle_summary"]["visible_findings"] == 2
    assert default_payload["lifecycle_summary"]["total_findings"] == 4
    assert "filtered" in default_payload["lifecycle_summary"]["count_truth"]
    assert default_payload["stats"]["total_recently_resolved"] == 1
    assert default_payload["recently_resolved"][0]["title"] == "Resolved TLS gap"
    assert "app-team" in default_payload["filters"]["assignees"]
    assert "PTES" in default_payload["filters"]["methodologies"]
    assert all(item["title"] != "Cross tenant critical" for item in default_payload["items"])

    paged_response = client.get(
        "/api/v1/problems?severity=all&status=all&limit=2",
        headers=_headers(tenant_a),
    )
    assert paged_response.status_code == 200
    page = paged_response.json()
    assert len(page["items"]) == 2
    assert page["next_cursor"]

    next_response = client.get(
        f"/api/v1/problems?severity=all&status=all&limit=2&cursor={page['next_cursor']}",
        headers=_headers(tenant_a),
    )
    assert next_response.status_code == 200
    assert {item["id"] for item in page["items"]}.isdisjoint(
        {item["id"] for item in next_response.json()["items"]}
    )
    assert {str(critical.id), str(high.id)} <= {
        item["id"] for item in page["items"] + next_response.json()["items"]
    }


def test_problem_bulk_assign_status_and_retest_use_existing_single_finding_path(client) -> None:
    tenant_id = "tenant-bulk"
    engagement_id = _create_engagement(client, tenant_id=tenant_id, name="Bulk Problems")
    run_id = _create_run(client, tenant_id=tenant_id, engagement_id=engagement_id)

    with client.app.state.session_factory() as session:
        finding = _seed_problem(session, run_id=run_id, title="Bulk managed issue", severity="high")
        other = _seed_problem(session, run_id=run_id, title="Other issue", severity="critical")
        session.commit()
        finding_id = str(finding.id)
        other_id = str(other.id)

    assign_response = client.patch(
        "/api/v1/problems/bulk",
        headers=_headers(tenant_id, "bulk-owner"),
        json={"finding_ids": [finding_id], "action": "assign", "assignee": "platform-team"},
    )
    assert assign_response.status_code == 200
    assert assign_response.json()["updated_count"] == 1

    verify_response = client.patch(
        "/api/v1/problems/bulk",
        headers=_headers(tenant_id, "bulk-owner"),
        json={"finding_ids": [finding_id], "action": "status", "status": "verified"},
    )
    assert verify_response.status_code == 200
    assert verify_response.json()["updated_count"] == 1

    retest_response = client.patch(
        "/api/v1/problems/bulk",
        headers=_headers(tenant_id, "bulk-owner"),
        json={
            "finding_ids": [other_id],
            "action": "schedule_retest",
            "retest_notes": "Validate the original affected target only.",
        },
    )
    assert retest_response.status_code == 200
    retest_payload = retest_response.json()
    assert retest_payload["updated_count"] == 1
    assert len(retest_payload["retest_run_ids"]) == 1

    with client.app.state.session_factory() as session:
        stored_finding = session.scalar(select(Finding).where(Finding.id == UUID(finding_id)))
        assert stored_finding is not None
        assert stored_finding.status == "resolved"
        remediation = session.scalar(select(FindingRemediation).where(FindingRemediation.finding_id == UUID(finding_id)))
        assert remediation is not None
        assert remediation.owner == "platform-team"
        assert remediation.state == "verified"

        retest_run = session.scalar(select(Run).where(Run.id == UUID(retest_payload["retest_run_ids"][0])))
        assert retest_run is not None
        assert retest_run.configuration_json["retest"]["source_finding_id"] == other_id
        assert retest_run.configuration_json["retest"]["operator_notes"] == "Validate the original affected target only."


def test_problem_bulk_actions_do_not_cross_tenant_and_delete_is_blocked(client) -> None:
    engagement_a = _create_engagement(client, tenant_id="tenant-a", name="Tenant A")
    engagement_b = _create_engagement(client, tenant_id="tenant-b", name="Tenant B")
    run_a = _create_run(client, tenant_id="tenant-a", engagement_id=engagement_a)
    run_b = _create_run(client, tenant_id="tenant-b", engagement_id=engagement_b)

    with client.app.state.session_factory() as session:
        own = _seed_problem(session, run_id=run_a, title="Owned issue", severity="high")
        foreign = _seed_problem(session, run_id=run_b, title="Foreign issue", severity="critical")
        session.commit()
        own_id = str(own.id)
        foreign_id = str(foreign.id)

    response = client.patch(
        "/api/v1/problems/bulk",
        headers=_headers("tenant-a"),
        json={"finding_ids": [own_id, foreign_id], "action": "assign", "assignee": "tenant-a-team"},
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["updated_count"] == 1
    assert payload["skipped"] == [{"finding_id": foreign_id, "reason": "finding not found"}]

    delete_response = client.patch(
        "/api/v1/problems/bulk",
        headers=_headers("tenant-a"),
        json={"finding_ids": [own_id], "action": "delete"},
    )
    assert delete_response.status_code == 409
    assert "no finding soft-delete marker exists" in delete_response.json()["detail"]
