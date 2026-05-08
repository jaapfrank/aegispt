from __future__ import annotations

from uuid import UUID

from sqlalchemy import select

from api.app.models import Finding, TargetContextDocument
from api.app.services.ai_planner import (
    MAX_PIVOT_DEPTH,
    PIVOT_KIND,
    detect_pivot_eligible_findings,
    generate_pivot_contexts_for_run,
    latest_context_document,
    PHASE0_LAYER_NAME,
)


def _create_pivot_run(client) -> dict:
    engagement = client.post(
        "/api/v1/engagements",
        headers={"X-Actor": "pivot-operator"},
        json={
            "name": "Pivot Engine Test",
            "client": "Acme Corp",
            "roe_ref": "ROE-PIVOT-1",
        },
    ).json()
    client.post(
        f"/api/v1/engagements/{engagement['id']}/scope",
        headers={"X-Actor": "pivot-operator"},
        json={
            "allowlist_json": {"urls": ["https://app.example.test"]},
            "denylist_json": {},
        },
    )
    response = client.post(
        f"/api/v1/engagements/{engagement['id']}/runs",
        headers={"X-Actor": "pivot-operator"},
        json={
            "profile_name": "passive-web-baseline",
            "configuration_json": {
                "assessment_type": "Website / Web App",
                "targets": {"urls": ["https://app.example.test"]},
            },
        },
    )
    assert response.status_code == 201
    return response.json()


def _seed_findings(client, *, run_id: str, specs: list[dict]) -> list[dict]:
    records: list[dict] = []
    with client.app.state.session_factory() as session:
        for spec in specs:
            finding = Finding(
                run_id=UUID(run_id),
                title=spec["title"],
                severity=spec.get("severity", "high"),
                target_id=spec.get("target_id", "https://app.example.test/upload"),
                evidence_ref=spec.get("evidence_ref", "artifact://nuclei/evidence"),
                status=spec.get("status", "open"),
                summary=spec.get("summary", ""),
            )
            session.add(finding)
            session.flush()
            records.append({"id": str(finding.id), "title": finding.title})
        session.commit()
    return records


def _ensure_phase0_context(client, *, run_id: str, engagement_id: str) -> None:
    with client.app.state.session_factory() as session:
        from api.app.models import Scope
        scope = session.scalar(
            select(Scope)
            .where(Scope.engagement_id == UUID(engagement_id))
            .order_by(Scope.created_at.desc())
        )
        assert scope is not None
        from api.app.services.ai_planner import ensure_context_document
        from api.app.models import Run
        run = session.scalar(select(Run).where(Run.id == UUID(run_id)))
        assert run is not None
        ensure_context_document(
            session,
            run=run,
            scope=scope,
            targets=[{"type": "url", "value": "https://app.example.test"}],
        )
        session.commit()


def test_detect_pivot_eligible_findings_returns_ssrf_finding() -> None:
    class FakeFinding:
        id = UUID("00000000-0000-0000-0000-000000000001")
        title = "SSRF via image URL parameter"
        target_id = "https://app.example.test/fetch"

    findings = [FakeFinding()]
    result = detect_pivot_eligible_findings(findings)  # type: ignore[arg-type]
    assert len(result) == 1
    finding, pivot_type, reason_template, tools, pattern = result[0]
    assert pivot_type == "ssrf_outbound_pivot"
    assert "httpx" in tools
    assert "{target}" in reason_template or "SSRF" in reason_template


def test_detect_pivot_eligible_findings_returns_rce_finding() -> None:
    class FakeFinding:
        id = UUID("00000000-0000-0000-0000-000000000002")
        title = "Remote Code Execution via deserialization"
        target_id = "https://app.example.test/api/deserialize"

    findings = [FakeFinding()]
    result = detect_pivot_eligible_findings(findings)  # type: ignore[arg-type]
    assert len(result) == 1
    _, pivot_type, _, tools, _ = result[0]
    assert pivot_type == "rce_shell_pivot"
    assert "priv-esc-linux" in tools


def test_detect_pivot_eligible_findings_returns_empty_for_benign() -> None:
    class FakeFinding:
        id = UUID("00000000-0000-0000-0000-000000000003")
        title = "Missing Content-Security-Policy header"
        target_id = "https://app.example.test/"

    findings = [FakeFinding()]
    result = detect_pivot_eligible_findings(findings)  # type: ignore[arg-type]
    assert result == []


def test_generate_pivot_contexts_creates_document_for_ssrf(client) -> None:
    run = _create_pivot_run(client)
    run_id = run["id"]
    engagement_id = run["engagement_id"]

    _ensure_phase0_context(client, run_id=run_id, engagement_id=engagement_id)
    _seed_findings(client, run_id=run_id, specs=[
        {
            "title": "SSRF confirmed via fetch endpoint",
            "severity": "high",
            "target_id": "https://app.example.test/fetch?url=",
            "evidence_ref": "artifact://nuclei/ssrf-001",
        }
    ])

    with client.app.state.session_factory() as session:
        from api.app.models import Run, Scope
        run_obj = session.scalar(select(Run).where(Run.id == UUID(run_id)))
        scope = session.scalar(
            select(Scope)
            .where(Scope.engagement_id == UUID(engagement_id))
            .order_by(Scope.created_at.desc())
        )
        parent_context = latest_context_document(session, run_id=UUID(run_id), layer_name=PHASE0_LAYER_NAME)
        assert parent_context is not None

        created = generate_pivot_contexts_for_run(
            session,
            run=run_obj,
            scope=scope,
            parent_context=parent_context,
        )
        session.commit()

    assert len(created) == 1
    pivot_doc = created[0]
    assert pivot_doc.context_kind == PIVOT_KIND
    assert pivot_doc.parent_context_document_id == parent_context.id
    assert "ssrf" in pivot_doc.layer_name
    assert "httpx" in pivot_doc.recommended_tools_json
    assert pivot_doc.provenance_json["pivot_type"] == "ssrf_outbound_pivot"
    assert pivot_doc.provenance_json["scope_enforced"] is True
    assert pivot_doc.provenance_json["runner_registry_bypassed"] is False


def test_generate_pivot_contexts_is_idempotent(client) -> None:
    run = _create_pivot_run(client)
    run_id = run["id"]
    engagement_id = run["engagement_id"]

    _ensure_phase0_context(client, run_id=run_id, engagement_id=engagement_id)
    _seed_findings(client, run_id=run_id, specs=[
        {
            "title": "SQL Injection on login endpoint",
            "severity": "critical",
            "target_id": "https://app.example.test/login",
            "evidence_ref": "artifact://sqlmap/sqli-001",
        }
    ])

    with client.app.state.session_factory() as session:
        from api.app.models import Run, Scope
        run_obj = session.scalar(select(Run).where(Run.id == UUID(run_id)))
        scope = session.scalar(
            select(Scope)
            .where(Scope.engagement_id == UUID(engagement_id))
            .order_by(Scope.created_at.desc())
        )
        parent_context = latest_context_document(session, run_id=UUID(run_id), layer_name=PHASE0_LAYER_NAME)

        first = generate_pivot_contexts_for_run(session, run=run_obj, scope=scope, parent_context=parent_context)
        second = generate_pivot_contexts_for_run(session, run=run_obj, scope=scope, parent_context=parent_context)
        session.commit()

        stored_pivots = session.scalars(
            select(TargetContextDocument).where(
                TargetContextDocument.run_id == UUID(run_id),
                TargetContextDocument.context_kind == PIVOT_KIND,
            )
        ).all()

    assert len(first) == 1
    assert len(second) == 0
    assert len(stored_pivots) == 1


def test_generate_pivot_contexts_respects_max_depth(client) -> None:
    run = _create_pivot_run(client)
    run_id = run["id"]
    engagement_id = run["engagement_id"]

    _ensure_phase0_context(client, run_id=run_id, engagement_id=engagement_id)
    _seed_findings(client, run_id=run_id, specs=[
        {"title": f"SSRF finding variant {i}", "severity": "high", "evidence_ref": f"artifact://nuclei/ssrf-{i:03d}"}
        for i in range(MAX_PIVOT_DEPTH + 2)
    ])

    with client.app.state.session_factory() as session:
        from api.app.models import Run, Scope
        run_obj = session.scalar(select(Run).where(Run.id == UUID(run_id)))
        scope = session.scalar(
            select(Scope)
            .where(Scope.engagement_id == UUID(engagement_id))
            .order_by(Scope.created_at.desc())
        )
        parent_context = latest_context_document(session, run_id=UUID(run_id), layer_name=PHASE0_LAYER_NAME)

        created = generate_pivot_contexts_for_run(session, run=run_obj, scope=scope, parent_context=parent_context)
        session.commit()

    assert len(created) <= MAX_PIVOT_DEPTH
