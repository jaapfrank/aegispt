from __future__ import annotations

from uuid import UUID

from sqlalchemy import func, select

from api.app.models import Finding, FindingChain
from api.app.services.finding_chains import refresh_finding_chains_for_run
from api.app.services.finding_views import build_finding_theater


def _create_chain_run(client) -> dict:
    engagement = client.post(
        "/api/v1/engagements",
        headers={"X-Actor": "chain-operator"},
        json={
            "name": "Chain Detection",
            "client": "Acme Corp",
            "roe_ref": "ROE-CHAIN-1",
        },
    ).json()
    client.post(
        f"/api/v1/engagements/{engagement['id']}/scope",
        headers={"X-Actor": "chain-operator"},
        json={
            "allowlist_json": {"urls": ["https://portal.example.test"]},
            "denylist_json": {},
        },
    )

    response = client.post(
        f"/api/v1/engagements/{engagement['id']}/runs",
        headers={"X-Actor": "chain-operator"},
        json={
            "profile_name": "passive-web-baseline",
            "configuration_json": {
                "assessment_type": "Website / Web App",
                "targets": {"urls": ["https://portal.example.test"]},
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
                severity=spec.get("severity", "medium"),
                target_id=spec.get("target_id", "https://portal.example.test"),
                evidence_ref=spec.get("evidence_ref", "artifact://chain/evidence"),
                status=spec.get("status", "open"),
                summary=spec.get("summary", ""),
                methodology_tags=spec.get("methodology_tags", []),
                control_family=spec.get("control_family"),
                wstg_id=spec.get("wstg_id"),
                asvs_reference=spec.get("asvs_reference"),
            )
            session.add(finding)
            session.flush()
            records.append(
                {
                    "id": str(finding.id),
                    "severity": finding.severity,
                    "status": finding.status,
                    "evidence_ref": finding.evidence_ref,
                    "summary": finding.summary,
                }
            )
        session.commit()
    return records


def test_chain_detection_stores_additive_record_and_theater_context_without_mutating_findings(client) -> None:
    run = _create_chain_run(client)
    findings = _seed_findings(
        client,
        run_id=run["id"],
        specs=[
            {
                "title": "Public admin console exposed",
                "severity": "high",
                "evidence_ref": "artifact://http/admin-console",
                "summary": "The admin panel is exposed without network restriction.",
                "methodology_tags": ["management", "exposed"],
            },
            {
                "title": "Default credential accepted",
                "severity": "high",
                "evidence_ref": "artifact://auth/default-password",
                "summary": "A default password was accepted during authorized validation.",
                "methodology_tags": ["credential", "cwe-798"],
            },
        ],
    )
    original = {item["id"]: {key: item[key] for key in ("severity", "status", "evidence_ref", "summary")} for item in findings}

    with client.app.state.session_factory() as session:
        chains = refresh_finding_chains_for_run(session=session, run_id=UUID(run["id"]))
        session.commit()

        assert len(chains) == 1
        chain = chains[0]
        assert chain.pattern_id == "exposed-management-plus-credential-weakness"
        assert chain.status == "detected"
        assert chain.confidence_score >= 0.6
        assert set(chain.component_finding_ids_json) == {item["id"] for item in findings}
        assert set(chain.evidence_refs_json) == {"artifact://http/admin-console", "artifact://auth/default-password"}
        assert chain.metadata_json["mutates_component_findings"] is False
        assert chain.metadata_json["auto_escalates_severity"] is False
        assert chain.metadata_json["executes_exploits"] is False

        stored_findings = session.scalars(select(Finding).where(Finding.id.in_([UUID(item["id"]) for item in findings]))).all()
        for stored in stored_findings:
            assert {
                "severity": stored.severity,
                "status": stored.status,
                "evidence_ref": stored.evidence_ref,
                "summary": stored.summary,
            } == original[str(stored.id)]

    response = client.get(f"/api/v1/findings/{findings[0]['id']}/theater")
    assert response.status_code == 200
    theater = response.json()
    chain_context = theater["vulnerability_chains"]
    assert chain_context["available"] is True
    assert chain_context["boundary"]["mutates_component_findings"] is False
    assert chain_context["boundary"]["auto_escalates_severity"] is False
    assert chain_context["boundary"]["executes_exploits"] is False
    assert chain_context["chains"][0]["combined_impact"]
    assert chain_context["chains"][0]["component_finding_ids"] == sorted(item["id"] for item in findings)


def test_chain_detection_returns_no_chain_for_unmatched_findings(client) -> None:
    run = _create_chain_run(client)
    findings = _seed_findings(
        client,
        run_id=run["id"],
        specs=[
            {
                "title": "Missing security header",
                "severity": "medium",
                "evidence_ref": "artifact://headers/missing-hsts",
                "summary": "The target omitted an expected security header.",
                "methodology_tags": ["headers"],
            },
        ],
    )

    with client.app.state.session_factory() as session:
        chains = refresh_finding_chains_for_run(session=session, run_id=UUID(run["id"]))
        stored_count = session.scalar(select(func.count()).select_from(FindingChain))
        theater = build_finding_theater(session, UUID(findings[0]["id"]))

    assert chains == []
    assert stored_count == 0
    assert theater is not None
    assert theater.vulnerability_chains["available"] is False
    assert theater.vulnerability_chains["chains"] == []
    assert "No known chain pattern" in theater.vulnerability_chains["no_chain_reason"]


def test_chain_detection_is_idempotent_for_duplicate_refreshes(client) -> None:
    run = _create_chain_run(client)
    _seed_findings(
        client,
        run_id=run["id"],
        specs=[
            {
                "title": "Public admin dashboard exposed",
                "severity": "high",
                "evidence_ref": "artifact://http/admin-dashboard",
                "summary": "The dashboard exposed management functionality.",
            },
            {
                "title": "Weak password policy observed",
                "severity": "medium",
                "evidence_ref": "artifact://auth/weak-password",
                "summary": "A weak password policy was observed for the same management surface.",
            },
        ],
    )

    with client.app.state.session_factory() as session:
        first = refresh_finding_chains_for_run(session=session, run_id=UUID(run["id"]))
        second = refresh_finding_chains_for_run(session=session, run_id=UUID(run["id"]))
        session.commit()
        stored_count = session.scalar(select(func.count()).select_from(FindingChain))

    assert len(first) == 1
    assert len(second) == 1
    assert first[0].id == second[0].id
    assert stored_count == 1


def test_chain_detection_degrades_sparse_matches_to_low_confidence(client) -> None:
    run = _create_chain_run(client)
    findings = _seed_findings(
        client,
        run_id=run["id"],
        specs=[
            {
                "title": "Exposed admin panel mention",
                "severity": "low",
                "evidence_ref": "",
                "summary": "A sparse note references an exposed admin panel.",
            },
            {
                "title": "Credential token weakness mention",
                "severity": "info",
                "evidence_ref": "",
                "summary": "A sparse note references credential token weakness.",
            },
        ],
    )

    with client.app.state.session_factory() as session:
        chains = refresh_finding_chains_for_run(session=session, run_id=UUID(run["id"]))
        session.commit()

    assert len(chains) == 1
    assert chains[0].status == "low_confidence"
    assert chains[0].confidence_score < 0.6
    assert chains[0].evidence_refs_json == []

    response = client.get(f"/api/v1/findings/{findings[0]['id']}/theater")
    assert response.status_code == 200
    chain = response.json()["vulnerability_chains"]["chains"][0]
    assert chain["status"] == "low_confidence"
    assert chain["metadata"]["auto_escalates_severity"] is False
