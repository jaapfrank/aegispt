from __future__ import annotations

from pathlib import Path
from uuid import UUID, uuid4

from sqlalchemy import select

from api.app.config import get_settings
from api.app.models import AgentProposal, Approval, Engagement, Run, RunProfile, Scope, Task
from api.app.services.ai_agent import review_agent_proposal
from api.app.services.cve_sync import FeedFetchResult
from api.app.services.inventory import create_inventory_snapshot_record
from api.app.services.on_demand_cve_intel import (
    build_run_cve_intelligence,
    maybe_refresh_after_discovery_task,
)
from api.app.services.threat_intel import upsert_threat_intel_record


def _create_service_run(client) -> tuple[str, str]:
    engagement_response = client.post(
        "/api/v1/engagements",
        headers={"X-Actor": "operator"},
        json={"name": "On-demand CVE LAN", "client": "Acme", "roe_ref": "ROE-CVE-INTEL"},
    )
    engagement_id = engagement_response.json()["id"]
    client.post(
        f"/api/v1/engagements/{engagement_id}/scope",
        headers={"X-Actor": "operator"},
        json={"allowlist_json": {"ip_addresses": ["10.0.20.14"]}, "denylist_json": {}},
    )
    run_response = client.post(
        f"/api/v1/engagements/{engagement_id}/runs",
        headers={"X-Actor": "operator"},
        json={
            "profile_name": "passive-network-service-enumeration",
            "configuration_json": {
                "targets": {"ip_addresses": ["10.0.20.14"]},
                "assessment_type": "Internal Range / LAN",
            },
        },
    )
    assert run_response.status_code == 201
    return engagement_id, run_response.json()["id"]


def _seed_nginx_inventory_and_intel(session, *, engagement_id: str, run_id: str) -> None:
    snapshot = create_inventory_snapshot_record(
        engagement_id=UUID(engagement_id),
        requested_by="operator",
        source_tools=["nmap"],
        observations=[
            {
                "tool": "nmap",
                "kind": "inventory",
                "data": {
                    "hosts": ["10.0.20.14"],
                    "services": [
                        {
                            "host": "10.0.20.14",
                            "port": 80,
                            "protocol": "tcp",
                            "service": "http",
                            "product": "nginx",
                            "version": "1.25",
                            "confidence": 0.9,
                        }
                    ],
                    "fingerprints": [
                        {
                            "vendor": "F5",
                            "product": "nginx",
                            "version": "1.25",
                            "confidence": 0.86,
                        }
                    ],
                },
            }
        ],
        environment_notes=["Service inventory from bounded nmap service detection."],
        assumptions=["No exploit tests were run."],
        raw_inputs_json={"run_id": run_id},
    )
    session.add(snapshot)
    upsert_threat_intel_record(
        session,
        {
            "source": "cve-cvss",
            "advisory_id": "CVE-2026-9999",
            "title": "Critical nginx request smuggling",
            "summary": "nginx 1.25 request handling flaw.",
            "affected_products": ["nginx", "F5 nginx"],
            "affected_versions": ["1.25"],
            "product_match_hints": ["nginx", "nginx 1.25"],
            "confidence": 0.92,
            "severity": "critical",
            "references": ["https://nvd.nist.gov/vuln/detail/CVE-2026-9999"],
            "metadata": {
                "feed_type": "cve_cvss",
                "cvss_score": 9.1,
                "cvss_severity": "CRITICAL",
                "external_lookup_performed": False,
            },
        },
    )


def _create_active_cve_review_run(session) -> tuple[Run, Task]:
    suffix = str(uuid4())
    engagement = Engagement(
        name=f"CVE proposal active {suffix}",
        client="Acme",
        roe_ref=f"ROE-CVE-PROPOSAL-{suffix}",
        status="active",
    )
    scope = Scope(
        engagement=engagement,
        allowlist_json={"ip_addresses": ["10.0.20.14"]},
        denylist_json={},
    )
    profile = RunProfile(
        name=f"cve-proposal-active-{suffix}",
        run_class="active",
        limits_json={
            "tools": ["nmap"],
            "required_approvals": 1,
            "max_rps": 1,
            "max_concurrency": 1,
        },
    )
    run = Run(
        engagement=engagement,
        profile=profile,
        requested_by="operator",
        status="running",
        configuration_json={
            "targets": {"ip_addresses": ["10.0.20.14"]},
            "assessment_type": "Internal Range / LAN",
        },
    )
    task = Task(
        run=run,
        tool="nmap",
        target_id="10.0.20.14",
        status="completed",
        params_json={"profile_name": "active-service-fingerprint"},
    )
    approval = Approval(
        run=run,
        step_id="run.launch",
        approver_id="operator",
        decision="approved",
    )
    session.add_all([engagement, scope, profile, run, task, approval])
    session.flush()
    return run, task


def test_on_demand_cve_intelligence_matches_discovery_products_without_running_tests(
    client,
    tmp_path: Path,
    monkeypatch,
) -> None:
    template_dir = tmp_path / "nuclei-templates"
    template_dir.mkdir()
    (template_dir / "CVE-2026-9999.yaml").write_text(
        "id: CVE-2026-9999\ninfo:\n  name: nginx detection\n  severity: critical\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("NUCLEI_TEMPLATES_DIR", str(template_dir))

    engagement_id, run_id = _create_service_run(client)
    with client.app.state.session_factory() as session:
        _seed_nginx_inventory_and_intel(session, engagement_id=engagement_id, run_id=run_id)
        initial_task_count = len(session.scalars(select(Task).where(Task.run_id == UUID(run_id))).all())
        session.commit()

    response = client.get(f"/api/v1/runs/{run_id}/cve-intelligence")

    assert response.status_code == 200
    payload = response.json()
    assert payload["product_count"] >= 1
    assert payload["cve_count"] == 1
    assert payload["rows"][0]["cve_id"] == "CVE-2026-9999"
    assert payload["rows"][0]["test_status"] == "ready"
    assert payload["rows"][0]["affected_product"]["host"] == "10.0.20.14"
    assert payload["boundary"]["automatic_tests_started"] is False

    with client.app.state.session_factory() as session:
        task_count = len(session.scalars(select(Task).where(Task.run_id == UUID(run_id))).all())
        assert task_count == initial_task_count


def test_discovery_refresh_creates_pending_nuclei_proposal_without_dispatch(
    client,
    tmp_path: Path,
    monkeypatch,
) -> None:
    template_dir = tmp_path / "nuclei-templates"
    template_dir.mkdir()
    (template_dir / "CVE-2026-9999.yaml").write_text(
        "id: CVE-2026-9999\ninfo:\n  name: nginx detection\n  severity: critical\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("NUCLEI_TEMPLATES_DIR", str(template_dir))
    engagement_id, run_id = _create_service_run(client)

    with client.app.state.session_factory() as session:
        _seed_nginx_inventory_and_intel(session, engagement_id=engagement_id, run_id=run_id)
        task = session.scalar(select(Task).where(Task.run_id == UUID(run_id), Task.tool == "nmap"))
        assert task is not None
        task.status = "completed"
        task_count_before = len(session.scalars(select(Task).where(Task.run_id == UUID(run_id))).all())

        payload = maybe_refresh_after_discovery_task(session, task=task, settings=get_settings())

        assert payload is not None
        assert payload["boundary"]["automatic_tests_started"] is False
        assert payload["boundary"]["agent_proposals_created"] == 1
        proposals = session.scalars(select(AgentProposal).where(AgentProposal.run_id == UUID(run_id))).all()
        assert len(proposals) == 1
        proposal = proposals[0]
        assert proposal.status == "pending_review"
        assert proposal.proposed_tool == "nuclei"
        assert proposal.proposed_target == "10.0.20.14"
        assert proposal.risk_tier == "active"
        assert "CVE CVE-2026-9999 matched" in (proposal.reasoning_text or "")
        assert proposal.proposed_params_json["template_id"] == "CVE-2026-9999"
        assert "id: CVE-2026-9999" in proposal.proposed_params_json["template_body"]
        assert proposal.proposed_params_json["on_demand_cve_intelligence"]["operator_approved"] is False
        assert proposal.metadata_json["proposal_kind"] == "cve_to_test_auto_queue"
        task_count_after = len(session.scalars(select(Task).where(Task.run_id == UUID(run_id))).all())
        assert task_count_after == task_count_before


def test_discovery_refresh_without_nuclei_template_creates_no_proposal(
    client,
    tmp_path: Path,
    monkeypatch,
) -> None:
    template_dir = tmp_path / "empty-nuclei-templates"
    template_dir.mkdir()
    monkeypatch.setenv("NUCLEI_TEMPLATES_DIR", str(template_dir))
    engagement_id, run_id = _create_service_run(client)

    with client.app.state.session_factory() as session:
        _seed_nginx_inventory_and_intel(session, engagement_id=engagement_id, run_id=run_id)
        task = session.scalar(select(Task).where(Task.run_id == UUID(run_id), Task.tool == "nmap"))
        assert task is not None
        task.status = "completed"

        payload = maybe_refresh_after_discovery_task(session, task=task, settings=get_settings())

        assert payload is not None
        assert payload["rows"][0]["test_status"] == "generatable"
        assert payload["boundary"]["agent_proposals_created"] == 0
        proposals = session.scalars(select(AgentProposal).where(AgentProposal.run_id == UUID(run_id))).all()
        assert proposals == []


def test_cve_agent_proposal_approval_queues_targeted_nuclei_without_dispatch(
    client,
    tmp_path: Path,
    monkeypatch,
) -> None:
    template_dir = tmp_path / "nuclei-templates"
    template_dir.mkdir()
    (template_dir / "CVE-2026-9999.yaml").write_text(
        "id: CVE-2026-9999\ninfo:\n  name: nginx detection\n  severity: critical\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("NUCLEI_TEMPLATES_DIR", str(template_dir))

    with client.app.state.session_factory() as session:
        run, source_task = _create_active_cve_review_run(session)
        run_id = run.id
        _seed_nginx_inventory_and_intel(
            session,
            engagement_id=str(run.engagement_id),
            run_id=str(run.id),
        )
        task_count_before = len(session.scalars(select(Task).where(Task.run_id == run.id)).all())
        payload = maybe_refresh_after_discovery_task(session, task=source_task, settings=get_settings())
        assert payload is not None
        proposal = session.scalar(select(AgentProposal).where(AgentProposal.run_id == run.id))
        assert proposal is not None
        proposal_id = proposal.id
        session.commit()

    with client.app.state.session_factory() as session:
        run = session.get(Run, run_id)
        assert run is not None
        proposal = review_agent_proposal(
            session=session,
            run=run,
            proposal_id=proposal_id,
            decision="approved",
            actor="operator",
        )
        session.commit()
        queued_task_id = UUID(proposal.metadata_json["queued_task_id"])

    with client.app.state.session_factory() as session:
        tasks = session.scalars(select(Task).where(Task.run_id == run_id)).all()
        assert len(tasks) == task_count_before + 1
        queued = session.get(Task, queued_task_id)
        assert queued is not None
        assert queued.tool == "nuclei"
        assert queued.target_id == "10.0.20.14"
        assert queued.status == "queued"
        assert queued.params_json["template_id"] == "CVE-2026-9999"
        assert "id: CVE-2026-9999" in queued.params_json["template_body"]
        cve_context = queued.params_json["on_demand_cve_intelligence"]
        assert cve_context["cve_id"] == "CVE-2026-9999"
        assert cve_context["operator_approved"] is True
        assert cve_context["automatic_tests_started"] is False
        assert queued.params_json["ai_proposal"]["dispatch_mode"] == "queued_not_dispatched"


def test_operator_action_queues_targeted_nuclei_task_but_does_not_dispatch(
    client,
    tmp_path: Path,
    monkeypatch,
) -> None:
    template_dir = tmp_path / "nuclei-templates"
    template_dir.mkdir()
    (template_dir / "CVE-2026-9999.yaml").write_text(
        "id: CVE-2026-9999\ninfo:\n  name: nginx detection\n  severity: critical\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("NUCLEI_TEMPLATES_DIR", str(template_dir))
    engagement_id, run_id = _create_service_run(client)
    with client.app.state.session_factory() as session:
        _seed_nginx_inventory_and_intel(session, engagement_id=engagement_id, run_id=run_id)
        session.commit()

    response = client.post(
        f"/api/v1/runs/{run_id}/cve-intelligence/CVE-2026-9999/queue-test",
        headers={"X-Actor": "operator"},
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["task"]["tool"] == "nuclei"
    assert payload["task"]["status"] == "queued"
    assert payload["task"]["params_json"]["on_demand_cve_intelligence"]["operator_approved"] is True
    assert payload["task"]["params_json"]["on_demand_cve_intelligence"]["automatic_tests_started"] is False
    assert payload["run"]["status"] == "queued"


def test_bounded_nvd_lookup_uses_discovered_product_query(client) -> None:
    engagement_id, run_id = _create_service_run(client)
    with client.app.state.session_factory() as session:
        snapshot = create_inventory_snapshot_record(
            engagement_id=UUID(engagement_id),
            requested_by="operator",
            source_tools=["nmap"],
            observations=[
                {
                    "tool": "nmap",
                    "kind": "inventory",
                    "data": {
                        "hosts": ["10.0.20.14"],
                        "services": [
                            {
                                "host": "10.0.20.14",
                                "port": 22,
                                "protocol": "tcp",
                                "service": "ssh",
                                "product": "OpenSSH",
                                "version": "9.0",
                                "confidence": 0.9,
                            }
                        ],
                        "fingerprints": [{"product": "OpenSSH", "version": "9.0"}],
                    },
                }
            ],
            raw_inputs_json={"run_id": run_id},
        )
        session.add(snapshot)
        session.commit()
        run = session.scalar(select(Run).where(Run.id == UUID(run_id)))
        assert run is not None
        captured_queries = []

        def fake_fetcher(*, url: str, headers: dict, params: dict, timeout: float) -> FeedFetchResult:
            captured_queries.append(params["keywordSearch"])
            return FeedFetchResult(
                status_code=200,
                json_data={
                    "vulnerabilities": [
                        {
                            "cve": {
                                "id": "CVE-2026-12345",
                                "descriptions": [{"lang": "en", "value": "OpenSSH 9.0 critical flaw."}],
                                "metrics": {
                                    "cvssMetricV31": [
                                        {"cvssData": {"baseScore": 9.8}, "baseSeverity": "CRITICAL"}
                                    ]
                                },
                                "references": {"referenceData": [{"url": "https://nvd.nist.gov/vuln/detail/CVE-2026-12345"}]},
                            }
                        }
                    ]
                },
            )

        payload = build_run_cve_intelligence(
            session,
            run=run,
            settings=get_settings(),
            allow_live_nvd=True,
            fetcher=fake_fetcher,
        )

    assert captured_queries == ["OpenSSH 9.0"]
    assert payload["boundary"]["live_nvd_lookup_performed"] is True
    assert payload["rows"][0]["cve_id"] == "CVE-2026-12345"
    assert payload["rows"][0]["cvss_score"] == 9.8
    assert payload["rows"][0]["test_status"] == "informational"
    assert payload["rows"][0]["actions"] == []
