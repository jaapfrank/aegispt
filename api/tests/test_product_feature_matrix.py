from __future__ import annotations

from datetime import UTC, datetime, timedelta
from io import BytesIO
from urllib.parse import urlparse
from uuid import UUID

from pypdf import PdfReader
from sqlalchemy import select

from api.app.models import (
    AgentProposal,
    AgentReasoning,
    CapabilityPack,
    CapabilityPackDeployment,
    CapabilityPackValidationResult,
    Engagement,
    Finding,
    FindingRemediation,
    Run,
)


def test_adaptive_pack_pipeline_binds_to_run_and_exports_reports_end_to_end(
    inline_client,
    probe_server: str,
) -> None:
    parsed_target = urlparse(probe_server)
    target_host = parsed_target.hostname or "127.0.0.1"

    engagement = inline_client.post(
        "/api/v1/engagements",
        headers={"X-Actor": "matrix-operator"},
        json={
            "name": "Product Feature Matrix",
            "client": "Acme Corp",
            "roe_ref": "ROE-2026-250",
        },
    ).json()

    inline_client.post(
        f"/api/v1/engagements/{engagement['id']}/scope",
        headers={"X-Actor": "matrix-operator"},
        json={
            "allowlist_json": {"urls": [probe_server], "hosts": [target_host]},
            "denylist_json": {},
        },
    )

    inventory = inline_client.post(
        "/api/v1/inventory/runs",
        headers={"X-Actor": "inventory-operator"},
        json={
            "engagement_id": engagement["id"],
            "source_tools": ["httpx"],
            "observations": [
                {
                    "tool": "httpx",
                    "kind": "inventory",
                    "data": {
                        "hosts": [target_host],
                        "urls": [probe_server],
                        "endpoints": [
                            {
                                "url": probe_server,
                                "methods": ["GET"],
                                "status_code": 200,
                                "title": "Probe",
                            }
                        ],
                        "technologies": [
                            {"name": "Probe Service", "vendor": "AegisPT", "confidence": 0.9}
                        ],
                        "auth_mechanisms": [],
                        "fingerprints": [
                            {"vendor": "AegisPT", "product": "Probe Service", "version": "1.0"}
                        ],
                        "confidence": 0.9,
                    },
                }
            ],
        },
    ).json()

    intel = inline_client.post(
        "/api/v1/threat-intel/ingest",
        headers={"X-Actor": "intel-operator"},
        json={
            "records": [
                {
                    "source": "internal-knowledge",
                    "advisory_id": "AEGIS-UI-0001",
                    "title": "Probe service hardening guidance",
                    "summary": "Baseline HTTP profiling and adaptive review are relevant for this probe target.",
                    "affected_products": ["probe service"],
                    "product_match_hints": ["probe service", "aegispt"],
                    "attack_surface_type": "web",
                    "suggested_test_patterns": ["httpx", "nuclei", "playwright"],
                    "confidence": 0.8,
                    "severity": "medium",
                }
            ]
        },
    ).json()[0]

    relevance = inline_client.post(
        "/api/v1/relevance/analyze",
        headers={"X-Actor": "planner"},
        json={
            "engagement_id": engagement["id"],
            "inventory_snapshot_id": inventory["id"],
            "threat_intel_ids": [intel["id"]],
            "include_prior_findings": False,
        },
    ).json()

    pack = inline_client.post(
        "/api/v1/packs/generate",
        headers={"X-Actor": "planner"},
        json={
            "engagement_id": engagement["id"],
            "relevance_decision_id": relevance["id"],
            "name": "matrix-pack",
        },
    ).json()

    validation = inline_client.post(
        f"/api/v1/packs/{pack['id']}/validate",
        headers={"X-Actor": "validator"},
    ).json()
    assert validation["status"] == "passed"

    approved_pack = inline_client.post(
        f"/api/v1/packs/{pack['id']}/approve?notes=matrix",
        headers={"X-Actor": "approver"},
    ).json()
    assert approved_pack["status"] == "approved"

    deployment = inline_client.post(
        f"/api/v1/packs/{pack['id']}/deploy",
        headers={"X-Actor": "deployer"},
        json={
            "engagement_id": engagement["id"],
            "deployment_target": "engagement-runtime",
            "run_profile_name": "passive-web-baseline",
            "notes": "matrix deployment",
        },
    ).json()
    assert deployment["status"] == "deployed"

    run = inline_client.post(
        f"/api/v1/engagements/{engagement['id']}/runs",
        headers={"X-Actor": "operator"},
        json={
            "profile_name": "passive-web-baseline",
            "source_inventory_snapshot_id": inventory["id"],
            "configuration_json": {
                "assessment_type": "Website / Web App",
                "test_profile": "Standard",
                "execution_profile": "passive-web-baseline",
                "targets": {"urls": [probe_server]},
                "modules": {
                    "discovery": True,
                    "web_crawling": True,
                    "content_discovery": True,
                    "nuclei_checks": True,
                },
                "safety": {
                    "rate_limit_rps": 1,
                    "concurrency": 1,
                    "time_budget_minutes": 30,
                    "active_checks": "passive-only",
                    "adaptive_generation": True,
                    "max_validation_depth": "light",
                },
                "eta": {
                    "estimated_total_minutes": 30,
                    "estimated_impact": "low",
                    "confidence": "medium",
                },
            },
        },
    ).json()

    assert run["status"] == "queued"
    assert run["pack_binding"] is not None
    assert run["pack_binding"]["pack_id"] == pack["id"]
    assert run["pack_binding"]["pack_version"] == approved_pack["version"]

    dispatch = inline_client.post(
        f"/api/v1/runs/{run['id']}/dispatch",
        headers={"X-Actor": "dispatcher"},
    ).json()
    hydrated_run = dispatch["run"]
    assert hydrated_run["status"] in {"completed", "completed_with_errors"}

    reports = inline_client.get(
        f"/api/v1/runs/{run['id']}/reports",
        headers={"X-Actor": "operator"},
    ).json()
    assert {item["variant"] for item in reports} == {
        "summary",
        "technical",
        "compliance",
        "retest",
    }
    technical = next(item for item in reports if item["variant"] == "technical")
    assert technical["export_paths"]["pdf"].endswith("format=pdf&variant=technical")
    assert technical["download_names"]["pdf"].endswith(".pdf")
    assert technical["download_names"]["html"].endswith(".html")
    assert technical["download_names"]["markdown"].endswith(".md")

    markdown = inline_client.get(
        f"/api/v1/runs/{run['id']}/report?format=markdown&variant=technical",
        headers={"X-Actor": "operator"},
    )
    html = inline_client.get(
        f"/api/v1/runs/{run['id']}/report?format=html&variant=technical",
        headers={"X-Actor": "operator"},
    )
    pdf = inline_client.get(
        f"/api/v1/runs/{run['id']}/report?format=pdf&variant=technical",
        headers={"X-Actor": "operator"},
    )

    assert markdown.status_code == 200
    assert markdown.headers["content-disposition"].endswith('-technical.md"')
    assert "AegisPT Run Report" in markdown.text

    assert html.status_code == 200
    assert html.headers["content-disposition"].endswith('-technical.html"')
    assert html.headers["content-type"].startswith("text/html")
    assert "<h1>AegisPT Run Report</h1>" in html.text

    assert pdf.status_code == 200
    assert pdf.headers["content-disposition"].endswith('-technical.pdf"')
    assert pdf.headers["content-type"].startswith("application/pdf")
    assert pdf.content.startswith(b"%PDF")
    pdf_reader = PdfReader(BytesIO(pdf.content))
    extracted = "\n".join(page.extract_text() or "" for page in pdf_reader.pages)
    assert "AegisPT Run Report" in extracted

    binding = inline_client.get(
        f"/api/v1/runs/{run['id']}/pack",
        headers={"X-Actor": "operator"},
    ).json()
    assert binding["pack_id"] == pack["id"]
    assert binding["deployment_id"] == deployment["id"]


def test_assessment_pattern_library_is_local_advisory_and_tenant_scoped(client) -> None:
    now = datetime.now(tz=UTC)

    with client.app.state.session_factory() as session:
        engagement = Engagement(
            name="Assessment Pattern Library",
            client="Tenant A",
            tenant_id="tenant-a",
            roe_ref="ROE-PATTERN-1",
            status="active",
        )
        other_engagement = Engagement(
            name="Other Tenant Patterns",
            client="Tenant B",
            tenant_id="tenant-b",
            roe_ref="ROE-PATTERN-2",
            status="active",
        )
        pack = CapabilityPack(
            engagement=engagement,
            name="pattern-adaptive-pack",
            version="2026.04.23",
            status="generated",
            generated_by="planner",
            generation_mode="codex-supervised",
            methodology_tags=["WSTG-CONF"],
            manifest_json={"source": "local-test"},
            provenance_json={"customer_data_exported": False},
        )
        run_one = Run(
            engagement=engagement,
            bound_pack=pack,
            bound_pack_version=pack.version,
            requested_by="operator",
            status="completed",
            configuration_json={"targets": {"urls": ["https://app.example.test"]}},
            created_at=now - timedelta(days=7),
            updated_at=now - timedelta(days=7),
        )
        run_two = Run(
            engagement=engagement,
            bound_pack=pack,
            bound_pack_version=pack.version,
            requested_by="operator",
            status="completed",
            configuration_json={"targets": {"urls": ["https://app.example.test"]}},
            created_at=now - timedelta(days=1),
            updated_at=now - timedelta(days=1),
        )
        other_run = Run(
            engagement=other_engagement,
            requested_by="operator",
            status="completed",
            configuration_json={},
        )
        session.add_all([engagement, other_engagement, pack, run_one, run_two, other_run])
        session.flush()

        recurring_one = Finding(
            run=run_one,
            source_pack=pack,
            source_pack_version=pack.version,
            title="Admin endpoint exposed",
            severity="high",
            target_id="https://app.example.test/admin",
            evidence_ref="artifact://patterns/admin-1",
            status="open",
            summary="Initial observation.",
            methodology_tags=["WSTG-CONF-05"],
            created_at=now - timedelta(days=7),
            updated_at=now - timedelta(days=7),
        )
        recurring_two = Finding(
            run=run_two,
            source_pack=pack,
            source_pack_version=pack.version,
            title="Admin endpoint exposed",
            severity="high",
            target_id="https://app.example.test/admin",
            evidence_ref="artifact://patterns/admin-2",
            status="open",
            summary="Still observable in the later run.",
            methodology_tags=["WSTG-CONF-05"],
            created_at=now - timedelta(days=1),
            updated_at=now - timedelta(days=1),
        )
        remediated_one = Finding(
            run=run_one,
            source_pack=pack,
            source_pack_version=pack.version,
            title="Missing security header",
            severity="medium",
            target_id="https://app.example.test",
            evidence_ref="artifact://patterns/header-1",
            status="open",
            created_at=now - timedelta(days=7),
            updated_at=now - timedelta(days=7),
        )
        remediated_two = Finding(
            run=run_two,
            source_pack=pack,
            source_pack_version=pack.version,
            title="Missing security header",
            severity="medium",
            target_id="https://app.example.test",
            evidence_ref="artifact://patterns/header-2",
            status="resolved",
            created_at=now - timedelta(days=1),
            updated_at=now - timedelta(days=1),
        )
        new_finding = Finding(
            run=run_two,
            source_pack=pack,
            source_pack_version=pack.version,
            title="Verbose error response",
            severity="low",
            target_id="https://app.example.test/error",
            evidence_ref="artifact://patterns/error",
            status="open",
            created_at=now - timedelta(days=1),
            updated_at=now - timedelta(days=1),
        )
        other_finding = Finding(
            run=other_run,
            title="Tenant B only finding",
            severity="critical",
            target_id="https://other.example.test",
            evidence_ref="artifact://patterns/other",
            status="open",
        )
        session.add_all([recurring_one, recurring_two, remediated_one, remediated_two, new_finding, other_finding])
        session.flush()

        reasoning = AgentReasoning(
            run=run_two,
            reasoning_type="analysis",
            status="succeeded",
            context_snapshot_json={"run_id": str(run_two.id)},
            provider="deterministic-test",
            metadata_json={"dispatches_work": False},
        )
        session.add_all(
            [
                FindingRemediation(
                    finding_id=remediated_two.id,
                    state="verified",
                    notes="Proof-of-resolution reviewed.",
                    owner="app-team",
                    created_by="portfolio-owner",
                    updated_by="portfolio-owner",
                ),
                CapabilityPackValidationResult(
                    pack=pack,
                    validator="local-test",
                    executed_by="validator",
                    status="failed",
                    summary="Fixture blocker for advisory signal coverage.",
                ),
                reasoning,
            ]
        )
        session.flush()
        session.add(
            AgentProposal(
                run=run_two,
                agent_reasoning=reasoning,
                proposed_tool="httpx",
                proposed_target="https://app.example.test",
                proposed_params_json={"mode": "headers"},
                risk_tier="passive",
                status="approved",
                approved_by="reviewer",
                approved_at=now,
            )
        )
        session.commit()
        engagement_id = str(engagement.id)
        pack_id = str(pack.id)

    response = client.get(
        f"/api/v1/engagements/{engagement_id}/assessment-patterns",
        headers={"X-Tenant-ID": "tenant-a"},
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["mode"] == "local_advisory"
    assert payload["data_scope"]["tenant_id"] == "tenant-a"
    assert payload["data_scope"]["cross_tenant_pattern_sharing"] is False
    assert payload["boundary"]["external_model_training_performed"] is False
    assert payload["boundary"]["customer_data_exported"] is False
    assert payload["boundary"]["risk_reduction_claimed"] is False
    assert payload["summary"]["risk_posture_counts"] == {
        "persistent": 1,
        "remediated": 1,
        "recurring": 2,
        "new": 1,
    }

    patterns_by_title = {pattern["title"]: pattern for pattern in payload["patterns"]}
    assert patterns_by_title["Admin endpoint exposed"]["posture_signal"] == "persistent"
    assert patterns_by_title["Admin endpoint exposed"]["recurrence_signal"] == "recurring"
    assert patterns_by_title["Missing security header"]["posture_signal"] == "remediated"
    assert "does not guarantee risk reduction" in patterns_by_title["Missing security header"]["advisory_note"]
    assert patterns_by_title["Verbose error response"]["posture_signal"] == "new"
    assert "Tenant B only finding" not in patterns_by_title

    pack_summary = next(item for item in payload["pack_effectiveness"]["packs"] if item["pack_id"] == pack_id)
    assert pack_summary["advisory_only"] is True
    assert pack_summary["generated_finding_count"] == 5
    assert pack_summary["proposal_outcomes"]["approved"] == 1
    assert "validation_blockers_present" in pack_summary["quality_signals"]
    assert payload["pack_effectiveness"]["automatic_pack_promotion_performed"] is False
    assert payload["pack_effectiveness"]["automatic_pack_deployment_performed"] is False
    assert payload["pack_effectiveness"]["runtime_binding_changed"] is False

    denied = client.get(
        f"/api/v1/engagements/{engagement_id}/assessment-patterns",
        headers={"X-Tenant-ID": "tenant-b"},
    )
    assert denied.status_code == 404

    with client.app.state.session_factory() as session:
        stored_pack = session.get(CapabilityPack, UUID(pack_id))
        assert stored_pack is not None
        assert stored_pack.status == "generated"
        deployments = session.scalars(
            select(CapabilityPackDeployment).where(CapabilityPackDeployment.pack_id == UUID(pack_id))
        ).all()
        assert deployments == []


def test_multi_agent_orchestration_primitives_remain_inactive_and_provenance_shaped(client) -> None:
    engagement = client.post(
        "/api/v1/engagements",
        headers={"X-Actor": "matrix-operator"},
        json={"name": "Multi-Agent Prep", "client": "Acme Corp", "roe_ref": "ROE-MA-1"},
    ).json()

    client.post(
        f"/api/v1/engagements/{engagement['id']}/scope",
        headers={"X-Actor": "matrix-operator"},
        json={
            "allowlist_json": {"urls": ["https://app.example.test"]},
            "denylist_json": {},
        },
    )

    run = client.post(
        f"/api/v1/engagements/{engagement['id']}/runs",
        headers={"X-Actor": "operator"},
        json={
            "profile_name": "passive-web-baseline",
            "configuration_json": {
                "assessment_type": "Website / Web App",
                "targets": {"urls": ["https://app.example.test"]},
                "multi_agent_orchestration": {
                    "activate": True,
                    "hidden_agents": True,
                    "autonomous_tool_execution": True,
                },
            },
        },
    ).json()

    readiness = run["multi_agent_orchestration"]
    assert readiness["status"] == "inactive_preparation"
    assert readiness["active"] is False
    assert readiness["runtime_enabled"] is False
    assert readiness["hidden_agents_enabled"] is False
    assert readiness["distributed_offensive_runtime_enabled"] is False
    assert readiness["autonomous_tool_execution_enabled"] is False
    assert readiness["uncontrolled_worker_coordination_enabled"] is False
    assert readiness["scope_broadening_handoffs_allowed"] is False
    assert readiness["operator_activation_required"] is True
    assert readiness["kill_switch_required"] is True
    assert readiness["stricter_than_single_agent_planning"] is True
    assert readiness["forbidden_activation_request"] == {
        "present": True,
        "blocked": True,
        "accepted": False,
        "requested_keys": ["activate", "autonomous_tool_execution", "hidden_agents"],
        "reason": (
            "Multi-agent orchestration activation is not implemented in this baseline; "
            "configuration is treated as non-executable planning input only."
        ),
    }

    role_ids = {role["role_id"] for role in readiness["roles"]}
    assert {
        "mission_lead",
        "inventory_surface",
        "threat_relevance",
        "capability_forge",
        "execution_planner",
        "evidence_qa",
        "reporting_assurance",
        "safety_policy",
    } <= role_ids
    assert all(role["activation_state"] == "inactive_planning" for role in readiness["roles"])
    assert all(handoff["activation_state"] == "inactive_planning" for handoff in readiness["allowed_handoff_types"])
    assert all(check["blocking_default"] is True for check in readiness["policy_checks"])

    provenance_shape = readiness["provenance_metadata_shape"]
    assert {
        "agent_role_id",
        "handoff_type",
        "source_run_id",
        "source_task_ids",
        "source_evidence_refs",
        "policy_check_ids",
        "operator_actor",
        "worker_identity",
        "created_at",
    } <= set(provenance_shape["required_fields"])
    assert "No multi-agent records are created" in provenance_shape["write_boundary"]
    assert readiness["boundary"]["creates_tasks"] is False
    assert readiness["boundary"]["dispatches_work"] is False
    assert readiness["boundary"]["validates_or_deploys_packs"] is False
    assert readiness["boundary"]["binds_runtime_packs"] is False
    assert readiness["boundary"]["changes_worker_runtime"] is False
