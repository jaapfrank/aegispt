from __future__ import annotations

import hashlib
import json
import time
from datetime import UTC, datetime
from threading import Thread
from uuid import UUID

from sqlalchemy import select

from api.app.config import Settings, get_settings
from api.app.models import (
    Engagement,
    EvidenceArtifact as EvidenceArtifactRecord,
    Finding,
    FindingAiEnrichment,
    InventorySnapshot,
    Run,
    Task,
    ThreatIntelRecord,
    ToolExecution,
)
from api.app.services.ai_enrichment import (
    FindingEnrichmentResult,
    build_finding_enrichment_provider,
    enrich_finding_async,
    build_mission_guidance_for_run,
    store_ai_enrichment_for_finding,
)
from workers.orchestration.findings import store_findings
from workers.runners.base.contracts import EvidenceArtifact as ContractEvidenceArtifact


class TimeoutFindingEnrichmentProvider:
    name = "timeout-test"

    def enrich(self, finding: Finding) -> FindingEnrichmentResult:
        raise TimeoutError("simulated enrichment timeout")


class ForbiddenFindingEnrichmentProvider:
    name = "forbidden-test"

    def enrich(self, finding: Finding) -> FindingEnrichmentResult:
        return FindingEnrichmentResult(
            business_impact="This would create customer-facing risk if reachable.",
            technical_context="The stored evidence should be reviewed by an operator.",
            remediation_narrative="Run sqlmap --os-shell against the target to prove impact.",
            metadata={"review_note": "provider returned unsafe operator guidance"},
        )


class FailingMissionGuidanceProvider:
    name = "failing-guidance"

    def refine(self, guidance: dict, run: Run) -> dict:
        raise TimeoutError("simulated mission guidance timeout")


def _seed_finding(
    client,
    *,
    severity: str = "medium",
    title: str = "Missing security header",
    target_id: str = "https://app.example.test",
    evidence_ref: str = "artifact://headers/missing-security-header",
    status: str = "open",
    summary: str = "The target is missing a hardening header.",
    methodology_tags: list[str] | None = None,
    wstg_id: str | None = None,
    asvs_reference: str | None = None,
    control_family: str | None = None,
) -> str:
    with client.app.state.session_factory() as session:
        finding = Finding(
            title=title,
            severity=severity,
            target_id=target_id,
            evidence_ref=evidence_ref,
            status=status,
            summary=summary,
            methodology_tags=list(methodology_tags or []),
            wstg_id=wstg_id,
            asvs_reference=asvs_reference,
            control_family=control_family,
        )
        session.add(finding)
        session.commit()
        return str(finding.id)


def _seed_contextual_finding(client) -> str:
    with client.app.state.session_factory() as session:
        engagement = Engagement(
            name="Contextual Remediation",
            client="Acme Corp",
            roe_ref="ROE-CONTEXTUAL",
        )
        session.add(engagement)
        session.flush()

        inventory = InventorySnapshot(
            engagement_id=engagement.id,
            requested_by="context-fixture",
            source_tools_json=["httpx"],
            normalized_inventory_json={
                "hosts": ["portal.example.test"],
                "services": [
                    {
                        "host": "portal.example.test",
                        "port": 443,
                        "protocol": "tcp",
                        "service": "https",
                        "product": "nginx",
                        "version": "1.25",
                        "confidence": 0.92,
                    }
                ],
                "http_endpoints": [
                    {
                        "url": "https://portal.example.test/admin",
                        "methods": ["GET"],
                        "status_code": 200,
                        "title": "Admin Portal",
                        "confidence": 0.9,
                    }
                ],
                "technologies": [
                    {
                        "name": "nginx",
                        "vendor": "nginx",
                        "version": "1.25",
                        "confidence": 0.82,
                    }
                ],
                "confidence_score": 0.9,
            },
            summary_json={
                "host_count": 1,
                "service_count": 1,
                "endpoint_count": 1,
                "technology_count": 1,
                "confidence_score": 0.9,
            },
            environment_notes_json=["Admin portal is internet-facing in the approved scope."],
            assumptions_json=["Remediation guidance must remain review-only."],
            confidence_score=0.9,
        )
        session.add(inventory)
        session.flush()

        run = Run(
            engagement_id=engagement.id,
            source_inventory_snapshot_id=inventory.id,
            requested_by="context-fixture",
            status="completed",
            configuration_json={
                "targets": {"urls": ["https://portal.example.test/admin"]},
                "safety": {"active_checks": "passive-only"},
            },
        )
        session.add(run)
        session.flush()

        threat_record = ThreatIntelRecord(
            source="cisa-kev",
            advisory_id="CVE-2026-0001",
            title="Portal admin exposure",
            summary="Local approved-feed record for contextual prioritization.",
            affected_products_json=["portal"],
            affected_versions_json=[],
            product_match_hints_json=["CVE-2026-0001", "portal"],
            architecture_hints_json=[],
            attack_surface_type="web",
            suggested_test_patterns_json=["local-cache-kev-review"],
            confidence_score=0.9,
            severity="known_exploited",
            references_json=["https://www.cisa.gov/known-exploited-vulnerabilities-catalog"],
            published_at=datetime(2026, 4, 1, tzinfo=UTC),
            advisory_updated_at=datetime(2026, 4, 20, tzinfo=UTC),
            normalization_status="normalized",
            metadata_json={
                "feed_type": "cisa_kev",
                "feed_name": "Unit Test KEV",
                "feed_cached_at": datetime(2026, 4, 20, tzinfo=UTC).isoformat(),
                "stale_after_days": 30,
                "badge_types": ["kev"],
                "approved_feed": True,
                "external_lookup_performed": False,
                "downloads_exploits": False,
            },
        )
        session.add(threat_record)

        finding = Finding(
            run_id=run.id,
            source_inventory_snapshot_id=inventory.id,
            title="CVE-2026-0001 Missing X-Frame-Options Header",
            severity="high",
            target_id="https://portal.example.test/admin",
            evidence_ref="artifact://headers/portal-x-frame-options",
            status="open",
            summary="The admin portal omitted a browser hardening header and references CVE-2026-0001.",
            methodology_tags=["configuration", "CVE-2026-0001"],
            wstg_id="WSTG-CONF-07",
            wstg_version="v4.2",
            control_family="configuration",
        )
        session.add(finding)
        session.commit()
        return str(finding.id)


def _create_guided_run(client) -> dict:
    engagement = client.post(
        "/api/v1/engagements",
        headers={"X-Actor": "mission-guidance-operator"},
        json={
            "name": "AI Mission Guidance",
            "client": "Acme Corp",
            "roe_ref": "ROE-AI-GUIDANCE",
        },
    ).json()

    client.post(
        f"/api/v1/engagements/{engagement['id']}/scope",
        headers={"X-Actor": "mission-guidance-operator"},
        json={
            "allowlist_json": {"urls": ["https://app.example.test"]},
            "denylist_json": {"domains": ["out-of-scope.example.test"]},
        },
    )

    inventory = client.post(
        "/api/v1/inventory/runs",
        headers={"X-Actor": "inventory-operator"},
        json={
            "engagement_id": engagement["id"],
            "source_tools": ["guidance-fixture"],
            "observations": [
                {
                    "tool": "guidance-fixture",
                    "kind": "inventory",
                    "data": {
                        "hosts": ["app.example.test"],
                        "services": [
                            {
                                "host": "app.example.test",
                                "port": 443,
                                "protocol": "tcp",
                                "service": "https",
                                "confidence": 0.9,
                            }
                        ],
                        "endpoints": [
                            {
                                "url": "https://app.example.test",
                                "methods": ["GET"],
                                "status_code": 200,
                                "title": "App",
                                "confidence": 0.88,
                            }
                        ],
                        "confidence": 0.9,
                    },
                }
            ],
        },
    ).json()

    response = client.post(
        f"/api/v1/engagements/{engagement['id']}/runs",
        headers={"X-Actor": "mission-guidance-operator"},
        json={
            "profile_name": "passive-web-baseline",
            "source_inventory_snapshot_id": inventory["id"],
            "configuration_json": {
                "assessment_type": "Website / Web App",
                "test_profile": "Standard",
                "execution_profile": "passive-web-baseline",
                "targets": {"urls": ["https://app.example.test"]},
                "safety": {
                    "active_checks": "passive-only",
                    "max_validation_depth": "light",
                    "concurrency": 1,
                    "rate_limit_rps": 1,
                    "time_budget_minutes": 20,
                },
            },
        },
    )
    assert response.status_code == 201
    return response.json()


def test_ai_finding_enrichment_is_disabled_by_default_and_theater_falls_back(client) -> None:
    assert Settings().ai_finding_enrichment_enabled is False
    finding_id = _seed_finding(client)

    with client.app.state.session_factory() as session:
        finding = session.get(Finding, UUID(finding_id))
        result = store_ai_enrichment_for_finding(
            session=session,
            finding=finding,
            settings=Settings(ai_finding_enrichment_enabled=False),
        )
        session.commit()
        stored = session.scalar(
            select(FindingAiEnrichment).where(FindingAiEnrichment.finding_id == UUID(finding_id))
        )

    assert result is None
    assert stored is None

    theater_response = client.get(f"/api/v1/findings/{finding_id}/theater")
    assert theater_response.status_code == 200
    theater = theater_response.json()
    assert theater["ai_enrichment"] == {
        "status": "disabled",
        "available": False,
        "label": "Enrichment unavailable",
    }
    assert theater["business_impact"] == (
        "May enable follow-on abuse, weakened trust boundaries, or meaningful operational disruption."
    )
    assert theater["technical_details"].startswith("Target https://app.example.test produced evidence")


def test_store_findings_auto_queues_background_ai_enrichment(client, monkeypatch) -> None:
    monkeypatch.setattr(
        "workers.orchestration.findings.get_settings",
        lambda: Settings(ai_finding_enrichment_enabled=True, ai_finding_enrichment_provider="deterministic"),
    )
    data = (
        json.dumps(
            {
                "template-id": "cves/2026/CVE-2026-0002",
                "matched-at": "https://app.example.test",
                "info": {"name": "Outdated component", "severity": "high"},
            }
        )
        + "\n"
    ).encode()

    with client.app.state.session_factory() as session:
        engagement = Engagement(name="Auto Enrichment", client="Acme Corp", roe_ref="ROE-AI-123")
        session.add(engagement)
        session.flush()
        run = Run(
            engagement_id=engagement.id,
            requested_by="pytest",
            status="running",
            configuration_json={"targets": {"urls": ["https://app.example.test"]}},
        )
        session.add(run)
        session.flush()
        task = Task(run_id=run.id, tool="nuclei", target_id="https://app.example.test", params_json={})
        session.add(task)
        session.flush()
        execution = ToolExecution(
            task_id=task.id,
            runner_digest="pytest",
            tool_version="nuclei 3.2.0",
            exit_code=0,
        )
        session.add(execution)
        session.flush()
        artifact_record = EvidenceArtifactRecord(
            tool_execution_id=execution.id,
            kind="nuclei-jsonl",
            uri="artifact://pytest/nuclei-results.jsonl",
            sha256=hashlib.sha256(data).hexdigest(),
            redaction_state="none",
            metadata_json={},
        )
        session.add(artifact_record)
        session.flush()
        artifact = ContractEvidenceArtifact(
            name="nuclei-results.jsonl",
            content_type="application/jsonl",
            data=data,
            kind="nuclei-jsonl",
        )

        started = time.monotonic()
        findings = store_findings(session=session, task=task, artifact_pairs=[(artifact, artifact_record)])
        elapsed = time.monotonic() - started
        assert len(findings) == 1
        assert elapsed < 0.5
        enrichment = session.scalar(
            select(FindingAiEnrichment).where(FindingAiEnrichment.finding_id == findings[0].id)
        )
        assert enrichment is not None
        assert enrichment.status == "enriching"
        assert findings[0].severity == "high"
        assert findings[0].evidence_ref == "artifact://pytest/nuclei-results.jsonl"
        finding_id = findings[0].id
        session.commit()

    deadline = time.monotonic() + 5
    while True:
        with client.app.state.session_factory() as session:
            enrichment = session.scalar(
                select(FindingAiEnrichment).where(FindingAiEnrichment.finding_id == finding_id)
            )
            finding = session.get(Finding, finding_id)
            if enrichment is not None and enrichment.status == "succeeded":
                break
        if time.monotonic() >= deadline:
            raise AssertionError("background finding enrichment did not complete")
        time.sleep(0.05)

    assert enrichment.provider == "deterministic"
    assert enrichment.business_impact
    assert enrichment.remediation_narrative
    assert finding.severity == "high"
    assert finding.evidence_ref == "artifact://pytest/nuclei-results.jsonl"


def test_enrich_finding_async_records_unavailable_when_provider_missing(client) -> None:
    finding_id = _seed_finding(client)
    with client.app.state.session_factory() as session:
        finding = session.get(Finding, UUID(finding_id))
        enrichment = enrich_finding_async(
            finding.id,
            session,
            settings=Settings(ai_finding_enrichment_enabled=True, ai_finding_enrichment_provider="disabled"),
        )
        session.commit()

    assert enrichment is not None
    assert enrichment.status == "unavailable"
    assert enrichment.failure_reason == "No AI provider is configured for finding enrichment."


def test_finding_ai_enrich_endpoint_requeues_stale_unavailable_enrichment(client) -> None:
    finding_id = _seed_finding(client)
    client.app.dependency_overrides[get_settings] = lambda: Settings(
        ai_finding_enrichment_enabled=True,
        ai_finding_enrichment_provider="deterministic",
    )
    try:
        with client.app.state.session_factory() as session:
            finding = session.get(Finding, UUID(finding_id))
            session.add(
                FindingAiEnrichment(
                    finding_id=finding.id,
                    status="unavailable",
                    provider="disabled",
                    failure_reason="No AI provider is configured for finding enrichment.",
                    metadata_json={"unavailable_at": datetime.now(tz=UTC).isoformat()},
                )
            )
            session.commit()

        response = client.post(
            f"/api/v1/findings/{finding_id}/ai-enrich",
            headers={"X-Actor": "finding-ai-operator"},
        )
        assert response.status_code == 200
        payload = response.json()
        assert payload["status"] == "enriching"
        assert payload["available"] is False
        assert payload["provider"] == "deterministic"
        assert payload["label"] == "Enriching"

        with client.app.state.session_factory() as session:
            stored = session.scalar(
                select(FindingAiEnrichment).where(FindingAiEnrichment.finding_id == UUID(finding_id))
            )
            assert stored is not None
            assert stored.provider == "deterministic"
            assert stored.status in {"enriching", "succeeded"}
    finally:
        client.app.dependency_overrides.pop(get_settings, None)


def test_run_events_emit_finding_enriched_event(client) -> None:
    with client.app.state.session_factory() as session:
        engagement = Engagement(name="Enriched Event", client="Acme Corp", roe_ref="ROE-EVENT")
        session.add(engagement)
        session.flush()
        run = Run(engagement_id=engagement.id, requested_by="pytest", status="running", configuration_json={})
        session.add(run)
        session.flush()
        finding = Finding(
            run_id=run.id,
            title="Missing header",
            severity="medium",
            target_id="https://app.example.test",
            evidence_ref="artifact://pytest/header",
            status="open",
            summary="Header was missing.",
        )
        session.add(finding)
        session.flush()
        enrichment = FindingAiEnrichment(
            finding_id=finding.id,
            status="enriching",
            provider="deterministic",
            metadata_json={"queued_at": datetime.now(tz=UTC).isoformat()},
        )
        session.add(enrichment)
        run_id = run.id
        finding_id = finding.id
        session.commit()

    def complete_enrichment() -> None:
        time.sleep(0.2)
        with client.app.state.session_factory() as session:
            enrichment = session.scalar(
                select(FindingAiEnrichment).where(FindingAiEnrichment.finding_id == finding_id)
            )
            enrichment.status = "succeeded"
            enrichment.business_impact = "Business impact is now available."
            enrichment.technical_context = "Technical context is now available."
            enrichment.remediation_narrative = "Remediation narrative is now available."
            session.commit()

    Thread(target=complete_enrichment, daemon=True).start()

    with client.stream(
        "GET",
        f"/api/v1/runs/{run_id}/events?poll_interval_seconds=0.1&max_events=2",
    ) as response:
        assert response.status_code == 200
        payload_lines = []
        saw_enriched_event = False
        for line in response.iter_lines():
            payload_lines.append(line)
            if line.startswith("event: finding.enriched"):
                saw_enriched_event = True
            elif saw_enriched_event and line.startswith("data: "):
                break

    payload = "\n".join(payload_lines)
    assert "event: run.snapshot" in payload
    assert "event: finding.enriched" in payload
    assert str(finding_id) in payload


def test_ai_finding_enrichment_success_stores_additive_copy_and_theater_prefers_it(client) -> None:
    finding_id = _seed_finding(client, severity="high")

    with client.app.state.session_factory() as session:
        finding = session.get(Finding, UUID(finding_id))
        original = {
            "severity": finding.severity,
            "status": finding.status,
            "evidence_ref": finding.evidence_ref,
            "summary": finding.summary,
        }
        enrichment = store_ai_enrichment_for_finding(
            session=session,
            finding=finding,
            settings=Settings(
                ai_finding_enrichment_enabled=True,
                ai_finding_enrichment_provider="deterministic",
            ),
        )
        session.commit()

        assert enrichment is not None
        assert enrichment.status == "succeeded"
        assert enrichment.provider == "deterministic"
        assert enrichment.business_impact is not None
        assert enrichment.technical_context is not None
        assert enrichment.remediation_narrative is not None
        assert {
            "severity": finding.severity,
            "status": finding.status,
            "evidence_ref": finding.evidence_ref,
            "summary": finding.summary,
        } == original

    theater_response = client.get(f"/api/v1/findings/{finding_id}/theater")
    assert theater_response.status_code == 200
    theater = theater_response.json()
    assert theater["finding"]["severity"] == "high"
    assert theater["finding"]["status"] == "open"
    assert theater["finding"]["evidence_ref"] == "artifact://headers/missing-security-header"
    assert theater["ai_enrichment"]["available"] is True
    assert theater["ai_enrichment"]["provider"] == "deterministic"
    contextual = theater["ai_enrichment"]["contextual_intelligence"]
    assert contextual["available"] is True
    assert contextual["boundaries"]["automatic_exploitation"] is False
    assert contextual["boundaries"]["destructive_steps"] is False
    assert contextual["boundaries"]["mutates_canonical_finding"] is False
    assert theater["business_impact"] == theater["ai_enrichment"]["business_impact"]
    assert theater["technical_details"] == theater["ai_enrichment"]["technical_context"]
    assert theater["remediation"]["ai_narrative"] == theater["ai_enrichment"]["remediation_narrative"]


def test_contextual_remediation_intelligence_is_grounded_in_inventory_and_threat_intel(client) -> None:
    finding_id = _seed_contextual_finding(client)

    with client.app.state.session_factory() as session:
        finding = session.get(Finding, UUID(finding_id))
        original = {
            "severity": finding.severity,
            "status": finding.status,
            "evidence_ref": finding.evidence_ref,
            "summary": finding.summary,
        }
        enrichment = store_ai_enrichment_for_finding(
            session=session,
            finding=finding,
            settings=Settings(
                ai_finding_enrichment_enabled=True,
                ai_finding_enrichment_provider="deterministic",
            ),
        )
        session.commit()
        metadata = dict(enrichment.metadata_json or {})

    contextual = metadata["contextual_intelligence"]
    assert contextual["status"] == "grounded"
    assert "finding.evidence_ref" in contextual["evidence_basis"]["grounding"]
    assert "inventory_snapshot.normalized_inventory_json" in contextual["evidence_basis"]["grounding"]
    assert "local_threat_intel_cache.badges" in contextual["evidence_basis"]["grounding"]
    assert contextual["environment_context"]["available"] is True
    assert contextual["environment_context"]["matched_target"]["direct_match"] is True
    assert contextual["threat_intel_context"]["available"] is True
    assert contextual["threat_intel_context"]["badges"][0]["label"] == "KEV CVE-2026-0001"
    assert contextual["exploitability"]["confidence"] == "high"
    assert contextual["exploitability"]["automatic_exploitation"] is False
    assert contextual["boundaries"]["credential_abuse_guidance"] is False
    assert any("observed environment surface" in item for item in contextual["remediation"]["immediate_actions"])
    assert any("single-finding retest" in item for item in contextual["remediation"]["verification_steps"])

    theater_response = client.get(f"/api/v1/findings/{finding_id}/theater")
    assert theater_response.status_code == 200
    theater_context = theater_response.json()["ai_enrichment"]["contextual_intelligence"]
    assert theater_context["environment_context"]["matched_target"]["endpoints"][0]["url"] == (
        "https://portal.example.test/admin"
    )

    with client.app.state.session_factory() as session:
        finding = session.get(Finding, UUID(finding_id))
        assert {
            "severity": finding.severity,
            "status": finding.status,
            "evidence_ref": finding.evidence_ref,
            "summary": finding.summary,
        } == original


def test_contextual_remediation_intelligence_labels_sparse_evidence_as_uncertain(client) -> None:
    finding_id = _seed_finding(
        client,
        severity="info",
        title="Analyst-created placeholder finding",
        evidence_ref="",
        summary="",
        methodology_tags=[],
    )

    with client.app.state.session_factory() as session:
        finding = session.get(Finding, UUID(finding_id))
        store_ai_enrichment_for_finding(
            session=session,
            finding=finding,
            settings=Settings(
                ai_finding_enrichment_enabled=True,
                ai_finding_enrichment_provider="deterministic",
            ),
        )
        session.commit()

    theater_response = client.get(f"/api/v1/findings/{finding_id}/theater")
    assert theater_response.status_code == 200
    contextual = theater_response.json()["ai_enrichment"]["contextual_intelligence"]
    assert contextual["status"] == "unsupported_or_uncertain"
    assert contextual["evidence_basis"]["evidence_available"] is False
    assert contextual["exploitability"]["label"] == "unsupported-or-uncertain"
    assert contextual["exploitability"]["confidence"] == "review"
    assert contextual["exploitability"]["unsupported_or_uncertain"] is True
    assert contextual["boundaries"]["automatic_exploitation"] is False


def test_ai_finding_enrichment_failure_is_recorded_without_blocking_theater_fallback(client) -> None:
    finding_id = _seed_finding(client, severity="high")

    with client.app.state.session_factory() as session:
        finding = session.get(Finding, UUID(finding_id))
        enrichment = store_ai_enrichment_for_finding(
            session=session,
            finding=finding,
            settings=Settings(
                ai_finding_enrichment_enabled=True,
                ai_finding_enrichment_provider="timeout-test",
            ),
            provider=TimeoutFindingEnrichmentProvider(),
        )
        session.commit()

        assert enrichment is not None
        assert enrichment.status == "failed"
        assert enrichment.provider == "timeout-test"
        assert "simulated enrichment timeout" in enrichment.failure_reason
        assert finding.severity == "high"
        assert finding.status == "open"
        assert finding.evidence_ref == "artifact://headers/missing-security-header"

    theater_response = client.get(f"/api/v1/findings/{finding_id}/theater")
    assert theater_response.status_code == 200
    theater = theater_response.json()
    assert theater["ai_enrichment"]["available"] is False
    assert theater["ai_enrichment"]["status"] == "failed"
    assert "simulated enrichment timeout" in theater["ai_enrichment"]["failure_reason"]
    assert "contextual_intelligence" not in theater["ai_enrichment"]
    assert theater["business_impact"] == (
        "Could materially affect confidentiality, integrity, or privileged workflows in the assessed environment."
    )
    assert "simulated enrichment timeout" not in theater["technical_details"]


def test_forbidden_exploit_guidance_is_rejected_without_finding_mutation(client) -> None:
    finding_id = _seed_finding(client, severity="critical")

    with client.app.state.session_factory() as session:
        finding = session.get(Finding, UUID(finding_id))
        original = {
            "severity": finding.severity,
            "status": finding.status,
            "evidence_ref": finding.evidence_ref,
            "summary": finding.summary,
        }
        enrichment = store_ai_enrichment_for_finding(
            session=session,
            finding=finding,
            settings=Settings(
                ai_finding_enrichment_enabled=True,
                ai_finding_enrichment_provider="forbidden-test",
            ),
            provider=ForbiddenFindingEnrichmentProvider(),
        )
        session.commit()

        assert enrichment is not None
        assert enrichment.status == "failed"
        assert enrichment.provider == "forbidden-test"
        assert "forbidden exploit guidance detected" in enrichment.failure_reason
        assert {
            "severity": finding.severity,
            "status": finding.status,
            "evidence_ref": finding.evidence_ref,
            "summary": finding.summary,
        } == original

    theater_response = client.get(f"/api/v1/findings/{finding_id}/theater")
    assert theater_response.status_code == 200
    theater = theater_response.json()
    assert theater["ai_enrichment"]["available"] is False
    assert theater["ai_enrichment"]["status"] == "failed"
    assert "contextual_intelligence" not in theater["ai_enrichment"]
    assert "sqlmap" not in theater["technical_details"].lower()


def test_threat_context_maps_supported_finding_without_actor_attribution(client) -> None:
    finding_id = _seed_finding(
        client,
        severity="high",
        title="SQL injection on login form",
        evidence_ref="artifact://zap/login-sql-injection",
        summary="The login form reflected a CWE-89 SQL injection validation payload.",
        methodology_tags=["owasp-wstg", "injection"],
        wstg_id="WSTG-INPV-05",
        control_family="input_validation",
    )

    theater_response = client.get(f"/api/v1/findings/{finding_id}/theater")

    assert theater_response.status_code == 200
    theater = theater_response.json()
    threat_context = theater["threat_context"]
    assert threat_context["available"] is True
    assert threat_context["status"] == "mapped"
    assert threat_context["attribution_boundary"]["claims_actor_attribution"] is False
    assert threat_context["attribution_boundary"]["changes_severity"] is False
    assert threat_context["evidence_basis"]["detected_references"] == ["CWE-89"]
    assert threat_context["mappings"][0]["technique_id"] == "T1190"
    assert threat_context["mappings"][0]["confidence"] == "high"
    assert threat_context["mappings"][0]["actor_attribution"] == "not-assessed"
    assert theater["finding"]["severity"] == "high"
    assert theater["finding"]["status"] == "open"


def test_threat_context_degrades_sparse_finding_without_fabrication(client) -> None:
    finding_id = _seed_finding(
        client,
        severity="info",
        title="Analyst-created placeholder finding",
        evidence_ref="",
        summary="",
        methodology_tags=[],
    )

    theater_response = client.get(f"/api/v1/findings/{finding_id}/theater")

    assert theater_response.status_code == 200
    threat_context = theater_response.json()["threat_context"]
    assert threat_context["available"] is False
    assert threat_context["status"] == "unmapped"
    assert threat_context["reason"] == "insufficient_evidence"
    assert threat_context["mappings"] == []
    assert threat_context["attribution_boundary"]["claims_actor_attribution"] is False


def test_threat_context_marks_configuration_context_as_low_confidence(client) -> None:
    finding_id = _seed_finding(
        client,
        severity="low",
        title="Missing X-Frame-Options header",
        evidence_ref="artifact://headers/x-frame-options",
        summary="The response omitted a browser hardening security header.",
        methodology_tags=["configuration"],
        wstg_id="WSTG-CONF-07",
        control_family="security_headers",
    )

    theater_response = client.get(f"/api/v1/findings/{finding_id}/theater")

    assert theater_response.status_code == 200
    threat_context = theater_response.json()["threat_context"]
    assert threat_context["available"] is True
    assert threat_context["status"] == "low_confidence"
    assert threat_context["mappings"][0]["technique_id"] == "AEGISPT-HARDENING-CONTROL-WEAKNESS"
    assert threat_context["mappings"][0]["confidence"] == "low"
    assert threat_context["attribution_boundary"]["claims_breach_likelihood"] is False


def test_detection_engineering_suggests_advisory_sql_detection_without_mutation(client) -> None:
    finding_id = _seed_finding(
        client,
        severity="high",
        title="SQL injection on login form",
        evidence_ref="artifact://zap/login-sql-injection",
        summary="The login form reflected a CWE-89 SQL injection validation payload.",
        methodology_tags=["owasp-wstg", "injection"],
        wstg_id="WSTG-INPV-05",
        control_family="input_validation",
    )

    with client.app.state.session_factory() as session:
        finding = session.get(Finding, UUID(finding_id))
        original = {
            "severity": finding.severity,
            "status": finding.status,
            "evidence_ref": finding.evidence_ref,
            "summary": finding.summary,
        }

    theater_response = client.get(f"/api/v1/findings/{finding_id}/theater")

    assert theater_response.status_code == 200
    theater = theater_response.json()
    detection = theater["detection_engineering"]
    assert detection["available"] is True
    assert detection["status"] == "suggested"
    assert detection["review_boundary"]["advisory_only"] is True
    assert detection["review_boundary"]["deploys_rules"] is False
    assert detection["review_boundary"]["deploys_siem_rules"] is False
    assert detection["review_boundary"]["production_ready"] is False
    assert detection["review_boundary"]["modifies_customer_systems"] is False
    assert detection["evidence_basis"]["evidence_ref"] == "artifact://zap/login-sql-injection"
    assert detection["evidence_basis"]["wstg_id"] == "WSTG-INPV-05"
    assert detection["evidence_basis"]["detected_references"] == ["CWE-89"]
    assert detection["evidence_basis"]["attack_scenarios"][0]["technique_id"] == "T1190"
    assert detection["unsupported_telemetry"] == []

    suggestion = detection["suggestions"][0]
    assert suggestion["id"] == "web-input-validation-detection"
    assert suggestion["production_ready"] is False
    assert suggestion["deploys_rules"] is False
    assert suggestion["operator_review_required"] is True
    assert suggestion["rule_starting_points"][0]["production_ready"] is False
    assert suggestion["rule_starting_points"][0]["deployment_status"] == "not_deployed"
    assert "finding.evidence_ref" in suggestion["source_trace"]
    assert "threat_context.mappings" in suggestion["source_trace"]
    assert {
        "source": "web_access_logs",
        "status": "supported",
        "support_status": "supported",
        "rationale": "Correlate URI, status code, user agent, and source IP.",
    } in suggestion["telemetry_sources"]
    assert {
        "severity": theater["finding"]["severity"],
        "status": theater["finding"]["status"],
        "evidence_ref": theater["finding"]["evidence_ref"],
        "summary": theater["finding"]["summary"],
    } == original


def test_detection_engineering_degrades_sparse_finding_without_fabrication(client) -> None:
    finding_id = _seed_finding(
        client,
        severity="info",
        title="Analyst-created placeholder finding",
        evidence_ref="",
        summary="",
        methodology_tags=[],
    )

    theater_response = client.get(f"/api/v1/findings/{finding_id}/theater")

    assert theater_response.status_code == 200
    detection = theater_response.json()["detection_engineering"]
    assert detection["available"] is False
    assert detection["status"] == "unsupported"
    assert detection["reason"] == "insufficient_evidence"
    assert detection["suggestions"] == []
    assert detection["unsupported_telemetry"] == []
    assert detection["review_boundary"]["advisory_only"] is True
    assert detection["review_boundary"]["deploys_rules"] is False
    assert detection["review_boundary"]["modifies_customer_systems"] is False


def test_detection_engineering_marks_unsupported_scenario_without_fabricating_rule(client) -> None:
    finding_id = _seed_finding(
        client,
        severity="medium",
        title="Manual business process observation",
        evidence_ref="artifact://manual/process-review",
        summary="The analyst recorded a manual control note without a curated attack scenario.",
        methodology_tags=["manual-review"],
        control_family="business_process",
    )

    theater_response = client.get(f"/api/v1/findings/{finding_id}/theater")

    assert theater_response.status_code == 200
    detection = theater_response.json()["detection_engineering"]
    assert detection["available"] is False
    assert detection["status"] == "unsupported"
    assert detection["reason"] == "no_curated_detection_match"
    assert detection["suggestions"] == []
    assert detection["evidence_basis"]["evidence_available"] is True
    assert detection["evidence_basis"]["structured_signals_available"] is True
    assert detection["review_boundary"]["deploys_rules"] is False
    assert detection["review_boundary"]["production_ready"] is False


def test_ai_finding_enrichment_http_adapter_is_configurable_without_local_ai_service() -> None:
    provider = build_finding_enrichment_provider(
        Settings(
            ai_finding_enrichment_enabled=True,
            ai_finding_enrichment_provider="http",
            ai_finding_enrichment_endpoint="https://ai.example.test/enrich-finding",
            ai_finding_enrichment_timeout_seconds=1.0,
        )
    )

    assert provider is not None
    assert provider.name == "http"


def test_ai_mission_guidance_is_grounded_and_read_only_when_provider_is_disabled(client) -> None:
    run = _create_guided_run(client)

    guidance = run["ai_mission_guidance"]
    assert guidance["available"] is True
    assert guidance["mode"] == "deterministic"
    assert guidance["provider"]["status"] == "disabled"
    assert "run.profile" in guidance["grounding"]
    assert "inventory_snapshot.summary_json" in guidance["grounding"]
    assert guidance["deterministic_inputs"]["profile_name"] == "passive-web-baseline"
    assert guidance["deterministic_inputs"]["inventory"]["summary"]["host_count"] == 1
    assert guidance["scope_boundary"]["expands_scope"] is False
    assert guidance["scope_boundary"]["launches_work"] is False
    assert guidance["scope_boundary"]["allowed_targets"] == ["https://app.example.test"]
    assert "out-of-scope.example.test" not in guidance["scope_boundary"]["allowed_targets"]
    assert guidance["follow_up_recommendations"]
    assert all(item["scope_effect"] == "no-scope-expansion" for item in guidance["follow_up_recommendations"])
    assert all(item["launches_work"] is False for item in guidance["follow_up_recommendations"])


def test_ai_mission_guidance_provider_failure_keeps_deterministic_fallback(client) -> None:
    run_payload = _create_guided_run(client)

    with client.app.state.session_factory() as session:
        run = session.get(Run, UUID(run_payload["id"]))
        guidance = build_mission_guidance_for_run(
            session=session,
            run=run,
            provider=FailingMissionGuidanceProvider(),
        )

    assert guidance["available"] is True
    assert guidance["mode"] == "deterministic"
    assert guidance["provider"]["status"] == "failed"
    assert guidance["provider"]["fallback"] == "deterministic"
    assert "simulated mission guidance timeout" in guidance["provider"]["failure_reason"]
    assert guidance["deterministic_inputs"]["target_count"] == 1
    assert guidance["scope_boundary"]["expands_scope"] is False
    assert guidance["follow_up_recommendations"]
