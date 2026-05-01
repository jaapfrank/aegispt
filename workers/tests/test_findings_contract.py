from __future__ import annotations

import uuid
from types import SimpleNamespace

from api.app.methodology import WSTG_STABLE_VERSION, derive_finding_methodology
from api.app.models import Finding
from api.app.services.ai_enrichment import DeterministicFindingEnrichmentProvider
from workers.runners.base.contracts import EvidenceArtifact
from workers.orchestration.findings import (
    NormalizedFinding,
    extract_nuclei_findings,
    extract_zap_findings,
    finding_signature,
    merge_finding,
    severity_rank,
)


def test_severity_rank_prefers_higher_severity() -> None:
    assert severity_rank("high") < severity_rank("medium")
    assert severity_rank("medium") < severity_rank("info")


def test_finding_signature_is_normalized() -> None:
    assert finding_signature(title=" Missing XFO ", target_id=" HTTPS://EXAMPLE.COM ") == (
        "missing xfo",
        "https://example.com",
    )


def test_merge_finding_updates_severity_evidence_and_reopens_resolved() -> None:
    existing = Finding(
        title="Missing Header",
        severity="low",
        target_id="https://example.com",
        evidence_ref="s3://old",
        summary="old summary",
        status="resolved",
    )
    incoming = NormalizedFinding(
        title="Missing Header",
        severity="high",
        target_id="https://example.com",
        evidence_ref="s3://new",
        summary="new summary",
    )

    changed = merge_finding(existing, incoming)

    assert changed is True
    assert existing.severity == "high"
    assert existing.evidence_ref == "s3://new"
    assert existing.summary == "new summary"
    assert existing.status == "reopened"


def test_merge_finding_updates_cvss_metadata() -> None:
    existing = Finding(
        title="Missing Header",
        severity="medium",
        target_id="https://example.com",
        evidence_ref="s3://old",
        status="open",
    )
    incoming = NormalizedFinding(
        title="Missing Header",
        severity="medium",
        target_id="https://example.com",
        evidence_ref="s3://new",
        summary="new summary",
        cvss_score=6.5,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N",
    )

    changed = merge_finding(existing, incoming)

    assert changed is True
    assert existing.cvss_score == 6.5
    assert existing.cvss_vector == "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N"


def test_nuclei_and_zap_extract_cvss_metadata() -> None:
    nuclei_artifact = EvidenceArtifact(
        name="nuclei-results.jsonl",
        content_type="application/jsonl",
        kind="nuclei-jsonl",
        data=(
            b'{"template-id":"CVE-2026-0001","info":{"name":"Test CVE",'
            b'"severity":"high","classification":{"cvss-score":8.8,'
            b'"cvss-metrics":"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"}},'
            b'"matched-at":"https://example.test"}\n'
        ),
    )
    nuclei_findings = extract_nuclei_findings(
        target_id="https://example.test",
        artifact=nuclei_artifact,
        artifact_record=SimpleNamespace(uri="inline://nuclei"),
    )
    assert nuclei_findings[0].cvss_score == 8.8
    assert nuclei_findings[0].cvss_vector == "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"

    zap_artifact = EvidenceArtifact(
        name="zap-results.json",
        content_type="application/json",
        kind="zap-json",
        data=(
            b'{"results":[{"target":"https://example.test","alerts":[{"alert":"Missing header",'
            b'"risk":"medium","riskcode":"2","url":"https://example.test"}]}]}'
        ),
    )
    zap_findings = extract_zap_findings(
        target_id="https://example.test",
        artifact=zap_artifact,
        artifact_record=SimpleNamespace(uri="inline://zap"),
    )
    assert zap_findings[0].cvss_score == 2.0


def test_merge_finding_merges_methodology_metadata() -> None:
    existing = Finding(
        title="Access Control Issue",
        severity="medium",
        target_id="https://example.com/account/1",
        evidence_ref="s3://old",
        status="open",
        methodology_tags=["ptes"],
    )
    incoming = NormalizedFinding(
        title="Access Control Issue",
        severity="medium",
        target_id="https://example.com/account/1",
        evidence_ref="s3://new",
        summary="IDOR confirmed.",
        methodology_tags=("ptes", "owasp-wstg", "authorization"),
        ptes_phase="exploitation",
        nist_phase="attack",
        wstg_id="WSTG-ATHZ-04",
        wstg_version=WSTG_STABLE_VERSION,
        control_family="authorization",
    )

    changed = merge_finding(existing, incoming)

    assert changed is True
    assert existing.methodology_tags == ["ptes", "owasp-wstg", "authorization"]
    assert existing.ptes_phase == "exploitation"
    assert existing.nist_phase == "attack"
    assert existing.wstg_id == "WSTG-ATHZ-04"
    assert existing.wstg_version == WSTG_STABLE_VERSION
    assert existing.control_family == "authorization"


def test_methodology_mapping_handles_idor() -> None:
    methodology = derive_finding_methodology(
        title="Insecure Direct Object Reference",
        summary="BOLA confirmed on the account details endpoint.",
        tool="zap",
        run_class="active",
    )

    assert methodology["ptes_phase"] == "exploitation"
    assert methodology["nist_phase"] == "attack"
    assert methodology["wstg_id"] == "WSTG-ATHZ-04"
    assert methodology["wstg_version"] == WSTG_STABLE_VERSION
    assert methodology["control_family"] == "authorization"


def test_methodology_mapping_handles_hyphenated_reflected_xss() -> None:
    methodology = derive_finding_methodology(
        title="Cross-site scripting (reflected)",
        summary="Scanner confirmed reflected JavaScript execution in a query parameter.",
        tool="burp",
        run_class="passive",
    )

    assert methodology["wstg_id"] == "WSTG-INPV-01"
    assert methodology["wstg_version"] == WSTG_STABLE_VERSION
    assert methodology["control_family"] == "input_validation"
    assert "owasp-wstg" in methodology["methodology_tags"]


def test_merge_finding_preserves_adaptive_pack_provenance() -> None:
    pack_id = uuid.uuid4()
    artifact_id = uuid.uuid4()
    snapshot_id = uuid.uuid4()
    decision_id = uuid.uuid4()

    existing = Finding(
        title="Session Misconfiguration",
        severity="medium",
        target_id="https://example.com",
        evidence_ref="s3://old",
        status="open",
        finding_origin="standard",
    )
    incoming = NormalizedFinding(
        title="Session Misconfiguration",
        severity="medium",
        target_id="https://example.com",
        evidence_ref="s3://new",
        summary="Generated pack confirmed a session weakness.",
        finding_origin="adaptive_pack",
        source_pack_id=pack_id,
        source_pack_artifact_id=artifact_id,
        source_inventory_snapshot_id=snapshot_id,
        source_relevance_decision_id=decision_id,
        source_pack_version="v2",
    )

    changed = merge_finding(existing, incoming)

    assert changed is True
    assert existing.finding_origin == "adaptive_pack"
    assert existing.source_pack_id == pack_id
    assert existing.source_pack_artifact_id == artifact_id
    assert existing.source_inventory_snapshot_id == snapshot_id
    assert existing.source_relevance_decision_id == decision_id
    assert existing.source_pack_version == "v2"


def test_deterministic_ai_enrichment_provider_is_additive_to_canonical_finding() -> None:
    finding = Finding(
        title="Missing Security Header",
        severity="medium",
        target_id="https://example.com",
        evidence_ref="artifact://headers/security",
        status="open",
        summary="The response did not include a hardening header.",
    )

    result = DeterministicFindingEnrichmentProvider().enrich(finding)

    assert "Missing Security Header" in result.business_impact
    assert "artifact://headers/security" in result.technical_context
    assert "single-finding retest flow" in result.remediation_narrative
    assert finding.severity == "medium"
    assert finding.status == "open"
    assert finding.evidence_ref == "artifact://headers/security"
