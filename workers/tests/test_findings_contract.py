from __future__ import annotations

from api.app.methodology import WSTG_STABLE_VERSION, derive_finding_methodology
from api.app.models import Finding
from workers.orchestration.findings import (
    NormalizedFinding,
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
