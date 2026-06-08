"""Tests for the No-Exploit-No-Report finding evidence taxonomy (rework-4 1.2)."""
from api.app.services.finding_evidence_gate import (
    PASSIVE,
    PROVEN,
    UNPROVEN,
    classify_finding,
    is_reportable,
    partition_findings,
)


def test_real_exploit_proven_findings():
    # XBEN-080 run a4900a50: interactive-exploit captured the flag
    assert classify_finding(
        title="Flag captured (interactive-exploit): xbow-a89daf5cad4a1b5d64b4e7316e72efbb",
        source_tool="interactive-exploit", evidence_ref="inline://.../flag",
    ) == PROVEN
    # Gruyere run d1b6d25d HIGH findings that ARE confirmed exploits
    assert classify_finding(title="Reflected XSS Confirmed — Cookie HttpOnly Protected (uid)") == PROVEN
    assert classify_finding(title="Path Traversal — Sensitive File Disclosure") == PROVEN


def test_real_passive_observations_are_not_reportable():
    # These appeared as "findings" but are passive — No Exploit, No Report.
    for title in (
        "Information Disclosure Header Exposes Platform Detail",
        "HSTS Missing on HTTPS Target",
        "Sensitive Page Missing Clickjacking Frame Protection",
        "Hidden Endpoint Discovered",
    ):
        assert classify_finding(title=title) == PASSIVE, title
        assert is_reportable(title=title) is False, title


def test_exploit_tool_needs_evidence_ref():
    # an exploit tool WITHOUT evidence is not auto-proven
    assert classify_finding(title="probe attempt", source_tool="interactive-exploit", evidence_ref="") == UNPROVEN


def test_ambiguous_defaults_to_unproven_not_reportable():
    assert classify_finding(title="Possible misconfiguration somewhere") == UNPROVEN
    assert is_reportable(title="Possible misconfiguration somewhere") is False


def test_only_proven_is_reportable():
    assert is_reportable(title="Reflected XSS Confirmed") is True
    assert is_reportable(title="Hidden Endpoint Discovered") is False


def test_partition_findings_counts_only_proven():
    # the real Gruyere run d1b6d25d finding set
    findings = [
        {"title": "Reflected XSS Confirmed — Cookie HttpOnly Protected (uid)"},
        {"title": "Path Traversal — Sensitive File Disclosure"},
        {"title": "Information Disclosure Header Exposes Platform Detail"},
        {"title": "HSTS Missing on HTTPS Target"},
        {"title": "Sensitive Page Missing Clickjacking Frame Protection"},
        {"title": "Hidden Endpoint Discovered"},
        "not-a-dict",  # skipped
    ]
    part = partition_findings(findings)
    assert len(part[PROVEN]) == 2          # XSS confirmed + path traversal
    assert len(part[PASSIVE]) == 4         # platform header, HSTS, clickjacking, hidden endpoint
    assert len(part[UNPROVEN]) == 0
    # No Exploit, No Report: only 2 of 6 count as real findings
    assert sum(len(v) for v in part.values()) == 6
