from __future__ import annotations

PRIMARY_REPORT_VARIANTS = ("summary", "technical", "compliance", "retest")
COMPLIANCE_REPORT_FRAMEWORKS = ("nis2", "dora", "soc2", "iso27001", "pci_dss", "nfir")
DEFAULT_COMPLIANCE_FRAMEWORK = "nis2"
REPORT_VARIANT_ALIASES = {
    "executive": "summary",
    "soc2": "compliance",
    "iso27001": "compliance",
    "pci_dss": "compliance",
    "nis2": "compliance",
    "dora": "compliance",
    "nfir": "compliance",
    "assurance": "technical",
    "attack_narrative": "technical",
}

REPORT_VARIANT_LABELS = {
    "summary": "Management Summary",
    "management_nl": "Management Samenvatting (Nederlands)",
    "technical": "Technical Report",
    "compliance": "Compliance Annex",
    "evidence": "Evidence Appendix",
    "retest": "Retest / Verification Report",
    "executive": "Executive Report",
    "soc2": "SOC 2 Report Package",
    "iso27001": "ISO 27001 Evidence Package",
    "pci_dss": "PCI DSS Evidence Package",
    "nis2": "NIS2 Evidence Package",
    "dora": "DORA Evidence Package",
    "nfir": "NFIR Evidence Mapping",
    "assurance": "Evidence-Backed Assurance Package",
    "attack_narrative": "Run Attack Narrative",
}

REPORT_VARIANT_DESCRIPTIONS = {
    "summary": "One-to-two page management view with risk level, top findings, tested scope, gaps, and top remediation priorities.",
    "management_nl": "Nederlandstalig managementrapport in begrijpelijke taal: risico, prioriteiten en aanbevelingen zonder technisch jargon.",
    "technical": "Full technical narrative with methodology, findings, evidence, and remediation detail.",
    "compliance": "Adaptive framework annex with a selectable NIS2, DORA, SOC 2, ISO 27001, PCI DSS, or NFIR mapping disclaimer.",
    "evidence": "Artifact-oriented appendix for replay, validation, and operator review.",
    "retest": "Verification-focused output tracking open, fixed, and still-unverified items.",
    "executive": "Leadership-ready summary of scope, outcomes, risk posture, and next steps.",
    "soc2": "SOC 2 Security-package view that maps existing evidence-backed findings to control references.",
    "iso27001": "ISO 27001 report-time view that groups existing evidence-backed findings by Annex A controls.",
    "pci_dss": "PCI DSS report-time view that groups existing evidence-backed findings by requirement review areas.",
    "nis2": "NIS2 report-time view that maps technical assessment evidence to Article 21 cybersecurity risk-management measures.",
    "dora": "DORA report-time view that maps technical assessment evidence to ICT risk management and TLPT boundary areas.",
    "nfir": "NFIR report-time view that maps stored evidence to seven pentest phases without claiming certification.",
    "assurance": "Scoped assurance output that states tested evidence, residual risk, and explicit non-certification limits.",
    "attack_narrative": "Review-only attack narrative synthesized from stored reconnaissance, attack paths, chains, findings, and evidence references.",
}


def normalize_report_variant(variant: str | None) -> str:
    if str(variant or "").strip().lower() == "management_nl":
        return "management_nl"
    token = str(variant or "technical").strip().lower()
    return REPORT_VARIANT_ALIASES.get(token, token if token in REPORT_VARIANT_LABELS else "technical")


def compliance_framework_for_request(variant: str | None = None, framework: str | None = None) -> str:
    variant_token = str(variant or "").strip().lower()
    framework_token = str(framework or "").strip().lower()
    if variant_token in COMPLIANCE_REPORT_FRAMEWORKS:
        return variant_token
    if framework_token in COMPLIANCE_REPORT_FRAMEWORKS:
        return framework_token
    return DEFAULT_COMPLIANCE_FRAMEWORK
