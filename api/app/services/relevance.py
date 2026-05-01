from __future__ import annotations

from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from api.app.methodology import derive_finding_methodology
from api.app.models import Finding, InventorySnapshot, RelevanceDecision, Run, ThreatIntelRecord


def _inventory_terms(normalized_inventory: dict[str, Any]) -> set[str]:
    terms: set[str] = set()
    for host in normalized_inventory.get("hosts", []):
        if isinstance(host, dict):
            value = str(host.get("host") or "").strip().lower()
            if value:
                terms.add(value)
    for service in normalized_inventory.get("services", []):
        if not isinstance(service, dict):
            continue
        for key in ("service", "product", "version", "host"):
            value = str(service.get(key) or "").strip().lower()
            if value:
                terms.add(value)
    for technology in normalized_inventory.get("technologies", []):
        if not isinstance(technology, dict):
            continue
        for key in ("name", "vendor", "version"):
            value = str(technology.get(key) or "").strip().lower()
            if value:
                terms.add(value)
    for auth_mechanism in normalized_inventory.get("auth_mechanisms", []):
        if isinstance(auth_mechanism, dict):
            value = str(auth_mechanism.get("type") or "").strip().lower()
            if value:
                terms.add(value)
    for api_type in normalized_inventory.get("api_types", []):
        if isinstance(api_type, dict):
            value = str(api_type.get("type") or "").strip().lower()
            if value:
                terms.add(value)
    for fingerprint in normalized_inventory.get("vendor_product_fingerprints", []):
        if not isinstance(fingerprint, dict):
            continue
        for key in ("vendor", "product", "version"):
            value = str(fingerprint.get(key) or "").strip().lower()
            if value:
                terms.add(value)
    return terms


def _inventory_context(normalized_inventory: dict[str, Any]) -> dict[str, bool]:
    tls_posture = normalized_inventory.get("tls_posture", {})
    return {
        "has_web": bool(normalized_inventory.get("http_endpoints")),
        "has_api": bool(normalized_inventory.get("api_types")),
        "has_auth": bool(normalized_inventory.get("auth_mechanisms")),
        "has_tls": bool(isinstance(tls_posture, dict) and (tls_posture.get("protocols") or tls_posture.get("issues"))),
        "has_code_signals": any(
            term in _inventory_terms(normalized_inventory)
            for term in {"python", "java", "javascript", "node", "go", "php"}
        ),
    }


def _surface_matches(attack_surface_type: str | None, context: dict[str, bool]) -> bool:
    normalized = (attack_surface_type or "").strip().lower()
    if not normalized:
        return False
    if normalized in {"web", "http", "browser"}:
        return context["has_web"]
    if normalized in {"api", "rest", "graphql"}:
        return context["has_api"]
    if normalized in {"auth", "authentication", "authorization", "session"}:
        return context["has_auth"]
    if normalized in {"tls", "ssl", "transport"}:
        return context["has_tls"]
    if normalized in {"code", "sast"}:
        return context["has_code_signals"]
    return False


def _record_score(record: ThreatIntelRecord, *, inventory_terms: set[str], context: dict[str, bool]) -> tuple[float, list[str]]:
    evidence: list[str] = []
    score = 0.0

    for candidate in [*record.affected_products_json, *record.product_match_hints_json, *record.architecture_hints_json]:
        normalized_candidate = candidate.strip().lower()
        if normalized_candidate and normalized_candidate in inventory_terms:
            score += 0.35
            evidence.append(f"inventory matched '{candidate}'")

    if _surface_matches(record.attack_surface_type, context):
        score += 0.2
        evidence.append(f"attack surface '{record.attack_surface_type}' present in inventory")

    severity = (record.severity or "").strip().lower()
    if severity == "critical":
        score += 0.15
        evidence.append("critical severity advisory")
    elif severity == "high":
        score += 0.1
        evidence.append("high severity advisory")

    score += min(max(record.confidence_score, 0.0), 1.0) * 0.2
    if record.confidence_score:
        evidence.append(f"intel confidence {record.confidence_score:.2f}")

    return min(score, 1.0), evidence


def _default_patterns(record: ThreatIntelRecord, *, context: dict[str, bool]) -> list[str]:
    if record.suggested_test_patterns_json:
        return list(record.suggested_test_patterns_json)

    surface = (record.attack_surface_type or "").strip().lower()
    if surface in {"api", "rest", "graphql"}:
        return ["nuclei", "zap", "playwright"]
    if surface in {"auth", "authentication", "authorization", "session"}:
        return ["playwright", "zap"]
    if surface in {"tls", "ssl", "transport"}:
        return ["scanner-profile"]
    if surface in {"code", "sast"} or context["has_code_signals"]:
        return ["semgrep"]
    return ["nuclei", "scanner-profile"]


def _capability_blueprints(
    record: ThreatIntelRecord,
    *,
    score: float,
    evidence_basis: list[str],
    context: dict[str, bool],
) -> list[dict[str, Any]]:
    blueprints: list[dict[str, Any]] = []
    for pattern in _default_patterns(record, context=context):
        normalized = pattern.strip().lower()
        if normalized in {"nuclei", "template", "nuclei-template"}:
            tool = "nuclei"
            capability_type = "nuclei_template"
            run_class = "passive"
        elif normalized in {"zap", "zap-job"}:
            tool = "zap"
            capability_type = "zap_job"
            run_class = "active"
        elif normalized in {"playwright", "browser-flow", "flow"}:
            tool = "playwright"
            capability_type = "playwright_flow"
            run_class = "active"
        elif normalized in {"semgrep", "rule", "semgrep-rule"}:
            tool = "semgrep"
            capability_type = "semgrep_rule"
            run_class = "passive"
        else:
            tool = "httpx"
            capability_type = "scanner_profile"
            run_class = "passive"

        methodology = derive_finding_methodology(
            title=record.title,
            summary=record.summary,
            tool=tool,
            run_class=run_class,
        )
        blueprints.append(
            {
                "capability_type": capability_type,
                "tool": tool,
                "title": record.title,
                "rationale": f"{record.advisory_id} is relevant to the observed environment.",
                "attack_surface_type": record.attack_surface_type,
                "methodology_tags": list(methodology.get("methodology_tags", [])),
                "ptes_phase": methodology.get("ptes_phase"),
                "nist_phase": methodology.get("nist_phase"),
                "wstg_id": methodology.get("wstg_id"),
                "wstg_version": methodology.get("wstg_version"),
                "asvs_reference": methodology.get("asvs_reference"),
                "control_family": methodology.get("control_family"),
                "confidence": round(score, 3),
                "evidence_basis": list(evidence_basis),
                "advisory_id": record.advisory_id,
                "source": record.source,
            }
        )
    return blueprints


def analyze_relevance(
    session: Session,
    *,
    requested_by: str,
    engagement_id,
    inventory_snapshot: InventorySnapshot,
    threat_intel_records: list[ThreatIntelRecord],
    include_prior_findings: bool = True,
) -> RelevanceDecision:
    normalized_inventory = inventory_snapshot.normalized_inventory_json
    inventory_terms = _inventory_terms(normalized_inventory)
    context = _inventory_context(normalized_inventory)
    prior_findings = (
        session.scalars(
            select(Finding)
            .join(Run, Finding.run_id == Run.id)
            .where(Run.engagement_id == engagement_id, Run.deleted_at.is_(None))
        ).all()
        if include_prior_findings
        else []
    )

    relevant_advisories: list[dict[str, Any]] = []
    informational_advisories: list[dict[str, Any]] = []
    suppressed_advisories: list[dict[str, Any]] = []
    proposed_capabilities: list[dict[str, Any]] = []
    evidence_basis: list[dict[str, Any]] = [
        {
            "type": "inventory_snapshot",
            "inventory_snapshot_id": str(inventory_snapshot.id),
            "confidence_score": inventory_snapshot.confidence_score,
            "signals": sorted(inventory_terms),
        }
    ]
    if include_prior_findings:
        evidence_basis.append(
            {
                "type": "prior_findings",
                "count": len(prior_findings),
                "control_families": sorted(
                    {
                        finding.control_family
                        for finding in prior_findings
                        if isinstance(finding.control_family, str) and finding.control_family
                    }
                ),
            }
        )

    methodology_tags: list[str] = []
    threat_refs: list[str] = []
    prior_finding_refs = [str(finding.id) for finding in prior_findings]

    for record in threat_intel_records:
        score, record_evidence = _record_score(record, inventory_terms=inventory_terms, context=context)
        threat_refs.append(str(record.id))
        advisory_entry = {
            "id": str(record.id),
            "source": record.source,
            "advisory_id": record.advisory_id,
            "title": record.title,
            "score": round(score, 3),
            "evidence_basis": record_evidence,
            "attack_surface_type": record.attack_surface_type,
            "severity": record.severity,
        }
        if score >= 0.55:
            relevant_advisories.append(advisory_entry)
            capability_blueprints = _capability_blueprints(
                record,
                score=score,
                evidence_basis=record_evidence,
                context=context,
            )
            proposed_capabilities.extend(capability_blueprints)
            for capability in capability_blueprints:
                methodology_tags.extend(
                    tag
                    for tag in capability.get("methodology_tags", [])
                    if isinstance(tag, str) and tag.strip()
                )
        elif score >= 0.3:
            informational_advisories.append(advisory_entry)
        else:
            suppressed_advisories.append(advisory_entry)

    proposed_templates = [
        capability for capability in proposed_capabilities if capability["capability_type"] == "nuclei_template"
    ]
    proposed_playwright_flows = [
        capability for capability in proposed_capabilities if capability["capability_type"] == "playwright_flow"
    ]
    proposed_semgrep_rules = [
        capability for capability in proposed_capabilities if capability["capability_type"] == "semgrep_rule"
    ]
    proposed_scanner_profiles = [
        capability
        for capability in proposed_capabilities
        if capability["capability_type"] in {"scanner_profile", "zap_job"}
    ]

    confidence_score = round(
        (
            sum(item["score"] for item in relevant_advisories + informational_advisories)
            / max(len(threat_intel_records), 1)
        ),
        3,
    )
    justification = (
        f"Analyzed {len(threat_intel_records)} advisory records against inventory snapshot {inventory_snapshot.id}. "
        f"{len(relevant_advisories)} advisories were relevant enough to drive customer-specific capabilities."
    )

    decision = RelevanceDecision(
        engagement_id=engagement_id,
        inventory_snapshot_id=inventory_snapshot.id,
        requested_by=requested_by,
        status="completed",
        threat_intel_refs_json=list(dict.fromkeys(threat_refs)),
        prior_finding_refs_json=prior_finding_refs,
        methodology_tags=list(dict.fromkeys(methodology_tags)),
        recommendations_json={
            "relevant_advisories": relevant_advisories,
            "informational_advisories": informational_advisories,
            "suppressed_advisories": suppressed_advisories,
            "proposed_capabilities": proposed_capabilities,
            "proposed_templates": proposed_templates,
            "proposed_playwright_flows": proposed_playwright_flows,
            "proposed_semgrep_rules": proposed_semgrep_rules,
            "proposed_scanner_profiles": proposed_scanner_profiles,
            "proposed_methodology_tags": list(dict.fromkeys(methodology_tags)),
            "justification": justification,
            "evidence_basis": evidence_basis,
            "confidence": confidence_score,
        },
        justification_text=justification,
        evidence_basis_json=evidence_basis,
        confidence_score=confidence_score,
    )
    session.add(decision)
    session.flush()
    return decision
