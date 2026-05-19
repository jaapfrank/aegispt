from __future__ import annotations

import re
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from api.app.models import ThreatIntelRecord

CVE_PATTERN = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)

FALLBACK_CVSS_BY_SEVERITY: dict[str, tuple[float, str]] = {
    "critical": (9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
    "high": (8.1, "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"),
    "medium": (5.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"),
    "low": (3.1, "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N"),
    "info": (0.0, "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:N/I:N/A:N"),
    "unknown": (0.0, "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:N/I:N/A:N"),
}


def _text_values(finding: Any) -> list[str]:
    tags = getattr(finding, "methodology_tags", None) or []
    return [
        str(getattr(finding, "title", "") or ""),
        str(getattr(finding, "summary", "") or ""),
        str(getattr(finding, "target_id", "") or ""),
        str(getattr(finding, "evidence_ref", "") or ""),
        str(getattr(finding, "control_family", "") or ""),
        str(getattr(finding, "wstg_id", "") or ""),
        str(getattr(finding, "asvs_reference", "") or ""),
        " ".join(str(tag) for tag in tags),
    ]


def _haystack(finding: Any) -> str:
    return " ".join(_text_values(finding)).lower()


def cve_ids_for_finding(finding: Any) -> list[str]:
    return list(dict.fromkeys(match.upper() for match in CVE_PATTERN.findall(" ".join(_text_values(finding)))))


def _float_or_none(value: Any) -> float | None:
    try:
        score = float(str(value).strip())
    except (TypeError, ValueError):
        return None
    if 0.0 <= score <= 10.0:
        return round(score, 1)
    return None


def _local_nvd_cvss(session: Session | None, cve_id: str) -> tuple[float, str | None, str] | None:
    if session is None:
        return None
    record = session.scalar(
        select(ThreatIntelRecord)
        .where(ThreatIntelRecord.advisory_id == cve_id.upper())
        .order_by(ThreatIntelRecord.updated_at.desc(), ThreatIntelRecord.id.desc())
    )
    if record is None:
        return None
    metadata = dict(record.metadata_json or {})
    score = _float_or_none(metadata.get("cvss_score"))
    if score is None:
        return None
    source = "nvd-cache" if record.source == "nvd" or metadata.get("feed_type") == "nvd" else "local-cve-cache"
    vector = metadata.get("cvss_vector") or metadata.get("cvss_metrics")
    return score, str(vector).strip()[:64] if vector else None, source


def cvss_quality_for_finding(finding: Any, *, session: Session | None = None) -> dict[str, Any]:
    stored_score = _float_or_none(getattr(finding, "cvss_score", None))
    stored_vector = str(getattr(finding, "cvss_vector", "") or "").strip()[:64] or None
    cve_ids = cve_ids_for_finding(finding)
    quality_metadata = _stored_quality_metadata(finding)

    if cve_ids:
        for cve_id in cve_ids:
            local = _local_nvd_cvss(session, cve_id)
            if local is not None:
                score, vector, source = local
                return {
                    "score": score,
                    "vector": vector or stored_vector or _fallback_cvss_vector(finding),
                    "source": source,
                    "cve_id": cve_id,
                }

    if stored_score is not None:
        return {
            "score": stored_score,
            "vector": stored_vector or _fallback_cvss_vector(finding),
            "source": quality_metadata.get("cvss_source") or "runner",
            "cve_id": cve_ids[0] if cve_ids else None,
        }

    severity = str(getattr(finding, "severity", "") or "unknown").strip().lower()
    score, vector = FALLBACK_CVSS_BY_SEVERITY.get(severity, FALLBACK_CVSS_BY_SEVERITY["unknown"])
    return {
        "score": score,
        "vector": vector,
        "source": "deterministic-fallback",
        "cve_id": cve_ids[0] if cve_ids else None,
    }


def _fallback_cvss_vector(finding: Any) -> str:
    severity = str(getattr(finding, "severity", "") or "unknown").strip().lower()
    return FALLBACK_CVSS_BY_SEVERITY.get(severity, FALLBACK_CVSS_BY_SEVERITY["unknown"])[1]


def _stored_quality_metadata(finding: Any) -> dict[str, Any]:
    recipe = getattr(finding, "replay_recipe_json", None)
    if isinstance(recipe, dict) and isinstance(recipe.get("finding_quality"), dict):
        return dict(recipe["finding_quality"])
    return {}


def owasp_quality_for_finding(finding: Any) -> dict[str, Any]:
    text = _haystack(finding)
    is_mobile = any(token in text for token in ("mobile", "android", "ios", "apk", "masvs"))
    is_api = any(token in text for token in (" api", "graphql", "rest", "openapi", "swagger", "bola"))

    if is_mobile:
        framework = "OWASP Mobile Top 10 2024"
        mappings = (
            (("credential", "password", "token", "secret", "session"), "M1: Improper Credential Usage", "OWASP-MAS-M1"),
            (("supply chain", "component", "dependency", "cve", "outdated"), "M2: Inadequate Supply Chain Security", "OWASP-MAS-M2"),
            (("auth", "authorization", "idor", "access control", "bola"), "M3: Insecure Authentication/Authorization", "OWASP-MAS-M3"),
            (("injection", "xss", "xxe", "ssti", "input"), "M4: Insufficient Input/Output Validation", "OWASP-MAS-M4"),
            (("tls", "ssl", "cleartext", "http://", "certificate"), "M5: Insecure Communication", "OWASP-MAS-M5"),
            (("privacy", "pii", "personal data"), "M6: Inadequate Privacy Controls", "OWASP-MAS-M6"),
            (("binary", "debuggable", "tamper"), "M7: Insufficient Binary Protections", "OWASP-MAS-M7"),
            (("configuration", "header", "cors", "manifest"), "M8: Security Misconfiguration", "OWASP-MAS-M8"),
            (("storage", "cache", "sqlite", "local data"), "M9: Insecure Data Storage", "OWASP-MAS-M9"),
            (("crypto", "cryptographic", "weak cipher"), "M10: Insufficient Cryptography", "OWASP-MAS-M10"),
        )
    elif is_api:
        framework = "OWASP API Security Top 10 2023"
        mappings = (
            (("idor", "bola", "object level", "access control"), "API1: Broken Object Level Authorization", "OWASP-API1"),
            (("auth", "session", "jwt", "password", "token"), "API2: Broken Authentication", "OWASP-API2"),
            (("object property", "mass assignment", "excessive data"), "API3: Broken Object Property Level Authorization", "OWASP-API3"),
            (("rate limit", "resource", "dos", "unrestricted"), "API4: Unrestricted Resource Consumption", "OWASP-API4"),
            (("function level", "admin", "role"), "API5: Broken Function Level Authorization", "OWASP-API5"),
            (("business logic", "workflow", "price", "state"), "API6: Unrestricted Access to Sensitive Business Flows", "OWASP-API6"),
            (("ssrf", "server-side request"), "API7: Server Side Request Forgery", "OWASP-API7"),
            (("configuration", "cors", "header", "injection", "xxe", "xss"), "API8: Security Misconfiguration", "OWASP-API8"),
            (("inventory", "version", "deprecated", "shadow"), "API9: Improper Inventory Management", "OWASP-API9"),
            (("third party", "external api", "unsafe consumption"), "API10: Unsafe Consumption of APIs", "OWASP-API10"),
        )
    else:
        framework = "OWASP Top 10 2021"
        mappings = (
            (("access control", "authorization", "idor", "bola", "privilege"), "A01: Broken Access Control", "OWASP-A01"),
            (("crypto", "cryptographic", "tls", "ssl", "certificate", "cleartext"), "A02: Cryptographic Failures", "OWASP-A02"),
            (("injection", "sql", "xss", "xxe", "ssti", "command injection"), "A03: Injection", "OWASP-A03"),
            (("business logic", "workflow", "insecure design"), "A04: Insecure Design", "OWASP-A04"),
            (("configuration", "header", "cors", "csp", "clickjacking", "debug"), "A05: Security Misconfiguration", "OWASP-A05"),
            (("component", "dependency", "cve", "outdated", "vulnerable version"), "A06: Vulnerable and Outdated Components", "OWASP-A06"),
            (("auth", "session", "jwt", "password reset", "login"), "A07: Identification and Authentication Failures", "OWASP-A07"),
            (("deserialization", "integrity", "signed", "supply chain"), "A08: Software and Data Integrity Failures", "OWASP-A08"),
            (("logging", "monitoring", "actuator", "stack trace"), "A09: Security Logging and Monitoring Failures", "OWASP-A09"),
            (("ssrf", "server-side request"), "A10: Server-Side Request Forgery", "OWASP-A10"),
        )

    for tokens, category, reference in mappings:
        if any(token in text for token in tokens):
            return {
                "framework": framework,
                "category": category,
                "reference": reference,
                "source": "deterministic-finding-type",
                "tags": ["owasp", reference.lower()],
            }

    return {
        "framework": framework,
        "category": "A05: Security Misconfiguration" if not is_api and not is_mobile else mappings[-1][1],
        "reference": "OWASP-A05" if not is_api and not is_mobile else mappings[-1][2],
        "source": "deterministic-default",
        "tags": ["owasp", ("OWASP-A05" if not is_api and not is_mobile else mappings[-1][2]).lower()],
    }


def proof_reference_for_finding(finding: Any) -> dict[str, Any]:
    recipe = getattr(finding, "replay_recipe_json", None)
    evidence_ref = str(getattr(finding, "evidence_ref", "") or "").strip()
    return {
        "label": "Reproduce from stored evidence",
        "evidence_ref": evidence_ref or None,
        "replay_recipe_available": isinstance(recipe, dict) and bool(recipe),
        "artifact_id": (recipe or {}).get("artifact", {}).get("id") if isinstance(recipe, dict) else None,
        "tool": (recipe or {}).get("tool") if isinstance(recipe, dict) else None,
        "target": (recipe or {}).get("target") if isinstance(recipe, dict) else getattr(finding, "target_id", None),
    }


def finding_quality_view(finding: Any, *, session: Session | None = None) -> dict[str, Any]:
    return {
        "cvss": cvss_quality_for_finding(finding, session=session),
        "owasp": owasp_quality_for_finding(finding),
        "proof_reference": proof_reference_for_finding(finding),
    }


def apply_finding_quality_defaults(finding: Any, *, session: Session | None = None) -> bool:
    quality = finding_quality_view(finding, session=session)
    changed = False
    cvss = quality["cvss"]
    if getattr(finding, "cvss_score", None) is None:
        finding.cvss_score = cvss["score"]
        changed = True
    if not getattr(finding, "cvss_vector", None) and cvss.get("vector"):
        finding.cvss_vector = cvss["vector"]
        changed = True

    existing_tags = [
        str(tag).strip()
        for tag in (getattr(finding, "methodology_tags", None) or [])
        if str(tag).strip()
    ]
    has_evidence_or_context = bool(
        str(getattr(finding, "evidence_ref", "") or "").strip()
        or str(getattr(finding, "summary", "") or "").strip()
        or existing_tags
    )
    if has_evidence_or_context:
        merged_tags = list(dict.fromkeys([*existing_tags, *quality["owasp"].get("tags", [])]))
        if merged_tags != existing_tags:
            finding.methodology_tags = merged_tags
            changed = True
    recipe = getattr(finding, "replay_recipe_json", None)
    if not isinstance(recipe, dict):
        recipe = {}
    existing_quality = dict(recipe.get("finding_quality") or {})
    next_quality = {
        **existing_quality,
        "cvss_source": quality["cvss"].get("source"),
        "cvss_cve_id": quality["cvss"].get("cve_id"),
        "owasp_reference": quality["owasp"].get("reference"),
        "owasp_category": quality["owasp"].get("category"),
        "proof_reference": quality["proof_reference"],
    }
    if next_quality != existing_quality:
        finding.replay_recipe_json = {**recipe, "finding_quality": next_quality}
        changed = True
    return changed
