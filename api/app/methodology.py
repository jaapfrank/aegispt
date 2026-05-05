from __future__ import annotations

import re
from typing import Final

WSTG_STABLE_VERSION: Final[str] = "v4.2"
ASVS_STABLE_VERSION: Final[str] = "v5.0.0"

PTES_PHASES: Final[dict[str, str]] = {
    "pre_engagement": "Pre-Engagement",
    "intelligence_gathering": "Intelligence Gathering",
    "threat_modeling": "Threat Modeling",
    "vulnerability_analysis": "Vulnerability Analysis",
    "exploitation": "Exploitation",
    "post_exploitation": "Post-Exploitation",
    "reporting": "Reporting",
    "retest": "Retest",
}

NIST_PHASES: Final[dict[str, str]] = {
    "planning": "Planning",
    "discovery": "Discovery",
    "attack": "Attack",
    "reporting": "Reporting",
    "post_testing": "Post-Testing",
}

OPERATOR_WORKFLOW_STAGES: Final[dict[str, str]] = {
    "pre_engagement": "Pre-Engagement",
    "intelligence_gathering": "Intelligence Gathering",
    "analysis_validation": "Analysis / Validation",
    "controlled_exploitation": "Controlled Exploitation / Verification",
    "reporting": "Reporting",
    "retest": "Retest",
}

WSTG_AREAS: Final[dict[str, str]] = {
    "INFO": "Information Gathering",
    "CONF": "Configuration and Deployment Management Testing",
    "IDNT": "Identity Management Testing",
    "ATHN": "Authentication Testing",
    "ATHZ": "Authorization Testing",
    "SESS": "Session Management Testing",
    "INPV": "Input Validation Testing",
    "ERRH": "Error Handling Testing",
    "CRYP": "Weak Cryptography Testing",
    "BUSL": "Business Logic Testing",
    "CLNT": "Client-side Testing",
    "APIT": "API Testing",
}

CONTROL_FAMILY_LABELS: Final[dict[str, str]] = {
    "information_gathering": "Information Gathering",
    "configuration": "Configuration and Deployment",
    "identity_management": "Identity Management",
    "authentication": "Authentication",
    "authorization": "Authorization",
    "session_management": "Session Management",
    "input_validation": "Input Validation",
    "error_handling": "Error Handling",
    "cryptography": "Weak Cryptography",
    "business_logic": "Business Logic",
    "client_security": "Client-side Security",
    "api_security": "API Security",
    "secure_code_review": "Secure Code Review",
}

TOOL_WSTG_AREAS: Final[dict[str, tuple[str, ...]]] = {
    "httpx": ("Information Gathering",),
    "nmap": ("Information Gathering", "Configuration and Deployment Management Testing"),
    "nuclei": ("Configuration and Deployment Management Testing", "Input Validation Testing"),
    "content-discovery": ("Information Gathering", "Configuration and Deployment Management Testing", "API Testing"),
    "ffuf": ("Information Gathering", "Configuration and Deployment Management Testing", "API Testing"),
    "feroxbuster": ("Information Gathering", "Configuration and Deployment Management Testing", "API Testing"),
    "nikto": ("Configuration and Deployment Management Testing", "Information Gathering"),
    "sqlmap": ("Input Validation Testing",),
    "xxe-probe": ("Input Validation Testing",),
    "jwt-probe": ("Authentication Testing", "Session Management Testing"),
    "auth-flow": ("Authentication Testing",),
    "oauth-probe": ("Authentication Testing", "Session Management Testing"),
    "session-security": ("Session Management Testing", "Authentication Testing"),
    "idor-bac": ("Authorization Testing", "API Testing"),
    "client-state": ("Authorization Testing", "Business Logic Testing"),
    "headers-security": ("Configuration and Deployment Management Testing", "Client-side Testing"),
    "graphql-probe": ("API Testing", "Input Validation Testing", "Authorization Testing"),
    "ssti-probe": ("Input Validation Testing",),
    "http-smuggling": ("Input Validation Testing", "Configuration and Deployment Management Testing"),
    "vuln-components": ("Configuration and Deployment Management Testing", "Information Gathering"),
    "xss-extended": ("Input Validation Testing", "Client-side Testing", "API Testing"),
    "ssrf-probe": ("Input Validation Testing", "API Testing"),
    "deserialization-probe": ("Input Validation Testing",),
    "external-osint": ("Information Gathering",),
    "zap": (
        "Information Gathering",
        "Configuration and Deployment Management Testing",
        "Authentication Testing",
        "Authorization Testing",
        "Session Management Testing",
        "Input Validation Testing",
        "Client-side Testing",
        "API Testing",
    ),
}

RUN_CLASS_TO_PTES_PHASE: Final[dict[str, str]] = {
    "passive": "vulnerability_analysis",
    "active": "exploitation",
    "intrusive": "exploitation",
}

RUN_CLASS_TO_NIST_PHASE: Final[dict[str, str]] = {
    "passive": "discovery",
    "active": "attack",
    "intrusive": "attack",
}

RUN_CLASS_TO_OPERATOR_STAGE: Final[dict[str, str]] = {
    "passive": OPERATOR_WORKFLOW_STAGES["analysis_validation"],
    "active": OPERATOR_WORKFLOW_STAGES["controlled_exploitation"],
    "intrusive": OPERATOR_WORKFLOW_STAGES["controlled_exploitation"],
}

DEFAULT_CONTROL_FAMILY_BY_TOOL: Final[dict[str, str]] = {
    "httpx": "information_gathering",
    "nmap": "information_gathering",
    "nuclei": "configuration",
    "content-discovery": "configuration",
    "ffuf": "configuration",
    "feroxbuster": "configuration",
    "nikto": "configuration",
    "sqlmap": "input_validation",
    "xxe-probe": "input_validation",
    "jwt-probe": "authentication",
    "auth-flow": "authentication",
    "oauth-probe": "authentication",
    "session-security": "session_management",
    "idor-bac": "business_logic",
    "client-state": "business_logic",
    "headers-security": "configuration",
    "graphql-probe": "api_security",
    "ssti-probe": "input_validation",
    "http-smuggling": "input_validation",
    "vuln-components": "configuration",
    "xss-extended": "input_validation",
    "ssrf-probe": "input_validation",
    "deserialization-probe": "input_validation",
    "external-osint": "information_gathering",
    "zap": "configuration",
    "semgrep": "secure_code_review",
}


NON_ALNUM_PATTERN: Final[re.Pattern[str]] = re.compile(r"[^a-z0-9]+")


def _normalize_match_text(value: str) -> str:
    return NON_ALNUM_PATTERN.sub(" ", value.strip().lower()).strip()

METHODOLOGY_RULES: Final[tuple[dict[str, str | tuple[str, ...]], ...]] = (
    {
        "terms": (
            "broken object level authorization",
            "insecure direct object reference",
            "idor",
            "bola",
        ),
        "control_family": "authorization",
        "wstg_id": "WSTG-ATHZ-04",
    },
    {
        "terms": ("privilege escalation",),
        "control_family": "authorization",
        "wstg_id": "WSTG-ATHZ-03",
    },
    {
        "terms": ("authorization bypass", "broken access control", "bypassing authorization"),
        "control_family": "authorization",
        "wstg_id": "WSTG-ATHZ-02",
    },
    {
        "terms": ("account enumeration", "guessable user account"),
        "control_family": "identity_management",
        "wstg_id": "WSTG-IDNT-04",
    },
    {
        "terms": ("weak username policy",),
        "control_family": "identity_management",
        "wstg_id": "WSTG-IDNT-05",
    },
    {
        "terms": ("default credentials",),
        "control_family": "authentication",
        "wstg_id": "WSTG-ATHN-02",
    },
    {
        "terms": ("weak password",),
        "control_family": "authentication",
        "wstg_id": "WSTG-ATHN-07",
    },
    {
        "terms": ("password reset", "password change"),
        "control_family": "authentication",
        "wstg_id": "WSTG-ATHN-09",
    },
    {
        "terms": ("authentication bypass", "bypassing authentication"),
        "control_family": "authentication",
        "wstg_id": "WSTG-ATHN-04",
    },
    {
        "terms": ("session fixation",),
        "control_family": "session_management",
        "wstg_id": "WSTG-SESS-03",
    },
    {
        "terms": ("cross site request forgery", "csrf"),
        "control_family": "session_management",
        "wstg_id": "WSTG-SESS-05",
    },
    {
        "terms": ("session timeout", "session not invalidated", "logout replay"),
        "control_family": "session_management",
        "wstg_id": "WSTG-SESS-07",
    },
    {
        "terms": (
            "httponly",
            "secure cookie",
            "samesite",
            "cookie attribute",
            "session token entropy",
            "session token in url",
        ),
        "control_family": "session_management",
        "wstg_id": "WSTG-SESS-02",
    },
    {
        "terms": (
            "dom-based cross site scripting",
            "cross site scripting dom based",
            "dom xss",
        ),
        "control_family": "client_security",
        "wstg_id": "WSTG-CLNT-01",
    },
    {
        "terms": (
            "stored cross site scripting",
            "cross site scripting stored",
            "stored xss",
        ),
        "control_family": "input_validation",
        "wstg_id": "WSTG-INPV-02",
    },
    {
        "terms": (
            "reflected cross site scripting",
            "cross site scripting reflected",
            "reflected xss",
            "xss",
        ),
        "control_family": "input_validation",
        "wstg_id": "WSTG-INPV-01",
    },
    {
        "terms": ("sql injection", "nosql injection", "orm injection"),
        "control_family": "input_validation",
        "wstg_id": "WSTG-INPV-05",
    },
    {
        "terms": ("ldap injection",),
        "control_family": "input_validation",
        "wstg_id": "WSTG-INPV-06",
    },
    {
        "terms": ("xml injection", "xxe"),
        "control_family": "input_validation",
        "wstg_id": "WSTG-INPV-07",
    },
    {
        "terms": ("xpath injection",),
        "control_family": "input_validation",
        "wstg_id": "WSTG-INPV-09",
    },
    {
        "terms": ("command injection", "os command injection"),
        "control_family": "input_validation",
        "wstg_id": "WSTG-INPV-12",
    },
    {
        "terms": ("server-side template injection", "ssti"),
        "control_family": "input_validation",
        "wstg_id": "WSTG-INPV-18",
    },
    {
        "terms": ("server-side request forgery", "ssrf"),
        "control_family": "input_validation",
        "wstg_id": "WSTG-INPV-19",
    },
    {
        "terms": ("stack trace",),
        "control_family": "error_handling",
        "wstg_id": "WSTG-ERRH-02",
    },
    {
        "terms": ("error handling", "verbose error", "exception leakage"),
        "control_family": "error_handling",
        "wstg_id": "WSTG-ERRH-01",
    },
    {
        "terms": ("strict transport security", "hsts"),
        "control_family": "configuration",
        "wstg_id": "WSTG-CONF-07",
    },
    {
        "terms": ("http methods", "trace method", "unsafe method"),
        "control_family": "configuration",
        "wstg_id": "WSTG-CONF-06",
    },
    {
        "terms": ("weak tls", "weak ssl", "padding oracle"),
        "control_family": "cryptography",
        "wstg_id": "WSTG-CRYP-01",
    },
    {
        "terms": ("weak encryption", "deprecated cipher"),
        "control_family": "cryptography",
        "wstg_id": "WSTG-CRYP-04",
    },
    {
        "terms": ("workflow bypass", "business logic", "process timing", "circumvention of work flows"),
        "control_family": "business_logic",
        "wstg_id": "WSTG-BUSL-06",
    },
    {
        "terms": ("clickjacking", "missing x-frame-options", "x-frame-options"),
        "control_family": "client_security",
        "wstg_id": "WSTG-CLNT-09",
    },
    {
        "terms": ("graphql",),
        "control_family": "api_security",
        "wstg_id": None,
    },
    {
        "terms": ("hardcoded secret", "hardcoded credential", "api key", "token"),
        "control_family": "secure_code_review",
        "wstg_id": None,
    },
)


def ptes_phase_label(phase: str | None) -> str | None:
    if phase is None:
        return None
    return PTES_PHASES.get(phase, phase.replace("_", " ").title())


def nist_phase_label(phase: str | None) -> str | None:
    if phase is None:
        return None
    return NIST_PHASES.get(phase, phase.replace("_", " ").title())


def control_family_label(control_family: str | None) -> str | None:
    if control_family is None:
        return None
    return CONTROL_FAMILY_LABELS.get(control_family, control_family.replace("_", " ").title())


def default_ptes_phase_for_run_class(run_class: str | None) -> str:
    normalized = (run_class or "").strip().lower()
    return RUN_CLASS_TO_PTES_PHASE.get(normalized, "vulnerability_analysis")


def default_nist_phase_for_run_class(run_class: str | None) -> str:
    normalized = (run_class or "").strip().lower()
    return RUN_CLASS_TO_NIST_PHASE.get(normalized, "discovery")


def operator_workflow_stage_for_run_class(run_class: str | None) -> str:
    normalized = (run_class or "").strip().lower()
    return RUN_CLASS_TO_OPERATOR_STAGE.get(normalized, OPERATOR_WORKFLOW_STAGES["analysis_validation"])


def wstg_area_for_identifier(wstg_id: str | None) -> str | None:
    if not wstg_id:
        return None

    parts = wstg_id.split("-")
    if len(parts) < 3:
        return None
    return WSTG_AREAS.get(parts[1])


def format_wstg_reference(wstg_id: str | None, wstg_version: str | None) -> str | None:
    if not wstg_id:
        return None
    if wstg_version:
        return f"{wstg_id} ({wstg_version})"
    return wstg_id


def tool_wstg_areas(tool: str | None) -> tuple[str, ...]:
    normalized = (tool or "").strip().lower()
    return TOOL_WSTG_AREAS.get(normalized, ())


def default_remediation_summary(control_family: str | None) -> str:
    summaries = {
        "information_gathering": "Reduce unnecessary exposed surface and remove non-essential discovery signals.",
        "configuration": "Harden deployment defaults and exposed web/application configuration.",
        "identity_management": "Tighten identity lifecycle controls and reduce account enumeration signals.",
        "authentication": "Strengthen authentication flows, fallback channels, and credential protections.",
        "authorization": "Enforce server-side authorization checks on every object and action.",
        "session_management": "Harden session issuance, rotation, timeout, cookie flags, and logout handling.",
        "input_validation": "Validate untrusted input server-side and use safe, parameterized execution paths.",
        "error_handling": "Remove diagnostic leakage and return user-safe errors while preserving server-side logging.",
        "cryptography": "Adopt modern cryptographic defaults and retire weak transport or encryption settings.",
        "business_logic": "Add workflow-aware server-side validation and abuse-case controls.",
        "client_security": "Apply client-side protections such as anti-framing and browser-facing hardening headers.",
        "api_security": "Document, authenticate, authorize, and validate API operations consistently.",
        "secure_code_review": "Move secrets and sensitive values out of source code and into approved secret storage.",
    }
    return summaries.get(
        control_family,
        "Prioritize a server-side remediation that removes the verified weakness and preserves evidence for retest.",
    )


def default_remediation_detail(control_family: str | None) -> str:
    details = {
        "information_gathering": "Review exposed endpoints, metadata, and fingerprints; disable what is unnecessary and document what remains intentionally public.",
        "configuration": "Review HTTP methods, headers, admin paths, backup files, and deployment defaults. Align the target to a hardened baseline before retest.",
        "identity_management": "Confirm role definitions, registration, provisioning, and account discovery behavior meet the intended access model.",
        "authentication": "Review credential transport, password policy, reset flows, lockout, and alternate channel authentication. Add strong server-side enforcement and logging.",
        "authorization": "Apply object-level and function-level authorization checks on every request path and test both horizontal and vertical access control cases during retest.",
        "session_management": "Review token issuance, invalidation, expiration, cookie attributes, and CSRF defenses. Ensure session boundaries are enforced uniformly.",
        "input_validation": "Use allowlists, parameterized queries, safe template execution, and output encoding where appropriate. Retest the exact payload class that produced the evidence.",
        "error_handling": "Return minimal external error detail while preserving complete server-side diagnostics for operators.",
        "cryptography": "Remove weak ciphers and protocols, enforce strong TLS configuration, and verify certificate and transport protections after change.",
        "business_logic": "Model the workflow abuse case explicitly and add server-side validations that enforce state transitions, limits, and integrity checks.",
        "client_security": "Set and validate browser security headers and client-side trust boundaries across all relevant routes.",
        "api_security": "Apply endpoint-specific authorization, schema validation, and documentation controls, then retest from both documented and undocumented paths.",
        "secure_code_review": "Rotate exposed secrets, move them to an approved vault or runtime injection mechanism, and scan the repository history where needed.",
    }
    return details.get(
        control_family,
        "Use the linked evidence to reproduce the issue, implement a focused fix, and re-run the validating step before closure.",
    )


def derive_finding_methodology(
    *,
    title: str,
    summary: str | None,
    tool: str | None,
    run_class: str | None,
) -> dict[str, object]:
    normalized_tool = (tool or "").strip().lower()
    text = _normalize_match_text(
        " ".join(part.strip() for part in (title, summary or "") if part and part.strip())
    )

    control_family = DEFAULT_CONTROL_FAMILY_BY_TOOL.get(normalized_tool)
    wstg_id: str | None = None
    asvs_reference: str | None = None

    for rule in METHODOLOGY_RULES:
        terms = rule["terms"]
        if not isinstance(terms, tuple):
            continue
        if any(_normalize_match_text(term) in text for term in terms):
            rule_control_family = rule.get("control_family")
            rule_wstg_id = rule.get("wstg_id")
            rule_asvs_reference = rule.get("asvs_reference")
            if isinstance(rule_control_family, str):
                control_family = rule_control_family
            if isinstance(rule_wstg_id, str) or rule_wstg_id is None:
                wstg_id = rule_wstg_id
            if isinstance(rule_asvs_reference, str):
                asvs_reference = rule_asvs_reference
            break

    ptes_phase = default_ptes_phase_for_run_class(run_class)
    nist_phase = default_nist_phase_for_run_class(run_class)
    wstg_version = WSTG_STABLE_VERSION if wstg_id else None

    tags: list[str] = ["ptes", "nist-sp-800-115"]
    if wstg_id:
        tags.append("owasp-wstg")
    if asvs_reference:
        tags.append("owasp-asvs")
    if control_family:
        tags.append(control_family)
    if normalized_tool:
        tool_tag = {
            "httpx": "reconnaissance",
            "nmap": "reconnaissance",
            "nuclei": "template-validation",
            "content-discovery": "content-discovery",
            "ffuf": "content-discovery",
            "feroxbuster": "content-discovery",
            "nikto": "web-configuration",
            "sqlmap": "sqli-confirmation",
            "xxe-probe": "xxe-validation",
            "jwt-probe": "jwt-validation",
            "auth-flow": "auth-flow-validation",
            "oauth-probe": "oauth-oidc-validation",
            "idor-bac": "idor-bac-validation",
            "client-state": "client-state-validation",
            "headers-security": "headers-security-validation",
            "graphql-probe": "graphql-probe-validation",
            "ssti-probe": "ssti-probe-validation",
            "http-smuggling": "http-smuggling-validation",
            "vuln-components": "vulnerable-components",
            "xss-extended": "xss-extended-validation",
            "ssrf-probe": "ssrf-validation",
            "deserialization-probe": "deserialization-validation",
            "external-osint": "passive-osint",
            "zap": "dynamic-analysis",
            "semgrep": "static-analysis",
        }.get(normalized_tool, normalized_tool)
        tags.append(tool_tag)

    ordered_tags = list(dict.fromkeys(tags))

    return {
        "methodology_tags": ordered_tags,
        "ptes_phase": ptes_phase,
        "nist_phase": nist_phase,
        "wstg_id": wstg_id,
        "wstg_version": wstg_version,
        "asvs_reference": asvs_reference,
        "control_family": control_family,
    }
