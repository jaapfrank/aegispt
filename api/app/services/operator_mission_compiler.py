from __future__ import annotations

import re
from typing import Any

MISSION_COMPILER_VERSION = "operator-safe-mission-compiler-v1"
TARGET_RE = re.compile(r"https?://[^\s,;]+|(?:\b\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?")
BROAD_SCOPE_TERMS = (
    "anything reachable",
    "scan the internet",
    "all public websites",
    "whatever you can find",
    "random targets",
)
REJECT_TERMS = (
    "steal data",
    "exfiltrate",
    "dump database",
    "ransomware",
    "destroy",
    "wipe",
)
UNSAFE_VALIDATION_TERMS = (
    "exploit",
    "payload",
    "shell",
    "bypass",
    "credential spray",
    "bruteforce",
    "brute force",
)


def compile_operator_safe_mission(
    intent_text: str,
    *,
    existing_scope: dict[str, Any] | None = None,
    authorization_confirmed: bool = False,
) -> dict[str, Any]:
    text = str(intent_text or "").strip()
    lowered = text.lower()
    targets = _extract_targets(text)
    broad_scope = any(term in lowered for term in BROAD_SCOPE_TERMS)
    reject_reasons = [term for term in REJECT_TERMS if term in lowered]
    unsafe_terms = [term for term in UNSAFE_VALIDATION_TERMS if term in lowered]
    plan_status = "rejected" if reject_reasons or (broad_scope and not targets) else "draft"
    safe_language = _safe_validation_language(text, unsafe_terms, reject_reasons)
    allowed = _allowed_capabilities(lowered, authorization_confirmed=authorization_confirmed)
    forbidden = _forbidden_capabilities(unsafe_terms=unsafe_terms, reject_reasons=reject_reasons)
    required_approvals = _required_approvals(
        lowered,
        targets=targets,
        authorization_confirmed=authorization_confirmed,
        plan_status=plan_status,
    )
    return {
        "mission_compiler_version": MISSION_COMPILER_VERSION,
        "plan_status": plan_status,
        "mission_plan": {
            "intent_summary": safe_language,
            "scope": {
                "targets": targets,
                "existing_scope": existing_scope or {},
                "broad_scope_rejected": broad_scope,
                "scope_expansion_allowed": False,
                "requires_exact_authorized_targets": not targets,
            },
            "roe": {
                "authorization_confirmed": authorization_confirmed,
                "written_authorization_required": True,
                "operator_approval_required_before_runtime": True,
                "kill_switch_remains_authoritative": True,
            },
            "allowed_capabilities": allowed,
            "forbidden_capabilities": forbidden,
            "required_approvals": required_approvals,
            "required_operator_inputs": _required_inputs(targets, authorization_confirmed, plan_status),
            "safe_validation_language": safe_language,
        },
        "unsafe_intent_handling": {
            "unsafe_terms_detected": unsafe_terms,
            "reject_reasons": reject_reasons,
            "converted_to_safe_validation": bool(unsafe_terms and not reject_reasons),
            "rejected": plan_status == "rejected",
        },
        "execution_contract": {
            "analysis_only": True,
            "creates_tasks": False,
            "dispatches_work_directly": False,
            "approves_proposals": False,
            "automatic_approval": False,
            "generates_exploits_or_payloads": False,
            "mutates_scope": False,
            "materializes_secrets": False,
            "uses_credentials": False,
            "runtime_self_modification": False,
        },
    }


def _extract_targets(text: str) -> list[dict[str, str]]:
    targets: list[dict[str, str]] = []
    seen: set[str] = set()
    for match in TARGET_RE.findall(text):
        value = match.strip().rstrip(".")
        if not value or value in seen:
            continue
        seen.add(value)
        kind = "url" if value.startswith(("http://", "https://")) else "cidr" if "/" in value else "ip"
        targets.append({"kind": kind, "value": value})
    return targets


def _safe_validation_language(text: str, unsafe_terms: list[str], reject_reasons: list[str]) -> str:
    if reject_reasons:
        return "Rejected unsafe objective; no mission can be compiled from destructive or exfiltration intent."
    if unsafe_terms:
        return (
            "Convert unsafe runtime wording into evidence review and approval-gated validation planning. "
            "No exploit, payload, credential, shell, bypass, or brute-force action is generated."
        )
    if "full pentest" in text.lower() or "volledige pentest" in text.lower():
        return "Compile a bounded full-pentest mission preview that requires written authorization and operator approval before runtime."
    return "Compile a bounded assessment mission preview for operator review before any runtime action."


def _allowed_capabilities(lowered: str, *, authorization_confirmed: bool) -> list[dict[str, Any]]:
    capabilities = [
        {
            "id": "evidence_review",
            "label": "Evidence review",
            "runtime_action": False,
            "approval_required": False,
        },
        {
            "id": "scope_and_roe_compilation",
            "label": "Scope and ROE compilation",
            "runtime_action": False,
            "approval_required": False,
        },
    ]
    if "passive" in lowered or "recon" in lowered:
        capabilities.append(
            {
                "id": "passive_recon_planning",
                "label": "Passive reconnaissance planning",
                "runtime_action": False,
                "approval_required": True,
            }
        )
    if "active" in lowered or "full pentest" in lowered or "volledige pentest" in lowered:
        capabilities.append(
            {
                "id": "approval_gated_active_validation_planning",
                "label": "Approval-gated active validation planning",
                "runtime_action": False,
                "approval_required": True,
                "requires_written_authorization": not authorization_confirmed,
            }
        )
    return capabilities


def _forbidden_capabilities(*, unsafe_terms: list[str], reject_reasons: list[str]) -> list[dict[str, str]]:
    forbidden = [
        ("automatic_approval", "The compiler cannot approve runtime work."),
        ("runtime_dispatch", "The compiler cannot create tasks or dispatch runners."),
        ("scope_expansion", "The compiler cannot add targets beyond exact authorization."),
        ("credential_materialization", "The compiler cannot use or reveal credentials."),
        ("exploit_or_payload_generation", "The compiler cannot generate exploit or payload instructions."),
        ("live_exfiltration", "The compiler cannot simulate or perform exfiltration."),
    ]
    if unsafe_terms:
        forbidden.append(("unsafe_runtime_intent", "Unsafe wording is converted to safe validation language."))
    if reject_reasons:
        forbidden.append(("destructive_or_exfiltration_intent", "Destructive or exfiltration intent is rejected."))
    return [{"id": item[0], "reason": item[1]} for item in forbidden]


def _required_approvals(
    lowered: str,
    *,
    targets: list[dict[str, str]],
    authorization_confirmed: bool,
    plan_status: str,
) -> list[dict[str, str]]:
    approvals = [{"id": "operator_mission_approval", "reason": "Required before any runtime task can be created."}]
    if not authorization_confirmed:
        approvals.append({"id": "written_authorization", "reason": "Written authorization must be confirmed."})
    if "active" in lowered or "full pentest" in lowered or "volledige pentest" in lowered:
        approvals.append({"id": "active_validation_approval", "reason": "Active validation requires explicit operator approval."})
    if not targets:
        approvals.append({"id": "exact_scope_confirmation", "reason": "Exact authorized targets are required."})
    if plan_status == "rejected":
        approvals.append({"id": "rewrite_safe_intent", "reason": "Unsafe intent must be rewritten before compilation can proceed."})
    return approvals


def _required_inputs(
    targets: list[dict[str, str]],
    authorization_confirmed: bool,
    plan_status: str,
) -> list[dict[str, str]]:
    inputs: list[dict[str, str]] = []
    if not targets:
        inputs.append({"id": "exact_targets", "prompt": "Provide exact authorized URLs, domains, IPs, or CIDRs."})
    if not authorization_confirmed:
        inputs.append({"id": "written_authorization", "prompt": "Confirm written authorization and ROE."})
    if plan_status == "rejected":
        inputs.append({"id": "safe_rewrite", "prompt": "Rewrite the objective as evidence review or bounded validation."})
    return inputs
