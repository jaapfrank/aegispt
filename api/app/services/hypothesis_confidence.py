from __future__ import annotations

from collections.abc import Iterable
from typing import Any
from uuid import UUID

from sqlalchemy.orm import Session

from api.app.models import Run
from api.app.services.assessment_graph import build_normalized_evidence_graph

HYPOTHESIS_CONFIDENCE_VERSION = "hypothesis-confidence-v1"


def build_hypothesis_confidence_report(
    session: Session,
    *,
    run: Run | None = None,
    run_id: UUID | str | None = None,
) -> dict[str, Any]:
    graph = build_normalized_evidence_graph(session, run=run, run_id=run_id)
    return score_hypothesis_confidence(graph)


def score_hypothesis_confidence(graph: dict[str, Any]) -> dict[str, Any]:
    nodes = [node for node in graph.get("nodes", []) if isinstance(node, dict)]
    hypotheses = [
        _score_template(template, nodes)
        for template in _hypothesis_templates()
    ]
    hypotheses = [hypothesis for hypothesis in hypotheses if hypothesis is not None]
    return {
        "hypothesis_confidence_version": HYPOTHESIS_CONFIDENCE_VERSION,
        "graph_version": graph.get("graph_version"),
        "run_id": graph.get("run_id"),
        "summary": {
            "hypothesis_count": len(hypotheses),
            "hypothesis_types": [item["hypothesis_type"] for item in hypotheses],
            "review_only": True,
        },
        "execution_contract": {
            "analysis_only": True,
            "dispatches_work_directly": False,
            "creates_tasks": False,
            "approves_proposals": False,
            "mutates_approvals": False,
            "mutates_scope": False,
            "materializes_secrets": False,
            "uses_credentials": False,
            "accesses_live_targets": False,
            "runtime_self_modification": False,
            "recommendations_operator_review_only": True,
        },
        "hypotheses": hypotheses,
    }


def _score_template(template: dict[str, Any], nodes: list[dict[str, Any]]) -> dict[str, Any] | None:
    supporting = _matching_evidence(nodes, template["supporting_signals"])
    if not supporting:
        return None
    contradicting = _matching_evidence(nodes, template["contradicting_signals"])
    observed_missing = _missing_evidence(template["missing_evidence"], supporting, contradicting)
    confidence = _confidence_score(supporting, contradicting, observed_missing)
    return {
        "id": f"hypothesis-confidence:{template['hypothesis_type']}",
        "hypothesis_type": template["hypothesis_type"],
        "title": template["title"],
        "statement": template["statement"],
        "confidence": confidence,
        "confidence_label": _confidence_label(confidence),
        "supporting_evidence": supporting,
        "contradicting_evidence": contradicting,
        "missing_evidence": observed_missing,
        "next_safe_validation_step": _next_safe_validation_step(template, observed_missing),
        "recommendation_contract": _review_only_contract(),
        "provenance": {
            "source": "normalized_evidence_graph",
            "supporting_node_ids": [item["node_id"] for item in supporting],
            "contradicting_node_ids": [item["node_id"] for item in contradicting],
            "graph_review_only": True,
        },
    }


def _hypothesis_templates() -> list[dict[str, Any]]:
    return [
        {
            "hypothesis_type": "idor",
            "title": "IDOR / Broken Object Authorization",
            "statement": (
                "Stored evidence suggests object-level authorization may be weak, but it "
                "needs evidence from authorized request and response comparisons."
            ),
            "supporting_signals": [
                {"types": {"finding"}, "terms": ("idor", "object reference", "object authorization", "broken access", "access control")},
                {"types": {"api"}, "terms": ("user", "account", "invoice", "object", "/api/")},
                {"types": {"task", "runner_capability"}, "terms": ("idor", "access-control", "auth-flow")},
            ],
            "contradicting_signals": [
                {"types": {"finding", "evidence_ref"}, "terms": ("false positive", "resolved", "not reproducible", "authorization enforced", "403")},
            ],
            "missing_evidence": [
                ("authorized_actor_pair", "Evidence for two authorized users or roles in scope."),
                ("object_identifier_baseline", "A recorded baseline object identifier owned by the first actor."),
                ("authorization_comparison", "Redacted request/response comparison showing whether the second actor is denied."),
            ],
            "next_step": "Review existing redacted request/response evidence for two authorized actors and compare object-access outcomes.",
            "expected_evidence_refs": ["authorized_actor_pair", "authorization_comparison"],
        },
        {
            "hypothesis_type": "oauth_scope",
            "title": "Excessive OAuth Scope Exposure",
            "statement": (
                "Imported OAuth or permission evidence suggests a client or connector may "
                "hold broader scopes than needed."
            ),
            "supporting_signals": [
                {"types": {"permission"}, "terms": ("all", "admin", "write", "delete", "export", "offline", "files:read:all")},
                {"types": {"saas_connector"}, "terms": ("oauth", "connector", "client", "app")},
                {"types": {"identity"}, "terms": ("service account", "service-account", "oauth")},
            ],
            "contradicting_signals": [
                {"types": {"permission", "saas_connector"}, "terms": ("read-only", "least privilege", "revoked", "disabled", "expired")},
            ],
            "missing_evidence": [
                ("consent_record", "Imported consent or grant record for the OAuth client."),
                ("business_need_mapping", "Evidence that each broad scope is required for the approved business purpose."),
                ("scope_use_observation", "Read-only audit evidence showing whether the broad scope is actually used."),
            ],
            "next_step": "Review imported OAuth consent, scope, and connector configuration evidence and map broad grants to documented business need.",
            "expected_evidence_refs": ["consent_record", "business_need_mapping"],
        },
        {
            "hypothesis_type": "ssrf_to_cloud",
            "title": "SSRF-to-Cloud Trust Path",
            "statement": (
                "Stored findings and inventory may describe a server-side request path that "
                "could reach cloud identity or metadata evidence."
            ),
            "supporting_signals": [
                {"types": {"finding"}, "terms": ("ssrf", "server-side request", "metadata", "imds")},
                {"types": {"api", "asset"}, "terms": ("metadata", "169.254.169.254", "cloud", "aws", "azure", "gcp")},
                {"types": {"identity", "permission"}, "terms": ("iam", "role", "managed identity", "service account", "cloud")},
            ],
            "contradicting_signals": [
                {"types": {"finding", "asset", "evidence_ref"}, "terms": ("egress blocked", "metadata disabled", "imds required", "not reachable", "denied")},
            ],
            "missing_evidence": [
                ("server_side_fetch_evidence", "Evidence that a server-side fetch primitive exists in scope."),
                ("metadata_access_boundary", "Read-only evidence for whether metadata endpoints are reachable or blocked."),
                ("cloud_identity_context", "Imported role, managed identity, or service-account evidence tied to the asset."),
            ],
            "next_step": "Review stored SSRF observations, egress controls, and imported cloud identity evidence without issuing new requests.",
            "expected_evidence_refs": ["server_side_fetch_evidence", "metadata_access_boundary", "cloud_identity_context"],
        },
        {
            "hypothesis_type": "weak_auth",
            "title": "Weak Authentication Control",
            "statement": (
                "Evidence suggests authentication controls may be weak or incomplete and "
                "need confirmation from existing policy, identity, and observed auth-flow records."
            ),
            "supporting_signals": [
                {"types": {"finding"}, "terms": ("weak auth", "default credential", "no mfa", "missing mfa", "session exposure", "password policy")},
                {"types": {"api", "asset"}, "terms": ("login", "signin", "auth", "session")},
                {"types": {"identity"}, "terms": ("user", "service account", "account")},
            ],
            "contradicting_signals": [
                {"types": {"finding", "evidence_ref", "identity"}, "terms": ("mfa enforced", "strong policy", "sso enforced", "resolved", "false positive")},
            ],
            "missing_evidence": [
                ("auth_policy_record", "Imported authentication policy or tenant configuration evidence."),
                ("observed_login_flow", "Evidence from the approved login flow or session review."),
                ("control_enforcement_record", "Evidence showing MFA, SSO, lockout, or password policy enforcement."),
            ],
            "next_step": "Review stored authentication-flow evidence and imported policy records to confirm which controls are enforced.",
            "expected_evidence_refs": ["auth_policy_record", "observed_login_flow", "control_enforcement_record"],
        },
        {
            "hypothesis_type": "saas_connector_exposure",
            "title": "SaaS Connector Data Exposure Path",
            "statement": (
                "SaaS connector, permission, identity, or credential-reference evidence may "
                "form a trust path to bulk data access."
            ),
            "supporting_signals": [
                {"types": {"saas_connector"}, "terms": ("connector", "oauth", "bulk", "export", "dataset", "canva", "canvas")},
                {"types": {"permission"}, "terms": ("bulk_export", "export", "read:all", "files:read:all", "dataset", "admin")},
                {"types": {"credential_ref", "identity"}, "terms": ("service account", "session", "connector", "oauth")},
            ],
            "contradicting_signals": [
                {"types": {"saas_connector", "permission", "credential_ref"}, "terms": ("disabled", "revoked", "read-only", "no export", "expired")},
            ],
            "missing_evidence": [
                ("connector_owner", "Evidence identifying the connector owner or service account."),
                ("dataset_sensitivity", "Evidence describing the dataset or records reachable through the connector."),
                ("export_audit_log", "Read-only audit evidence for export or bulk-access activity."),
                ("scope_to_dataset_mapping", "Evidence mapping connector scopes to reachable datasets."),
            ],
            "next_step": "Review imported connector configuration, dataset inventory, and audit-log evidence for owner, scope, and export reach.",
            "expected_evidence_refs": ["connector_owner", "dataset_sensitivity", "export_audit_log"],
        },
    ]


def _matching_evidence(nodes: list[dict[str, Any]], signals: list[dict[str, Any]]) -> list[dict[str, Any]]:
    matches: dict[str, dict[str, Any]] = {}
    for node in nodes:
        text = _node_search_text(node)
        node_type = str(node.get("type") or "")
        for signal in signals:
            if node_type not in signal["types"]:
                continue
            terms = tuple(str(term).lower() for term in signal["terms"])
            matched_terms = [term for term in terms if term and term in text]
            if not matched_terms:
                continue
            matches[str(node["id"])] = {
                "node_id": str(node["id"]),
                "node_type": node_type,
                "subtype": node.get("subtype"),
                "label": str(node.get("label") or node.get("id")),
                "confidence": _bounded_float(node.get("confidence"), default=0.5),
                "evidence_refs": _string_list(node.get("evidence_refs")),
                "matched_terms": sorted(set(matched_terms)),
                "reason": f"Matched stored {node_type} evidence for {', '.join(sorted(set(matched_terms)))}.",
            }
    return sorted(matches.values(), key=lambda item: (item["node_type"], item["node_id"]))


def _missing_evidence(
    expected: Iterable[tuple[str, str]],
    supporting: list[dict[str, Any]],
    contradicting: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    observed_terms = {
        term
        for item in [*supporting, *contradicting]
        for term in item.get("matched_terms", [])
    }
    missing: list[dict[str, Any]] = []
    for evidence_id, description in expected:
        evidence_terms = set(str(evidence_id).replace("_", " ").split())
        if evidence_terms and evidence_terms.issubset(observed_terms):
            continue
        missing.append(
            {
                "id": evidence_id,
                "description": description,
                "status": "missing",
                "importance": "high",
            }
        )
    return missing


def _confidence_score(
    supporting: list[dict[str, Any]],
    contradicting: list[dict[str, Any]],
    missing: list[dict[str, Any]],
) -> float:
    support_score = min(0.52, len(supporting) * 0.11)
    evidence_ref_bonus = min(
        0.18,
        sum(0.03 for item in supporting if item.get("evidence_refs")),
    )
    node_confidence_bonus = min(
        0.16,
        sum(float(item.get("confidence") or 0.0) for item in supporting[:4]) * 0.04,
    )
    contradiction_penalty = min(0.28, len(contradicting) * 0.12)
    missing_penalty = min(0.2, len(missing) * 0.035)
    return round(max(0.05, min(0.95, 0.22 + support_score + evidence_ref_bonus + node_confidence_bonus - contradiction_penalty - missing_penalty)), 2)


def _confidence_label(score: float) -> str:
    if score >= 0.75:
        return "high"
    if score >= 0.45:
        return "medium"
    return "low"


def _next_safe_validation_step(
    template: dict[str, Any],
    missing: list[dict[str, Any]],
) -> dict[str, Any]:
    return {
        "action_type": "operator_review",
        "description": template["next_step"],
        "missing_evidence_ids": [item["id"] for item in missing],
        "expected_evidence_refs": list(template.get("expected_evidence_refs") or []),
        "creates_tasks": False,
        "dispatches_work": False,
        "approves_proposals": False,
        "mutates_scope": False,
        "uses_credentials": False,
        "materializes_secrets": False,
        "accesses_live_targets": False,
        "operator_review_only": True,
        "safety_notes": [
            "Use existing imported evidence or operator-provided records.",
            "Do not generate exploits, payloads, runtime tasks, approvals, or credential use from this recommendation.",
        ],
    }


def _review_only_contract() -> dict[str, bool]:
    return {
        "operator_review_only": True,
        "creates_tasks": False,
        "dispatches_work": False,
        "approves_proposals": False,
        "mutates_scope": False,
        "uses_credentials": False,
        "materializes_secrets": False,
        "accesses_live_targets": False,
    }


def _node_search_text(node: dict[str, Any]) -> str:
    parts = [
        node.get("id"),
        node.get("type"),
        node.get("subtype"),
        node.get("label"),
        node.get("source_id"),
        node.get("data"),
        node.get("evidence_refs"),
    ]
    return " ".join(_flatten_text(part) for part in parts).lower()


def _flatten_text(value: object) -> str:
    if isinstance(value, dict):
        return " ".join(f"{key} {_flatten_text(item)}" for key, item in value.items())
    if isinstance(value, (list, tuple, set)):
        return " ".join(_flatten_text(item) for item in value)
    if value is None:
        return ""
    return str(value)


def _string_list(value: object) -> list[str]:
    if isinstance(value, list):
        return [str(item) for item in value if str(item)]
    if isinstance(value, tuple | set):
        return [str(item) for item in value if str(item)]
    if value in (None, ""):
        return []
    return [str(value)]


def _bounded_float(value: object, *, default: float) -> float:
    try:
        parsed = float(value)
    except (TypeError, ValueError):
        return default
    return max(0.0, min(1.0, parsed))
