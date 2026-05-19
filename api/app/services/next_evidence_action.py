from __future__ import annotations

from typing import Any
from uuid import UUID

from sqlalchemy.orm import Session

from api.app.models import Run
from api.app.services.hypothesis_confidence import build_hypothesis_confidence_report
from api.app.services.runner_contracts import runner_contract_matrix

NEXT_EVIDENCE_ACTION_VERSION = "next-best-evidence-action-v1"
RISK_SAFETY = {"passive": 1.0, "active": 0.72, "intrusive": 0.35}
COST_SAFETY = {"low": 1.0, "medium": 0.72, "high": 0.45}


def build_next_evidence_action_plan(
    session: Session,
    *,
    run: Run | None = None,
    run_id: UUID | str | None = None,
) -> dict[str, Any]:
    confidence_report = build_hypothesis_confidence_report(session, run=run, run_id=run_id)
    return plan_next_evidence_actions(confidence_report)


def plan_next_evidence_actions(confidence_report: dict[str, Any]) -> dict[str, Any]:
    contracts = _contract_lookup()
    actions = [
        action
        for hypothesis in _as_list(confidence_report.get("hypotheses"))
        if isinstance(hypothesis, dict)
        for action in [_plan_for_hypothesis(hypothesis, contracts)]
        if action is not None
    ]
    for index, action in enumerate(
        sorted(actions, key=lambda item: (-float(item["priority_score"]), item["hypothesis_type"])),
        start=1,
    ):
        action["rank"] = index
    actions.sort(key=lambda item: item["rank"])
    return {
        "next_evidence_action_version": NEXT_EVIDENCE_ACTION_VERSION,
        "source_hypothesis_confidence_version": confidence_report.get("hypothesis_confidence_version"),
        "run_id": confidence_report.get("run_id"),
        "summary": {
            "action_count": len(actions),
            "operator_review_only": True,
            "planner_goal": "identify missing evidence, not the next tool to run",
        },
        "execution_contract": _execution_contract(),
        "actions": actions,
    }


def _plan_for_hypothesis(
    hypothesis: dict[str, Any],
    contracts: dict[str, dict[str, Any]],
) -> dict[str, Any] | None:
    missing = [item for item in _as_list(hypothesis.get("missing_evidence")) if isinstance(item, dict)]
    if not missing:
        return None
    candidates = [
        candidate
        for item in missing
        for candidate in _candidate_evidence_reviews(hypothesis, item, contracts)
    ]
    if not candidates:
        candidates = [_generic_review_candidate(hypothesis, missing[0])]
    candidates.sort(key=lambda item: (-float(item["safety_score"]), -float(item["evidence_value"]), item["evidence_id"]))
    selected = candidates[0]
    alternatives = [
        _lower_value_alternative(candidate, selected)
        for candidate in _unique_alternative_candidates(candidates[1:], selected)[:3]
    ]
    if not alternatives:
        alternatives = [
            {
                "evidence_id": "defer_runtime_validation",
                "description": "Creating or dispatching a runtime task is lower value for this planner because the current gap can be framed as operator evidence review first.",
                "lower_value_reason": "Would move from evidence planning into runtime action and therefore requires a separate approval-aware workflow.",
                "runner_capability_metadata": None,
            }
        ]
    priority_score = round(
        float(hypothesis.get("confidence") or 0.0) * 0.55
        + float(selected["evidence_value"]) * 0.3
        + float(selected["safety_score"]) * 0.15,
        3,
    )
    return {
        "id": f"next-evidence:{hypothesis.get('hypothesis_type')}:{selected['evidence_id']}",
        "rank": 0,
        "hypothesis_id": hypothesis.get("id"),
        "hypothesis_type": hypothesis.get("hypothesis_type"),
        "hypothesis_title": hypothesis.get("title"),
        "confidence": hypothesis.get("confidence"),
        "confidence_label": hypothesis.get("confidence_label"),
        "priority_score": priority_score,
        "recommended_missing_evidence": {
            "id": selected["evidence_id"],
            "description": selected["description"],
            "expected_evidence_refs": selected["expected_evidence_refs"],
        },
        "safest_next_validation": {
            "action_type": "operator_evidence_review",
            "description": selected["description"],
            "rationale": selected["rationale"],
            "why_safest": selected["why_safest"],
            "operator_review_only": True,
            "creates_tasks": False,
            "dispatches_work": False,
            "approves_proposals": False,
            "mutates_scope": False,
            "materializes_secrets": False,
            "uses_credentials": False,
            "accesses_live_targets": False,
        },
        "runner_capability_metadata": selected["runner_capability_metadata"],
        "lower_value_alternatives": alternatives,
        "supporting_evidence_refs": _evidence_refs(hypothesis.get("supporting_evidence")),
        "contradicting_evidence_refs": _evidence_refs(hypothesis.get("contradicting_evidence")),
        "recommendation_contract": _execution_contract(),
        "provenance": {
            "source": "hypothesis_confidence_report",
            "runner_contract_matrix_version": "runner-contract-matrix-v1",
            "dispatches_work": False,
            "approval_gates_bypassed": False,
            "scope_roe_bypassed": False,
        },
    }


def _candidate_evidence_reviews(
    hypothesis: dict[str, Any],
    missing_item: dict[str, Any],
    contracts: dict[str, dict[str, Any]],
) -> list[dict[str, Any]]:
    evidence_id = str(missing_item.get("id") or "missing_evidence")
    keywords = _evidence_keywords(hypothesis.get("hypothesis_type"), evidence_id)
    candidates: list[dict[str, Any]] = []
    for contract in contracts.values():
        text = _contract_text(contract)
        matched = sorted({keyword for keyword in keywords if keyword and keyword in text})
        runner = str(contract.get("runner") or "")
        if not matched and runner not in _preferred_runners(hypothesis.get("hypothesis_type"), evidence_id):
            continue
        safety_score = _contract_safety_score(contract)
        evidence_value = min(1.0, 0.44 + len(matched) * 0.08 + len(_as_list(contract.get("expected_evidence"))) * 0.01)
        metadata = _runner_metadata(contract, matched)
        candidates.append(
            {
                "evidence_id": evidence_id,
                "description": str(missing_item.get("description") or evidence_id),
                "expected_evidence_refs": _expected_refs(evidence_id, contract),
                "safety_score": round(safety_score, 3),
                "evidence_value": round(evidence_value, 3),
                "runner_capability_metadata": metadata,
                "rationale": (
                    f"Review existing or imported evidence for `{evidence_id}` using the "
                    f"{runner} capability contract as a metadata guide, without launching that runner."
                ),
                "why_safest": _why_safest(contract),
            }
        )
    return candidates


def _generic_review_candidate(hypothesis: dict[str, Any], missing_item: dict[str, Any]) -> dict[str, Any]:
    evidence_id = str(missing_item.get("id") or "missing_evidence")
    return {
        "evidence_id": evidence_id,
        "description": str(missing_item.get("description") or evidence_id),
        "expected_evidence_refs": [evidence_id],
        "safety_score": 1.0,
        "evidence_value": 0.5,
        "runner_capability_metadata": None,
        "rationale": (
            f"Review operator-provided or imported records for `{evidence_id}` before considering any runtime validation."
        ),
        "why_safest": "It can be performed from existing evidence and does not require any runner, credential, scope, or approval change.",
    }


def _lower_value_alternative(candidate: dict[str, Any], selected: dict[str, Any]) -> dict[str, Any]:
    metadata = candidate.get("runner_capability_metadata")
    selected_metadata = selected.get("runner_capability_metadata") or {}
    risk = _safe_metadata_value(metadata, "risk_tier")
    selected_risk = _safe_metadata_value(selected_metadata, "risk_tier")
    reason = "Lower evidence value for the current missing evidence."
    if _risk_rank(risk) > _risk_rank(selected_risk):
        reason = f"Higher runner risk tier ({risk}) than the selected metadata guide ({selected_risk})."
    elif candidate.get("safety_score") < selected.get("safety_score"):
        reason = "Lower safety score because the contract has more approval, cost, or risk friction."
    return {
        "evidence_id": candidate["evidence_id"],
        "description": candidate["description"],
        "lower_value_reason": reason,
        "runner_capability_metadata": metadata,
    }


def _unique_alternative_candidates(
    candidates: list[dict[str, Any]],
    selected: dict[str, Any],
) -> list[dict[str, Any]]:
    selected_runner = _safe_metadata_value(selected.get("runner_capability_metadata"), "runner")
    seen: set[str] = {selected_runner}
    unique: list[dict[str, Any]] = []
    for candidate in candidates:
        runner = _safe_metadata_value(candidate.get("runner_capability_metadata"), "runner")
        key = runner or str(candidate.get("evidence_id") or "")
        if key in seen:
            continue
        seen.add(key)
        unique.append(candidate)
    return unique


def _contract_lookup() -> dict[str, dict[str, Any]]:
    matrix = runner_contract_matrix()
    return {
        str(contract.get("runner")): contract
        for contract in _as_list(matrix.get("contracts"))
        if isinstance(contract, dict)
    }


def _runner_metadata(contract: dict[str, Any], matched_terms: list[str]) -> dict[str, Any]:
    return {
        "runner": contract.get("runner"),
        "contract_id": contract.get("contract_id"),
        "contract_version": contract.get("contract_version"),
        "risk_tier": contract.get("risk_tier"),
        "cost": contract.get("cost"),
        "approval": contract.get("approval"),
        "expected_evidence": _as_list(contract.get("expected_evidence")),
        "trigger_signals": contract.get("trigger_signals"),
        "report_mapping": _as_list(contract.get("report_mapping")),
        "matched_terms": matched_terms,
        "metadata_source": contract.get("metadata_source"),
    }


def _contract_safety_score(contract: dict[str, Any]) -> float:
    approval = contract.get("approval") if isinstance(contract.get("approval"), dict) else {}
    approval_penalty = 0.18 if approval.get("required") else 0.0
    return max(
        0.05,
        min(
            1.0,
            RISK_SAFETY.get(str(contract.get("risk_tier") or "active"), 0.55) * 0.55
            + COST_SAFETY.get(str(contract.get("cost") or "medium"), 0.55) * 0.35
            + 0.1
            - approval_penalty,
        ),
    )


def _why_safest(contract: dict[str, Any]) -> str:
    risk = str(contract.get("risk_tier") or "unknown")
    cost = str(contract.get("cost") or "unknown")
    approval = contract.get("approval") if isinstance(contract.get("approval"), dict) else {}
    approval_text = "no approval-required execution contract" if not approval.get("required") else "approval-required metadata, so review must stop before runtime"
    return (
        f"It uses existing evidence review guided by a {risk}/{cost} runner contract with {approval_text}; "
        "the planner does not create the runner task."
    )


def _expected_refs(evidence_id: str, contract: dict[str, Any]) -> list[str]:
    refs = [evidence_id]
    refs.extend(str(item) for item in _as_list(contract.get("expected_evidence"))[:3])
    return sorted(set(refs))


def _evidence_keywords(hypothesis_type: object, evidence_id: str) -> set[str]:
    base = set(str(evidence_id).replace("_", " ").split())
    by_hypothesis = {
        "idor": {"auth", "role", "boundary", "access", "client", "state", "session"},
        "oauth_scope": {"oauth", "scope", "config", "redirect", "iam", "inventory"},
        "ssrf_to_cloud": {"ssrf", "server", "fetch", "cloud", "aws", "iam", "inventory", "parameter"},
        "weak_auth": {"auth", "session", "cookie", "login", "flow", "policy"},
        "saas_connector_exposure": {"oauth", "connector", "export", "inventory", "iam", "scope"},
    }
    base.update(by_hypothesis.get(str(hypothesis_type), set()))
    return {item.lower() for item in base if item}


def _preferred_runners(hypothesis_type: object, evidence_id: str) -> set[str]:
    runners = {
        "idor": {"auth-flow", "client-state", "session-security"},
        "oauth_scope": {"oauth-probe", "aws-inventory"},
        "ssrf_to_cloud": {"ssrf-probe", "aws-inventory", "cloud-native"},
        "weak_auth": {"auth-flow", "session-security", "oauth-probe"},
        "saas_connector_exposure": {"oauth-probe", "aws-inventory", "external-osint"},
    }
    result = set(runners.get(str(hypothesis_type), set()))
    if "audit" in evidence_id:
        result.add("external-osint")
    return result


def _contract_text(contract: dict[str, Any]) -> str:
    parts = [
        contract.get("runner"),
        contract.get("trigger_signals"),
        contract.get("prerequisites"),
        contract.get("expected_evidence"),
        contract.get("follow_up_candidates"),
        contract.get("report_mapping"),
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


def _evidence_refs(items: object) -> list[str]:
    refs: list[str] = []
    for item in _as_list(items):
        if not isinstance(item, dict):
            continue
        refs.extend(str(ref) for ref in _as_list(item.get("evidence_refs")) if str(ref))
    return sorted(set(refs))


def _safe_metadata_value(metadata: object, key: str) -> str:
    return str(metadata.get(key) if isinstance(metadata, dict) else "none")


def _risk_rank(risk: str) -> int:
    return {"passive": 0, "active": 1, "intrusive": 2}.get(str(risk), 3)


def _execution_contract() -> dict[str, bool]:
    return {
        "analysis_only": True,
        "operator_review_only": True,
        "dispatches_work_directly": False,
        "creates_tasks": False,
        "approves_proposals": False,
        "mutates_approvals": False,
        "mutates_scope": False,
        "materializes_secrets": False,
        "uses_credentials": False,
        "accesses_live_targets": False,
        "runtime_self_modification": False,
    }


def _as_list(value: object) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, tuple | set):
        return list(value)
    return [value]
