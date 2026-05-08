from __future__ import annotations

from collections import Counter
from typing import Any
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from api.app.models import Finding, Run
from api.app.services.attack_paths import build_attack_path_summary

ADVISOR_MODEL = "deterministic-ai-choke-point-remediation-v1"
SEVERITY_WEIGHTS = {
    "critical": 10.0,
    "high": 7.0,
    "medium": 4.0,
    "low": 1.5,
    "info": 0.5,
    "unknown": 0.0,
}
EFFORT_BY_NODE_TYPE = {
    "identity_subject": 1.0,
    "identity_group": 1.0,
    "cloud_iam_principal": 1.1,
    "cloud_iam_policy": 1.1,
    "cloud_security_group": 1.2,
    "endpoint": 1.3,
    "service": 1.4,
    "kubernetes_workload": 1.5,
    "kubernetes_cluster": 1.7,
    "host": 1.8,
    "cloud_resource": 1.8,
}


def build_choke_point_remediation_advisor(
    session: Session,
    *,
    run_id: UUID | str,
) -> dict[str, Any] | None:
    attack_graph = build_attack_path_summary(session, run_id)
    if attack_graph is None:
        return None

    run = _load_run(session, UUID(str(attack_graph["run_id"])))
    if run is None:
        return None

    candidate_paths = list(attack_graph.get("candidate_paths") or [])
    choke_points = list(attack_graph.get("choke_points") or [])
    findings_by_id = _findings_by_id(run)
    recommendations = [
        _recommendation(
            choke=choke,
            candidate_paths=candidate_paths,
            total_path_count=len(candidate_paths),
            findings_by_id=findings_by_id,
        )
        for choke in choke_points
    ]
    recommendations = sorted(
        recommendations,
        key=lambda item: (-float(item["efficiency_score"]), -int(item["breaks_candidate_path_count"]), item["label"]),
    )

    return {
        "status": "ready" if recommendations else attack_graph.get("status", "empty"),
        "run_id": str(run.id),
        "engagement_id": str(run.engagement_id),
        "advisor_model": ADVISOR_MODEL,
        "source_attack_graph_model": attack_graph.get("evaluation_model"),
        "summary": {
            "candidate_path_count": len(candidate_paths),
            "choke_point_count": len(choke_points),
            "recommendation_count": len(recommendations),
            "top_recommendation": recommendations[0]["label"] if recommendations else None,
            "cloud_context_available": _cloud_context_available(attack_graph),
            "drift_context_available": run.drift_summary is not None,
        },
        "recommendations": recommendations,
        "proof_of_resolution": _proof_of_resolution_summary(recommendations),
        "drift_context": _drift_context(run),
        "cloud_context": _cloud_context(attack_graph),
        "execution_contract": {
            "planning_only": True,
            "dispatches_work": False,
            "creates_tasks": False,
            "creates_findings": False,
            "registered_runner_required_for_future_tests": True,
            "approval_gates_bypassed": False,
            "scope_enforced": True,
            "roe_enforced": True,
            "kill_switch_still_authoritative": True,
            "operator_next_step": (
                "Review the recommended choke point, remediate the linked finding group, then use the existing "
                "single-finding retest or validation workflow for controlled proof."
            ),
        },
        "evidence_basis": {
            "attack_path_endpoint": f"/api/v1/runs/{run.id}/attack-paths",
            "candidate_path_ids": [str(path.get("id")) for path in candidate_paths if path.get("id")],
            "finding_ids": sorted(findings_by_id.keys()),
            "drift_summary_id": str(run.drift_summary.id) if run.drift_summary is not None else None,
        },
    }


def _load_run(session: Session, run_id: UUID) -> Run | None:
    return session.scalar(
        select(Run)
        .options(
            selectinload(Run.findings).selectinload(Finding.remediation),
            selectinload(Run.findings).selectinload(Finding.validation_records),
            selectinload(Run.drift_summary),
        )
        .where(Run.id == run_id, Run.deleted_at.is_(None))
    )


def _findings_by_id(run: Run) -> dict[str, Finding]:
    return {str(finding.id): finding for finding in list(run.findings or [])}


def _recommendation(
    *,
    choke: dict[str, Any],
    candidate_paths: list[dict[str, Any]],
    total_path_count: int,
    findings_by_id: dict[str, Finding],
) -> dict[str, Any]:
    node_id = str(choke.get("node_id") or "")
    affected_paths = [path for path in candidate_paths if node_id in list(path.get("node_ids") or [])]
    affected_finding_ids = sorted(
        {
            str(path.get("finding_id") or "")
            for path in affected_paths
            if str(path.get("finding_id") or "")
        }
        | {str(item) for item in list(choke.get("affected_findings") or []) if str(item)}
    )
    affected_findings = [findings_by_id[finding_id] for finding_id in affected_finding_ids if finding_id in findings_by_id]
    severity_breakdown = _severity_breakdown(choke, affected_findings)
    path_count = int(choke.get("path_count") or len(affected_paths))
    effort = EFFORT_BY_NODE_TYPE.get(str(choke.get("type") or ""), 1.6)
    severity_score = sum(SEVERITY_WEIGHTS.get(severity, 0.0) * count for severity, count in severity_breakdown.items())
    efficiency_score = round(((path_count * 10.0) + (len(affected_finding_ids) * 3.0) + severity_score) / effort, 2)
    percent = round((path_count / total_path_count) * 100, 1) if total_path_count else 0.0

    return {
        "node_id": node_id,
        "type": choke.get("type"),
        "label": choke.get("label"),
        "breaks_candidate_path_count": path_count,
        "breaks_candidate_path_percent": percent,
        "affected_finding_count": len(affected_finding_ids),
        "affected_findings": [_finding_payload(finding) for finding in affected_findings],
        "candidate_path_ids": [str(path.get("id")) for path in affected_paths if path.get("id")],
        "severity_breakdown": dict(sorted(severity_breakdown.items())),
        "estimated_effort": _effort_label(effort),
        "impact_score": round((path_count * 10.0) + severity_score, 2),
        "efficiency_score": efficiency_score,
        "recommended_action": _recommended_action(choke),
        "proof_of_resolution_plan": [_proof_plan_for_finding(finding) for finding in affected_findings],
        "evidence_refs": _evidence_refs(affected_paths, affected_findings),
        "rationale": (
            f"{choke.get('label')} appears in {path_count} of {total_path_count} candidate path(s). "
            f"Addressing this choke point first can retire {percent}% of currently modelled paths, "
            "then existing validation/retest flows should produce controlled proof."
        ),
    }


def _severity_breakdown(choke: dict[str, Any], findings: list[Finding]) -> Counter[str]:
    if isinstance(choke.get("severity_breakdown"), dict) and choke["severity_breakdown"]:
        return Counter({str(key): int(value) for key, value in choke["severity_breakdown"].items()})
    return Counter(str(finding.severity or "unknown").lower() for finding in findings)


def _finding_payload(finding: Finding) -> dict[str, Any]:
    return {
        "finding_id": str(finding.id),
        "title": finding.title,
        "severity": finding.severity,
        "target_id": finding.target_id,
        "status": finding.status,
        "evidence_ref": finding.evidence_ref,
        "remediation_state": finding.remediation.state if finding.remediation is not None else "not_started",
        "validation_status": finding.validation_status,
    }


def _proof_plan_for_finding(finding: Finding) -> dict[str, Any]:
    records = list(finding.validation_records or [])
    replay_recipe = finding.replay_recipe_json if isinstance(finding.replay_recipe_json, dict) else {}
    latest_record = sorted(records, key=lambda record: (record.created_at, record.id), reverse=True)[0] if records else None
    validator_tool = (
        latest_record.validator_tool
        if latest_record is not None and latest_record.validator_tool
        else replay_recipe.get("tool")
        or replay_recipe.get("runner")
        or "existing-single-finding-retest"
    )
    return {
        "finding_id": str(finding.id),
        "mode": "planning_only",
        "proof_type": "controlled proof",
        "recommended_validator_tool": validator_tool,
        "target": finding.target_id,
        "replay_recipe_available": bool(replay_recipe),
        "existing_validation_count": len(records),
        "latest_validation_status": latest_record.status if latest_record is not None else finding.validation_status,
        "latest_validation_evidence_ref": latest_record.evidence_ref if latest_record is not None else None,
        "next_step": (
            "Use the existing validation/retest workflow after remediation; this advisor does not queue or run the proof."
        ),
    }


def _recommended_action(choke: dict[str, Any]) -> str:
    label = str(choke.get("label") or "the selected choke point")
    node_type = str(choke.get("type") or "")
    if node_type in {"identity_subject", "identity_group", "cloud_iam_principal", "cloud_iam_policy"}:
        return (
            f"Prioritize least-privilege review, access removal, and session exposure risk reduction for {label}; "
            "confirm with audit-backed identity or IAM evidence."
        )
    if node_type == "cloud_security_group":
        return (
            f"Restrict the exposed security-group path around {label}, then confirm with read-only cloud inventory "
            "and controlled proof from the affected finding set."
        )
    if node_type in {"endpoint", "service"}:
        return f"Patch or harden {label} at the shared exposure point before retesting the linked findings."
    if node_type == "host":
        return f"Prioritize hardening {label} because it concentrates multiple evidence-backed paths."
    if node_type.startswith("kubernetes"):
        return f"Review Kubernetes exposure and workload policy around {label} using read-only cluster evidence."
    return f"Review and remediate {label} first because it concentrates multiple evidence-backed paths."


def _effort_label(effort: float) -> str:
    if effort <= 1.15:
        return "low"
    if effort <= 1.5:
        return "medium"
    return "high"


def _evidence_refs(paths: list[dict[str, Any]], findings: list[Finding]) -> list[str]:
    refs = []
    for finding in findings:
        if finding.evidence_ref and finding.evidence_ref not in refs:
            refs.append(finding.evidence_ref)
    for path in paths:
        for ref in list(path.get("evidence_refs") or []):
            ref_text = str(ref or "").strip()
            if ref_text and ref_text not in refs:
                refs.append(ref_text)
    return refs


def _proof_of_resolution_summary(recommendations: list[dict[str, Any]]) -> dict[str, Any]:
    plans = [
        proof
        for recommendation in recommendations
        for proof in list(recommendation.get("proof_of_resolution_plan") or [])
    ]
    return {
        "planning_only": True,
        "finding_count": len({str(plan.get("finding_id")) for plan in plans}),
        "replay_ready_count": sum(1 for plan in plans if plan.get("replay_recipe_available") is True),
        "existing_validation_record_count": sum(int(plan.get("existing_validation_count") or 0) for plan in plans),
        "boundary": (
            "The advisor identifies controlled proof candidates only. Future proof runs must use existing "
            "registered runners, scope checks, ROE, approval gates, provenance, and kill switch."
        ),
    }


def _drift_context(run: Run) -> dict[str, Any]:
    drift = run.drift_summary
    if drift is None:
        return {
            "available": False,
            "reason": "No run drift summary is linked to this run yet.",
        }
    return {
        "available": True,
        "drift_summary_id": str(drift.id),
        "previous_run_id": str(drift.previous_run_id),
        "new_finding_count": drift.new_finding_count,
        "resolved_finding_count": drift.resolved_finding_count,
        "exposure_delta": drift.exposure_delta,
        "computed_at": drift.computed_at.isoformat(),
    }


def _cloud_context_available(attack_graph: dict[str, Any]) -> bool:
    return bool(_cloud_context(attack_graph)["available"])


def _cloud_context(attack_graph: dict[str, Any]) -> dict[str, Any]:
    nodes = list(attack_graph.get("nodes") or [])
    inferred_edges = list(attack_graph.get("inferred_edges") or [])
    cloud_native_paths = list(attack_graph.get("cloud_native_attack_paths") or [])
    cloud_node_types = {
        "cloud_resource",
        "cloud_security_group",
        "cloud_iam_principal",
        "cloud_iam_policy",
        "kubernetes_cluster",
        "kubernetes_workload",
    }
    cloud_nodes = [node for node in nodes if str(node.get("type") or "") in cloud_node_types]
    cloud_edges = [
        edge
        for edge in inferred_edges
        if "cloud" in str(edge.get("type") or "") or "kubernetes" in str(edge.get("type") or "") or "iam" in str(edge.get("type") or "")
    ]
    return {
        "available": bool(cloud_nodes or cloud_edges),
        "cloud_node_count": len(cloud_nodes),
        "cloud_inferred_edge_count": len(cloud_edges),
        "cloud_native_attack_path_count": len(cloud_native_paths),
        "cloud_native_attack_path_ids": [
            str(path.get("id")) for path in cloud_native_paths if path.get("id")
        ],
        "cloud_node_types": sorted({str(node.get("type")) for node in cloud_nodes}),
        "cloud_edge_types": sorted({str(edge.get("type")) for edge in cloud_edges}),
        "boundary": (
            "Cloud and Kubernetes context is read-only attack-graph analysis. It does not mutate cloud resources, "
            "expand scope, test credentials, or dispatch cloud actions."
        ),
    }
