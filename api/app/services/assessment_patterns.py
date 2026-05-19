from __future__ import annotations

from collections import Counter, defaultdict
from typing import Any
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from api.app.models import (
    CapabilityPack,
    CapabilityPackApproval,
    CapabilityPackDeployment,
    CapabilityPackValidationResult,
    Engagement,
    Finding,
    Run,
)

REMEDIATED_FINDING_STATUSES = {"resolved", "closed", "verified"}
REMEDIATED_REMEDIATION_STATES = {"verified", "remediated", "fixed", "closed"}
SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def build_assessment_pattern_library(session: Session, *, engagement: Engagement) -> dict[str, Any]:
    runs = _load_engagement_runs(session, engagement.id)
    packs = _load_engagement_packs(session, engagement.id)
    findings = [finding for run in runs for finding in run.findings]

    latest_run_id = runs[-1].id if runs else None
    patterns = _build_patterns(findings, latest_run_id=latest_run_id)
    pack_effectiveness = _build_pack_effectiveness(packs=packs, runs=runs, findings=findings)
    sparse_data = len(runs) < 2 or not findings

    return {
        "engagement_id": str(engagement.id),
        "mode": "local_advisory",
        "summary": {
            "run_count": len(runs),
            "finding_count": len(findings),
            "pattern_count": len(patterns),
            "pack_count": len(packs),
            "sparse_data": sparse_data,
            "risk_posture_counts": _risk_posture_counts(patterns),
            "recurrence_counts": dict(Counter(pattern["recurrence_signal"] for pattern in patterns)),
        },
        "data_scope": {
            "engagement_scoped": True,
            "tenant_id": engagement.tenant_id,
            "tenant_boundary_enforced_by_route": True,
            "cross_tenant_pattern_sharing": False,
            "source": "local_stored_aegispt_records",
        },
        "patterns": patterns,
        "pack_effectiveness": pack_effectiveness,
        "boundary": _advisory_boundary(),
        "limitations": _limitations(sparse_data=sparse_data),
    }


def _load_engagement_runs(session: Session, engagement_id: UUID) -> list[Run]:
    return list(
        session.scalars(
            select(Run)
            .options(
                selectinload(Run.profile),
                selectinload(Run.bound_pack),
                selectinload(Run.bound_pack_deployment),
                selectinload(Run.agent_proposals),
                selectinload(Run.findings).selectinload(Finding.remediation),
            )
            .where(Run.engagement_id == engagement_id, Run.deleted_at.is_(None))
            .order_by(Run.created_at.asc(), Run.id.asc())
        ).all()
    )


def _load_engagement_packs(session: Session, engagement_id: UUID) -> list[CapabilityPack]:
    return list(
        session.scalars(
            select(CapabilityPack)
            .options(
                selectinload(CapabilityPack.validation_results),
                selectinload(CapabilityPack.approvals),
                selectinload(CapabilityPack.deployments),
                selectinload(CapabilityPack.bound_runs),
                selectinload(CapabilityPack.generated_findings),
            )
            .where(CapabilityPack.engagement_id == engagement_id)
            .order_by(CapabilityPack.created_at.asc(), CapabilityPack.id.asc())
        ).all()
    )


def _build_patterns(findings: list[Finding], *, latest_run_id: UUID | None) -> list[dict[str, Any]]:
    grouped_findings: dict[str, list[Finding]] = defaultdict(list)
    for finding in findings:
        grouped_findings[_pattern_key(finding)].append(finding)

    patterns: list[dict[str, Any]] = []
    for key, group in grouped_findings.items():
        ordered = sorted(group, key=lambda item: (item.created_at, item.id.hex))
        run_ids = _unique_strings(finding.run_id for finding in ordered if finding.run_id is not None)
        recurrence_signal = "recurring" if len(run_ids) > 1 else "single_observation"
        posture_signal = _posture_signal(ordered, latest_run_id=latest_run_id)
        latest = ordered[-1]
        remediation_states = [
            finding.remediation.state
            for finding in ordered
            if finding.remediation is not None and finding.remediation.state
        ]

        patterns.append(
            {
                "key": key,
                "title": latest.title,
                "target_id": latest.target_id,
                "highest_severity": _highest_severity(finding.severity for finding in ordered),
                "occurrence_count": len(ordered),
                "run_ids": run_ids,
                "finding_ids": [str(finding.id) for finding in ordered],
                "methodology_tags": sorted({tag for finding in ordered for tag in (finding.methodology_tags or [])}),
                "status_history": [finding.status for finding in ordered],
                "remediation_states": remediation_states,
                "first_seen_at": ordered[0].created_at,
                "last_seen_at": latest.created_at,
                "recurrence_signal": recurrence_signal,
                "posture_signal": posture_signal,
                "advisory_note": _pattern_note(
                    posture_signal=posture_signal,
                    recurrence_signal=recurrence_signal,
                ),
            }
        )

    return sorted(patterns, key=lambda item: (item["posture_signal"], item["title"], item["target_id"]))


def _build_pack_effectiveness(
    *,
    packs: list[CapabilityPack],
    runs: list[Run],
    findings: list[Finding],
) -> dict[str, Any]:
    runs_by_pack_id: dict[UUID, list[Run]] = defaultdict(list)
    for run in runs:
        if run.bound_pack_id is not None:
            runs_by_pack_id[run.bound_pack_id].append(run)

    findings_by_pack_id: dict[UUID, list[Finding]] = defaultdict(list)
    for finding in findings:
        if finding.source_pack_id is not None:
            findings_by_pack_id[finding.source_pack_id].append(finding)
        elif finding.run is not None and finding.run.bound_pack_id is not None:
            findings_by_pack_id[finding.run.bound_pack_id].append(finding)

    pack_summaries = [
        _pack_effectiveness_summary(
            pack,
            bound_runs=runs_by_pack_id.get(pack.id, []),
            generated_findings=findings_by_pack_id.get(pack.id, []),
        )
        for pack in packs
    ]

    return {
        "mode": "advisory_only",
        "automatic_pack_promotion_performed": False,
        "automatic_pack_deployment_performed": False,
        "automatic_pack_mutation_performed": False,
        "automatic_pack_approval_performed": False,
        "runtime_binding_changed": False,
        "pack_count": len(pack_summaries),
        "packs": pack_summaries,
    }


def _pack_effectiveness_summary(
    pack: CapabilityPack,
    *,
    bound_runs: list[Run],
    generated_findings: list[Finding],
) -> dict[str, Any]:
    validation_counts = _status_counts(pack.validation_results)
    approval_counts = _approval_counts(pack.approvals)
    deployment_counts = _deployment_counts(pack.deployments)
    proposal_counts = _proposal_counts(bound_runs)

    return {
        "pack_id": str(pack.id),
        "name": pack.name,
        "version": pack.version,
        "status": pack.status,
        "generation_mode": pack.generation_mode,
        "bound_run_count": len(bound_runs),
        "generated_finding_count": len({finding.id for finding in generated_findings}),
        "validation_outcomes": validation_counts,
        "approval_outcomes": approval_counts,
        "deployment_outcomes": deployment_counts,
        "proposal_outcomes": proposal_counts,
        "quality_signals": _pack_quality_signals(
            pack=pack,
            validation_counts=validation_counts,
            deployment_counts=deployment_counts,
            generated_findings=generated_findings,
        ),
        "advisory_only": True,
        "next_operator_boundary": (
            "Use existing validation, approval, deployment, and runtime binding gates; "
            "this analysis does not promote, deploy, mutate, approve, or bind packs."
        ),
    }


def _pattern_key(finding: Finding) -> str:
    parts = [
        _normalize_key_part(finding.title),
        _normalize_key_part(finding.target_id),
        _normalize_key_part(finding.control_family or finding.wstg_id or finding.asvs_reference or ""),
    ]
    return "|".join(parts)


def _normalize_key_part(value: str | None) -> str:
    return " ".join((value or "unknown").casefold().strip().split())


def _posture_signal(findings: list[Finding], *, latest_run_id: UUID | None) -> str:
    latest = findings[-1]
    if _is_remediated(latest):
        return "remediated"
    unique_run_ids = {finding.run_id for finding in findings if finding.run_id is not None}
    if len(unique_run_ids) > 1:
        return "persistent"
    if latest_run_id is not None and latest.run_id == latest_run_id:
        return "new"
    return "persistent"


def _is_remediated(finding: Finding) -> bool:
    if finding.status in REMEDIATED_FINDING_STATUSES:
        return True
    remediation = finding.remediation
    return remediation is not None and remediation.state in REMEDIATED_REMEDIATION_STATES


def _highest_severity(severities: Any) -> str:
    ordered = [str(severity or "info").lower() for severity in severities]
    if not ordered:
        return "info"
    return max(ordered, key=lambda severity: SEVERITY_RANK.get(severity, -1))


def _unique_strings(values: Any) -> list[str]:
    seen: set[str] = set()
    ordered_values: list[str] = []
    for value in values:
        item = str(value)
        if item not in seen:
            ordered_values.append(item)
            seen.add(item)
    return ordered_values


def _status_counts(records: list[CapabilityPackValidationResult]) -> dict[str, int]:
    return dict(Counter(record.status for record in records))


def _approval_counts(records: list[CapabilityPackApproval]) -> dict[str, int]:
    return dict(Counter(record.decision for record in records))


def _deployment_counts(records: list[CapabilityPackDeployment]) -> dict[str, int]:
    return dict(Counter(record.status for record in records))


def _proposal_counts(bound_runs: list[Run]) -> dict[str, int]:
    return dict(Counter(proposal.status for run in bound_runs for proposal in run.agent_proposals))


def _pack_quality_signals(
    *,
    pack: CapabilityPack,
    validation_counts: dict[str, int],
    deployment_counts: dict[str, int],
    generated_findings: list[Finding],
) -> list[str]:
    signals: list[str] = []
    if validation_counts.get("failed", 0) > 0:
        signals.append("validation_blockers_present")
    if not validation_counts:
        signals.append("needs_validation_before_promotion")
    if pack.status == "approved" and not deployment_counts:
        signals.append("approved_not_deployed")
    if generated_findings:
        signals.append("observed_findings_from_pack_bound_runs")
    if not signals:
        signals.append("insufficient_pack_outcome_data")
    return signals


def _risk_posture_counts(patterns: list[dict[str, Any]]) -> dict[str, int]:
    counts = Counter(pattern["posture_signal"] for pattern in patterns)
    counts["recurring"] = sum(1 for pattern in patterns if pattern["recurrence_signal"] == "recurring")
    return {key: int(counts.get(key, 0)) for key in ["persistent", "remediated", "recurring", "new"]}


def _pattern_note(*, posture_signal: str, recurrence_signal: str) -> str:
    if posture_signal == "remediated":
        return "Stored records indicate remediation or verification; this does not guarantee risk reduction."
    if posture_signal == "persistent":
        return "Stored records indicate the issue remains observable or unresolved across available evidence."
    if recurrence_signal == "recurring":
        return "Stored records indicate repeated observation across runs."
    return "Stored records indicate a new local observation in the current assessment window."


def _advisory_boundary() -> dict[str, Any]:
    return {
        "advisory_only": True,
        "local_records_only": True,
        "external_model_training_performed": False,
        "customer_data_exported": False,
        "third_party_analytics_used": False,
        "automatic_pack_promotion_performed": False,
        "automatic_pack_deployment_performed": False,
        "automatic_pack_mutation_performed": False,
        "automatic_pack_approval_performed": False,
        "runtime_binding_changed": False,
        "risk_reduction_claimed": False,
    }


def _limitations(*, sparse_data: bool) -> list[str]:
    limitations = [
        "Signals are derived from local stored AegisPT records only.",
        "Recurring is a frequency signal and may overlap with persistent or remediated posture.",
        "Remediated signals reflect stored status or remediation records and do not claim guaranteed risk reduction.",
        "Pack effectiveness is advisory and cannot bypass validation, approval, deployment, or runtime binding gates.",
    ]
    if sparse_data:
        limitations.append(
            "Sparse data: at least two runs with findings are needed for stronger recurrence and persistence signals."
        )
    return limitations
