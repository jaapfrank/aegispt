from __future__ import annotations

import hashlib
import json
from collections import Counter
from html import escape
from types import SimpleNamespace
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from api.app.methodology import (
    ASVS_STABLE_VERSION,
    WSTG_STABLE_VERSION,
    control_family_label,
    default_nist_phase_for_run_class,
    default_ptes_phase_for_run_class,
    default_remediation_detail,
    default_remediation_summary,
    format_wstg_reference,
    nist_phase_label,
    operator_workflow_stage_for_run_class,
    ptes_phase_label,
    tool_wstg_areas,
    wstg_area_for_identifier,
)
from api.app.models import Approval, CapabilityPack, Engagement, EvidenceArtifact, Finding, Run, Scope, Task, ToolExecution
from api.app.schemas.report_center import RunReportCatalogItemRead
from api.app.services.codex_tasks import list_codex_tasks, load_codex_task_result
from api.app.services.secrets import sanitize_run_configuration
from api.app.services.inventory import aggregate_inventory_snapshots
from api.app.services.packs import latest_validation_for_pack

SEVERITY_ORDER = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "info": 4,
    "unknown": 5,
}

REMEDIATION_PRIORITY = {
    "critical": "Immediate",
    "high": "High",
    "medium": "Planned",
    "low": "Routine",
    "info": "Advisory",
    "unknown": "Review",
}

REPORT_VARIANT_LABELS = {
    "executive": "Executive Report",
    "technical": "Technical Report",
    "evidence": "Evidence Appendix",
    "retest": "Retest / Verification Report",
}

REPORT_VARIANT_DESCRIPTIONS = {
    "executive": "Leadership-ready summary of scope, outcomes, risk posture, and next steps.",
    "technical": "Full technical narrative with methodology, findings, evidence, and remediation detail.",
    "evidence": "Artifact-oriented appendix for replay, validation, and operator review.",
    "retest": "Verification-focused output tracking open, fixed, and still-unverified items.",
}


def load_run_report(session: Session, run_id: UUID | str) -> Run | None:
    return session.scalar(
        select(Run)
        .options(
            selectinload(Run.engagement).selectinload(Engagement.scopes),
            selectinload(Run.engagement).selectinload(Engagement.inventory_snapshots),
            selectinload(Run.profile),
            selectinload(Run.bound_pack).selectinload(CapabilityPack.validation_results),
            selectinload(Run.bound_pack).selectinload(CapabilityPack.approvals),
            selectinload(Run.bound_pack).selectinload(CapabilityPack.deployments),
            selectinload(Run.bound_pack_deployment),
            selectinload(Run.approvals),
            selectinload(Run.findings),
            selectinload(Run.tasks)
            .selectinload(Task.executions)
            .selectinload(ToolExecution.artifacts),
        )
        .where(Run.id == run_id)
    )


def sort_findings(findings: list[Finding]) -> list[Finding]:
    return sorted(
        findings,
        key=lambda finding: (
            SEVERITY_ORDER.get(finding.severity, SEVERITY_ORDER["unknown"]),
            finding.title.lower(),
            finding.target_id.lower(),
        ),
    )


def sort_tasks(tasks: list[Task]) -> list[Task]:
    return sorted(tasks, key=lambda task: (task.tool, task.target_id, task.created_at, task.id.hex))


def sort_approvals(approvals: list[Approval]) -> list[Approval]:
    return sorted(approvals, key=lambda approval: (approval.created_at, approval.id.hex))


def sort_artifacts(artifacts: list[EvidenceArtifact]) -> list[EvidenceArtifact]:
    return sorted(
        artifacts,
        key=lambda artifact: (
            str(artifact.metadata_json.get("name", "")),
            artifact.created_at,
            artifact.id.hex,
        ),
    )


def artifact_download_path(artifact_id: UUID) -> str:
    return f"/api/v1/artifacts/{artifact_id}/content"


def task_targets_display(task: Task) -> str:
    configured_targets = task.params_json.get("targets")
    if isinstance(configured_targets, list):
        normalized_targets = [target.strip() for target in configured_targets if isinstance(target, str) and target.strip()]
        if normalized_targets:
            return ", ".join(normalized_targets)

    return task.target_id


def findings_summary(findings: list[Finding]) -> tuple[dict[str, int], dict[str, int]]:
    by_severity = dict(Counter(finding.severity for finding in findings))
    by_status = dict(Counter(finding.status for finding in findings))
    return by_severity, by_status


def latest_scope_for_engagement(engagement: Engagement | None) -> Scope | None:
    if engagement is None:
        return None
    if not engagement.scopes:
        return None
    return sorted(engagement.scopes, key=lambda scope: (scope.created_at, scope.id.hex), reverse=True)[0]


def effective_inventory_snapshot_for_run(run: Run):
    engagement = run.engagement
    if engagement is None:
        return None

    snapshots = list(engagement.inventory_snapshots or [])
    run_id = str(run.id)
    derived = sorted(
        (
            snapshot
            for snapshot in snapshots
            if str(snapshot.raw_inputs_json.get("run_id") or "") == run_id
        ),
        key=lambda snapshot: (snapshot.created_at, snapshot.id.hex),
        reverse=True,
    )
    if derived:
        aggregated = aggregate_inventory_snapshots(derived)
        if aggregated is not None:
            representative = derived[0]
            return SimpleNamespace(
                id=representative.id,
                engagement_id=representative.engagement_id,
                requested_by=representative.requested_by,
                status=representative.status,
                raw_inputs_json={"run_id": run_id, "aggregated_snapshot_count": len(derived)},
                normalized_inventory_json=aggregated["normalized_inventory_json"],
                summary_json=aggregated["summary_json"],
                source_tools_json=aggregated["source_tools_json"],
                environment_notes_json=aggregated["environment_notes_json"],
                assumptions_json=aggregated["assumptions_json"],
                confidence_score=aggregated["confidence_score"],
                created_at=representative.created_at,
            )
        return derived[0]

    if run.source_inventory_snapshot_id is not None:
        for snapshot in snapshots:
            if snapshot.id == run.source_inventory_snapshot_id:
                return snapshot
    return None


def format_json_block(payload: dict[str, object] | None) -> str:
    return json.dumps(payload or {}, indent=2, sort_keys=True)


def methodology_context_for_run(run: Run) -> dict[str, str]:
    run_class = run.profile.run_class if run.profile is not None else None
    ptes_phase = default_ptes_phase_for_run_class(run_class)
    nist_phase = default_nist_phase_for_run_class(run_class)
    return {
        "operator_stage": operator_workflow_stage_for_run_class(run_class),
        "ptes_phase": ptes_phase,
        "ptes_phase_label": ptes_phase_label(ptes_phase) or ptes_phase,
        "nist_phase": nist_phase,
        "nist_phase_label": nist_phase_label(nist_phase) or nist_phase,
    }


def adaptive_pack_context(run: Run) -> dict[str, object]:
    if run.bound_pack is None:
        return {
            "active": False,
            "label": "Standard baseline coverage only",
            "manifest": {},
            "deployment_target": None,
            "deployment_status": None,
        }

    deployment = run.bound_pack_deployment
    return {
        "active": True,
        "label": f"{run.bound_pack.name} {run.bound_pack.version}",
        "manifest": dict(run.bound_pack.manifest_json or {}),
        "deployment_target": deployment.deployment_target if deployment is not None else None,
        "deployment_status": deployment.status if deployment is not None else None,
    }


def _latest_pack_approval(run: Run):
    if run.bound_pack is None or not run.bound_pack.approvals:
        return None
    return sorted(
        run.bound_pack.approvals,
        key=lambda approval: (approval.created_at, approval.id.hex),
        reverse=True,
    )[0]


def _latest_pack_deployment(run: Run):
    if run.bound_pack_deployment is not None:
        return run.bound_pack_deployment
    if run.bound_pack is None or not run.bound_pack.deployments:
        return None
    return sorted(
        run.bound_pack.deployments,
        key=lambda deployment: (deployment.created_at, deployment.id.hex),
        reverse=True,
    )[0]


def _pack_related_codex_tasks(run: Run) -> list[object]:
    if run.bound_pack is None:
        return []

    pack_id = str(run.bound_pack.id)
    pack_version = str(run.bound_pack.version)
    related = []
    for task in list_codex_tasks():
        source_context = task.source_context
        if source_context.pack_id is None or str(source_context.pack_id) != pack_id:
            continue
        if source_context.pack_version and str(source_context.pack_version) != pack_version:
            continue
        related.append(task)

    return sorted(related, key=lambda item: (item.updated_at, item.created_at, item.id), reverse=True)


def _adaptive_findings_for_run(run: Run, findings: list[Finding]) -> list[Finding]:
    if run.bound_pack is None:
        return []

    pack_id = str(run.bound_pack.id)
    pack_version = str(run.bound_pack.version)
    linked: list[Finding] = []
    seen_ids: set[UUID] = set()
    for finding in findings:
        matches_pack = False
        if finding.source_pack_id is not None and str(finding.source_pack_id) == pack_id:
            matches_pack = True
        elif finding.source_pack_version and str(finding.source_pack_version) == pack_version:
            matches_pack = True
        elif finding.finding_origin == "adaptive_pack":
            matches_pack = True

        if matches_pack and finding.id not in seen_ids:
            linked.append(finding)
            seen_ids.add(finding.id)

    return linked


def adaptive_change_summary_for_run(run: Run, findings: list[Finding]) -> dict[str, object]:
    if run.bound_pack is None:
        return {
            "active": False,
            "review_state": "standard-baseline",
            "pack_label": "Standard baseline coverage only",
            "summary_line": "No adaptive pack is bound to this run, so the report reflects the standard baseline coverage path only.",
            "governance_line": "Codex build-lane review is not in scope for this run because no adaptive pack version is attached.",
            "finding_line": "No findings are linked to a bound adaptive pack for this run.",
            "change_highlights": [],
            "related_task_count": 0,
            "related_finding_count": 0,
            "finding_origin_breakdown": {},
            "methodology_tags": [],
            "source_threat_intel_refs": [],
            "latest_task": None,
        }

    pack = run.bound_pack
    validation = latest_validation_for_pack(pack)
    approval = _latest_pack_approval(run)
    deployment = _latest_pack_deployment(run)
    related_tasks = _pack_related_codex_tasks(run)
    latest_task = related_tasks[0] if related_tasks else None
    latest_result = load_codex_task_result(latest_task.id) if latest_task is not None else None
    related_findings = _adaptive_findings_for_run(run, findings)
    origin_breakdown = dict(Counter(finding.finding_origin for finding in related_findings))
    origin_summary = ", ".join(
        f"{count} {origin.replace('_', ' ')}"
        for origin, count in sorted(origin_breakdown.items())
    )
    generation_reason = str(pack.manifest_json.get("generation_reason") or "No generation reason recorded.")
    validation_status = validation.status if validation is not None else "not_run"
    approval_status = approval.decision if approval is not None else "not_requested"
    deployment_status = deployment.status if deployment is not None else "not_deployed"

    if latest_result is not None:
        review_state = "codex-prepared"
        summary_line = (
            f"Codex-reviewed adaptive coverage is bound through {pack.name} {pack.version}; "
            f"task {latest_task.id} prepared a supervised review bundle before promotion."
        )
    elif latest_task is not None:
        review_state = "codex-linked"
        summary_line = (
            f"Adaptive coverage is linked to Codex task {latest_task.id}, but no prepared review bundle "
            f"is recorded for this pack version yet."
        )
    else:
        review_state = "pack-only"
        summary_line = (
            f"Adaptive coverage is bound through {pack.name} {pack.version} in the supervised pack lane, "
            "but no linked Codex task is recorded for this pack version yet."
        )

    governance_line = (
        f"Pack status {pack.status}; validation {validation_status}; approval {approval_status}; "
        f"deployment {deployment_status}."
    )
    if related_findings:
        finding_line = (
            f"{len(related_findings)} findings in this run currently inherit bound-pack provenance"
            + (f" ({origin_summary})." if origin_summary else ".")
        )
    else:
        finding_line = "No findings in this run currently carry provenance from the bound adaptive pack."

    task_summary = None
    if latest_task is not None:
        task_summary = {
            "id": latest_task.id,
            "task_type": latest_task.task_type,
            "status": latest_task.status,
            "validation_status": latest_task.validation_status,
            "approval_status": latest_task.approval_status,
            "generation_reason": latest_task.generation_reason,
            "updated_at": latest_task.updated_at.isoformat(),
            "prepared_result_status": latest_result.status if latest_result is not None else None,
            "prepared_command_count": len(latest_result.prepared_commands) if latest_result is not None else 0,
            "prepared_output_count": len(latest_result.output_files) if latest_result is not None else 0,
        }

    change_highlights = [
        governance_line,
        (
            f"Latest Codex task {latest_task.id} ({latest_task.task_type}) is {latest_task.status} / "
            f"{latest_task.validation_status}; reason: {latest_task.generation_reason}."
            if latest_task is not None
            else f"Generation reason: {generation_reason}"
        ),
        finding_line,
    ]

    return {
        "active": True,
        "review_state": review_state,
        "pack_label": f"{pack.name} {pack.version}",
        "generation_mode": pack.generation_mode,
        "generation_reason": generation_reason,
        "summary_line": summary_line,
        "governance_line": governance_line,
        "finding_line": finding_line,
        "change_highlights": change_highlights,
        "related_task_count": len(related_tasks),
        "related_finding_count": len(related_findings),
        "finding_origin_breakdown": origin_breakdown,
        "methodology_tags": list(pack.methodology_tags),
        "source_threat_intel_refs": list(pack.source_threat_intel_refs_json),
        "latest_task": task_summary,
    }


def methodology_coverage_summary(findings: list[Finding], tasks: list[Task]) -> dict[str, list[str]]:
    wstg_areas = {
        area
        for area in (
            wstg_area_for_identifier(finding.wstg_id)
            for finding in findings
        )
        if area
    }
    if not wstg_areas:
        for task in tasks:
            wstg_areas.update(tool_wstg_areas(task.tool))

    control_families = {
        label
        for label in (
            control_family_label(finding.control_family)
            for finding in findings
        )
        if label
    }
    methodology_tags = {
        tag
        for finding in findings
        for tag in (finding.methodology_tags or [])
        if isinstance(tag, str) and tag.strip()
    }

    return {
        "wstg_areas": sorted(wstg_areas),
        "control_families": sorted(control_families),
        "methodology_tags": sorted(methodology_tags),
        "tools": sorted({task.tool for task in tasks}),
    }


def remediation_priority_for_finding(finding: Finding) -> str:
    return REMEDIATION_PRIORITY.get(finding.severity, REMEDIATION_PRIORITY["unknown"])


def replay_status_for_finding(finding: Finding) -> str:
    return "evidence-linked" if finding.evidence_ref else "not-linked"


def remediation_priority_counts(findings: list[Finding]) -> dict[str, int]:
    return dict(Counter(remediation_priority_for_finding(finding) for finding in findings))


def finding_methodology_lines(finding: Finding) -> list[str]:
    lines = [
        f"- PTES Phase: {ptes_phase_label(finding.ptes_phase) or 'Not Assigned'}",
        f"- NIST Phase: {nist_phase_label(finding.nist_phase) or 'Not Assigned'}",
        f"- WSTG Reference: {format_wstg_reference(finding.wstg_id, finding.wstg_version) or 'Not Assigned'}",
        f"- WSTG Area: {wstg_area_for_identifier(finding.wstg_id) or 'Not Assigned'}",
        f"- ASVS Reference: {finding.asvs_reference or 'Not Assigned'}",
        f"- Control Family: {control_family_label(finding.control_family) or 'Not Assigned'}",
        f"- Methodology Tags: {', '.join(finding.methodology_tags or []) or 'None'}",
        f"- Finding Origin: {finding.finding_origin}",
        f"- Source Pack Version: {finding.source_pack_version or 'Standard Coverage'}",
    ]
    return lines


def _humanize_key(value: str) -> str:
    return value.replace("_", " ").replace("-", " ").title()


def run_configuration_context(run: Run) -> dict[str, object]:
    configuration = sanitize_run_configuration(dict(run.configuration_json or {}))
    raw_modules = configuration.get("modules", {})
    enabled_modules = []
    if isinstance(raw_modules, dict):
        enabled_modules = sorted(
            _humanize_key(module)
            for module, enabled in raw_modules.items()
            if isinstance(module, str) and bool(enabled)
        )

    raw_targets = configuration.get("targets", {})
    normalized_targets: dict[str, list[str]] = {}
    if isinstance(raw_targets, dict):
        for key, values in raw_targets.items():
            if isinstance(key, str) and isinstance(values, list):
                normalized_targets[key] = [value for value in values if isinstance(value, str) and value.strip()]

    access = configuration.get("access", {})
    accounts_summary: list[str] = []
    if isinstance(access, dict):
        accounts = access.get("accounts", [])
        if isinstance(accounts, list):
            for account in accounts:
                if not isinstance(account, dict):
                    continue
                label = str(account.get("label") or account.get("username") or "Account").strip()
                role = str(account.get("role") or "role not set").strip()
                accounts_summary.append(f"{label} ({role})")

    eta = configuration.get("eta", {})
    if not isinstance(eta, dict):
        eta = {}
    safety = configuration.get("safety", {})
    if not isinstance(safety, dict):
        safety = {}

    return {
        "assessment_type": str(configuration.get("assessment_type") or "Not recorded"),
        "test_profile": str(configuration.get("test_profile") or (run.profile.name if run.profile is not None else "Not recorded")),
        "targets": normalized_targets,
        "enabled_modules": enabled_modules,
        "accounts_summary": accounts_summary,
        "safety": safety,
        "eta": eta,
    }


def report_methodology_references(run: Run) -> list[str]:
    references = [
        "PTES",
        f"OWASP WSTG {WSTG_STABLE_VERSION}",
        "NIST SP 800-115",
    ]
    if any(finding.asvs_reference for finding in run.findings):
        references.append(f"OWASP ASVS {ASVS_STABLE_VERSION}")
    return references


def report_context(run: Run) -> dict[str, object]:
    findings = sort_findings(list(run.findings))
    tasks = sort_tasks(list(run.tasks))
    approvals = sort_approvals(list(run.approvals))
    findings_by_severity, findings_by_status = findings_summary(findings)
    inventory_snapshot = effective_inventory_snapshot_for_run(run)
    inventory_summary = dict(inventory_snapshot.summary_json or {}) if inventory_snapshot is not None else {}
    return {
        "profile_name": run.profile.name if run.profile is not None else "unknown-profile",
        "engagement_name": run.engagement.name if run.engagement is not None else "unknown-engagement",
        "client_name": run.engagement.client if run.engagement is not None and run.engagement.client else "unknown-client",
        "findings": findings,
        "tasks": tasks,
        "approvals": approvals,
        "findings_by_severity": findings_by_severity,
        "findings_by_status": findings_by_status,
        "methodology": methodology_context_for_run(run),
        "adaptive_pack": adaptive_pack_context(run),
        "adaptive_change": adaptive_change_summary_for_run(run, findings),
        "coverage": methodology_coverage_summary(findings, tasks),
        "latest_scope": latest_scope_for_engagement(run.engagement),
        "remediation_counts": remediation_priority_counts(findings),
        "configuration": run_configuration_context(run),
        "inventory_snapshot": inventory_snapshot,
        "inventory_summary": inventory_summary,
    }


def _inventory_summary_lines(context: dict[str, object]) -> list[str]:
    inventory_summary = context.get("inventory_summary", {})
    if not isinstance(inventory_summary, dict) or not inventory_summary:
        return ["- No discovery-confirmed inventory snapshot is linked to this run.", ""]

    return [
        f"- Hosts Observed: {inventory_summary.get('host_count', 0)}",
        f"- Services Observed: {inventory_summary.get('service_count', 0)}",
        f"- Endpoints Observed: {inventory_summary.get('endpoint_count', 0)}",
        f"- Technologies Observed: {inventory_summary.get('technology_count', 0)}",
        f"- Inventory Confidence: {inventory_summary.get('confidence_score', 0.0)}",
        "",
    ]


def _retest_metadata_for_run(run: Run) -> dict[str, object] | None:
    configuration = run.configuration_json if isinstance(run.configuration_json, dict) else {}
    retest = configuration.get("retest")
    return dict(retest) if isinstance(retest, dict) and retest.get("mode") == "single_finding" else None


def _retest_verification_timestamp(run: Run) -> str:
    if run.status in {"completed", "completed_with_errors", "failed", "cancelled"}:
        return run.updated_at.isoformat()
    return "Pending retest execution completion"


def _render_retest_evidence_markdown(tasks: list[Task]) -> list[str]:
    if not tasks:
        return ["- No retest tasks recorded yet.", ""]

    lines: list[str] = []
    for task in tasks:
        lines.extend(
            [
                f"### Retest Task {task.id}",
                "",
                f"- Tool: {task.tool}",
                f"- Target: {task_targets_display(task)}",
                f"- Status: {task.status}",
            ]
        )
        if task.executions:
            for execution in task.executions:
                lines.append(
                    f"- Execution {execution.id}: exit_code={execution.exit_code}, tool_version={execution.tool_version}"
                )
                artifacts = sort_artifacts(list(execution.artifacts))
                if artifacts:
                    for artifact in artifacts:
                        artifact_name = str(artifact.metadata_json.get("name", artifact.id))
                        lines.append(
                            f"  artifact: {artifact_name} ({artifact.uri}) download={artifact_download_path(artifact.id)}"
                        )
                else:
                    lines.append("  artifact: no artifact recorded for this execution")
        else:
            lines.append("- No executions recorded for this retest task yet.")
        lines.append("")
    return lines


def _render_proof_of_resolution_markdown(run: Run, context: dict[str, object]) -> list[str]:
    retest = _retest_metadata_for_run(run)
    if retest is None:
        return [
            "## Proof of Resolution",
            "",
            "- This run is not linked to a single-finding retest request yet.",
            "",
        ]

    tasks = context["tasks"]
    assert isinstance(tasks, list)
    lines = [
        "## Proof of Resolution",
        "",
        f"- Source Finding: {retest.get('source_finding_title') or 'Not recorded'}",
        f"- Source Finding ID: {retest.get('source_finding_id') or 'Not recorded'}",
        f"- Source Run ID: {retest.get('source_run_id') or 'Not recorded'}",
        f"- Source Severity: {retest.get('source_finding_severity') or 'Not recorded'}",
        f"- Source Status Before Retest: {retest.get('source_finding_status') or 'Not recorded'}",
        f"- Source Target: {retest.get('source_finding_target') or 'Not recorded'}",
        f"- Source Evidence Ref: {retest.get('source_evidence_ref') or 'Not recorded'}",
        f"- Source Summary: {retest.get('source_finding_summary') or retest.get('source_summary') or 'Not recorded'}",
        f"- Remediation State: {retest.get('remediation_state') or 'Not recorded'}",
        f"- Remediation Notes: {retest.get('remediation_notes') or 'Not recorded'}",
        f"- Retest Operator Notes: {retest.get('operator_notes') or 'Not recorded'}",
        f"- Retest Run Status: {run.status}",
        f"- Verification Timestamp: {_retest_verification_timestamp(run)}",
        "",
        "## Retest Evidence",
        "",
    ]
    lines.extend(_render_retest_evidence_markdown(tasks))
    return lines


def _render_retest_evidence_html(tasks: list[Task]) -> str:
    if not tasks:
        return "<p>No retest tasks recorded yet.</p>"

    task_cards: list[str] = []
    for task in tasks:
        execution_items: list[str] = []
        for execution in task.executions:
            artifact_items = "".join(
                "<li>"
                f"{escape(str(artifact.metadata_json.get('name', artifact.id)))} - "
                f"<code>{escape(artifact.uri)}</code> - "
                f"<a href=\"{escape(artifact_download_path(artifact.id))}\">download</a>"
                "</li>"
                for artifact in sort_artifacts(list(execution.artifacts))
            )
            execution_items.append(
                "<li>"
                f"Execution {escape(str(execution.id))}: "
                f"exit_code={escape(str(execution.exit_code))}, "
                f"tool_version={escape(execution.tool_version)}"
                + (
                    f"<ul>{artifact_items}</ul>"
                    if artifact_items
                    else "<ul><li>No artifact recorded for this execution.</li></ul>"
                )
                + "</li>"
            )
        if not execution_items:
            execution_items.append("<li>No executions recorded for this retest task yet.</li>")

        task_cards.append(
            "<article class='task'>"
            f"<h3>Retest Task {escape(str(task.id))}</h3>"
            f"<p><strong>Tool:</strong> {escape(task.tool)} | "
            f"<strong>Target:</strong> {escape(task_targets_display(task))} | "
            f"<strong>Status:</strong> {escape(task.status)}</p>"
            f"<ul>{''.join(execution_items)}</ul>"
            "</article>"
        )
    return "".join(task_cards)


def _render_proof_of_resolution_html(run: Run, context: dict[str, object]) -> str:
    retest = _retest_metadata_for_run(run)
    if retest is None:
        return """
        <section class="panel">
          <h2>Proof of Resolution</h2>
          <p>This run is not linked to a single-finding retest request yet.</p>
        </section>
        """

    tasks = context["tasks"]
    assert isinstance(tasks, list)
    proof_rows = [
        ("Source Finding", retest.get("source_finding_title") or "Not recorded"),
        ("Source Finding ID", retest.get("source_finding_id") or "Not recorded"),
        ("Source Run ID", retest.get("source_run_id") or "Not recorded"),
        ("Source Severity", retest.get("source_finding_severity") or "Not recorded"),
        ("Source Status Before Retest", retest.get("source_finding_status") or "Not recorded"),
        ("Source Target", retest.get("source_finding_target") or "Not recorded"),
        ("Source Evidence Ref", retest.get("source_evidence_ref") or "Not recorded"),
        (
            "Source Summary",
            retest.get("source_finding_summary") or retest.get("source_summary") or "Not recorded",
        ),
        ("Remediation State", retest.get("remediation_state") or "Not recorded"),
        ("Remediation Notes", retest.get("remediation_notes") or "Not recorded"),
        ("Retest Operator Notes", retest.get("operator_notes") or "Not recorded"),
        ("Retest Run Status", run.status),
        ("Verification Timestamp", _retest_verification_timestamp(run)),
    ]
    rows_html = "".join(
        f"<tr><th>{escape(label)}</th><td>{escape(str(value))}</td></tr>" for label, value in proof_rows
    )
    return f"""
    <section class="panel">
      <h2>Proof of Resolution</h2>
      <table>{rows_html}</table>
      <h3>Retest Evidence</h3>
      {_render_retest_evidence_html(tasks)}
    </section>
    """


def _render_configuration_markdown(context: dict[str, object]) -> list[str]:
    configuration = context["configuration"]
    assert isinstance(configuration, dict)
    eta = configuration.get("eta", {})
    safety = configuration.get("safety", {})
    targets = configuration.get("targets", {})
    return [
        "## Run Configuration",
        "",
        f"- Assessment Type: {configuration.get('assessment_type') or 'Not Recorded'}",
        f"- Test Profile: {configuration.get('test_profile') or 'Not Recorded'}",
        f"- Enabled Modules: {', '.join(configuration.get('enabled_modules', [])) or 'Not Recorded'}",
        f"- Active Accounts / Roles: {', '.join(configuration.get('accounts_summary', [])) or 'None Recorded'}",
        f"- Target Inputs: {targets or {}}",
        f"- Safety Settings: {safety or {}}",
        f"- ETA Model: {eta or {}}",
        "",
    ]


def _render_configuration_html(context: dict[str, object]) -> str:
    configuration = context["configuration"]
    assert isinstance(configuration, dict)
    return (
        "<ul>"
        f"<li><strong>Assessment Type:</strong> {escape(str(configuration.get('assessment_type') or 'Not Recorded'))}</li>"
        f"<li><strong>Test Profile:</strong> {escape(str(configuration.get('test_profile') or 'Not Recorded'))}</li>"
        f"<li><strong>Enabled Modules:</strong> {escape(', '.join(configuration.get('enabled_modules', [])) or 'Not Recorded')}</li>"
        f"<li><strong>Active Accounts / Roles:</strong> {escape(', '.join(configuration.get('accounts_summary', [])) or 'None Recorded')}</li>"
        f"<li><strong>Target Inputs:</strong> {escape(str(configuration.get('targets') or {}))}</li>"
        f"<li><strong>Safety Settings:</strong> {escape(str(configuration.get('safety') or {}))}</li>"
        f"<li><strong>ETA Model:</strong> {escape(str(configuration.get('eta') or {}))}</li>"
        "</ul>"
    )


def _render_adaptive_change_markdown(context: dict[str, object]) -> list[str]:
    adaptive_change = context["adaptive_change"]
    assert isinstance(adaptive_change, dict)
    if not adaptive_change.get("active"):
        return [
            "## Adaptive Change Summary",
            "",
            f"- {adaptive_change.get('summary_line')}",
            "",
        ]

    latest_task = adaptive_change.get("latest_task") if isinstance(adaptive_change.get("latest_task"), dict) else None
    lines = [
        "## Adaptive Change Summary",
        "",
        f"- Summary: {adaptive_change.get('summary_line')}",
        f"- Governance: {adaptive_change.get('governance_line')}",
        f"- Findings Linked to This Pack: {adaptive_change.get('finding_line')}",
        f"- Threat Intel References: {', '.join(adaptive_change.get('source_threat_intel_refs', [])) or 'None'}",
        f"- Methodology Tags: {', '.join(adaptive_change.get('methodology_tags', [])) or 'None'}",
    ]
    if latest_task is not None:
        lines.extend(
            [
                (
                    f"- Latest Codex Task: {latest_task.get('id')} ({latest_task.get('task_type')}) "
                    f"status={latest_task.get('status')} validation={latest_task.get('validation_status')}"
                ),
                f"- Task Reason: {latest_task.get('generation_reason') or 'Not recorded'}",
            ]
        )
        if latest_task.get("prepared_result_status"):
            lines.append(
                "- Prepared Review Bundle: "
                f"{latest_task.get('prepared_result_status')} with "
                f"{latest_task.get('prepared_command_count', 0)} commands and "
                f"{latest_task.get('prepared_output_count', 0)} output files"
            )
    lines.append("")
    return lines


def _render_adaptive_change_html(context: dict[str, object]) -> str:
    adaptive_change = context["adaptive_change"]
    assert isinstance(adaptive_change, dict)
    latest_task = adaptive_change.get("latest_task") if isinstance(adaptive_change.get("latest_task"), dict) else None
    items = [
        f"<li><strong>Summary:</strong> {escape(str(adaptive_change.get('summary_line') or 'Not recorded'))}</li>",
        f"<li><strong>Governance:</strong> {escape(str(adaptive_change.get('governance_line') or 'Not recorded'))}</li>",
        f"<li><strong>Findings Linked to This Pack:</strong> {escape(str(adaptive_change.get('finding_line') or 'Not recorded'))}</li>",
        f"<li><strong>Threat Intel References:</strong> {escape(', '.join(adaptive_change.get('source_threat_intel_refs', [])) or 'None')}</li>",
        f"<li><strong>Methodology Tags:</strong> {escape(', '.join(adaptive_change.get('methodology_tags', [])) or 'None')}</li>",
    ]
    if latest_task is not None:
        items.append(
            "<li><strong>Latest Codex Task:</strong> "
            f"{escape(str(latest_task.get('id')))} "
            f"({escape(str(latest_task.get('task_type') or 'unknown'))}) "
            f"status={escape(str(latest_task.get('status') or 'unknown'))} "
            f"validation={escape(str(latest_task.get('validation_status') or 'unknown'))}</li>"
        )
        items.append(
            f"<li><strong>Task Reason:</strong> {escape(str(latest_task.get('generation_reason') or 'Not recorded'))}</li>"
        )
        if latest_task.get("prepared_result_status"):
            items.append(
                "<li><strong>Prepared Review Bundle:</strong> "
                f"{escape(str(latest_task.get('prepared_result_status')))} with "
                f"{escape(str(latest_task.get('prepared_command_count', 0)))} commands and "
                f"{escape(str(latest_task.get('prepared_output_count', 0)))} output files</li>"
            )
    return f"<ul>{''.join(items)}</ul>"


def _render_executive_markdown(run: Run, context: dict[str, object]) -> str:
    findings = context["findings"]
    methodology = context["methodology"]
    adaptive_pack = context["adaptive_pack"]
    adaptive_change = context["adaptive_change"]
    remediation_counts = context["remediation_counts"]
    inventory_summary = context["inventory_summary"]
    return "\n".join(
        [
            f"# AegisPT Executive Report: {run.id}",
            "",
            "## Mission Snapshot",
            "",
            f"- Engagement: {context['engagement_name']}",
            f"- Client: {context['client_name']}",
            f"- Run Profile: {context['profile_name']}",
            f"- Run Status: {run.status}",
            f"- Adaptive Coverage: {adaptive_pack['label']}",
            f"- Adaptive Change Review: {adaptive_change['summary_line']}",
            f"- Findings by Severity: {context['findings_by_severity'] or {}}",
            f"- Findings by Status: {context['findings_by_status'] or {}}",
            f"- Discovery Summary: {inventory_summary or {}}",
            "",
            *_render_configuration_markdown(context),
            "## Methodology",
            "",
            f"- PTES Lifecycle Mapping: {methodology['ptes_phase_label']}",
            f"- NIST Mapping: {methodology['nist_phase_label']}",
            f"- OWASP WSTG Baseline: {WSTG_STABLE_VERSION}",
            "",
            *_render_adaptive_change_markdown(context),
            "## Risk Highlights",
            "",
            f"- Remediation Priorities: {remediation_counts or {}}",
            *(
                [f"- {finding.severity.upper()}: {finding.title}" for finding in findings[:5]]
                if findings
                else ["- No confirmed findings recorded.", *(_inventory_summary_lines(context) if inventory_summary else [])]
            ),
            "",
            "## Recommended Next Steps",
            "",
            "- Validate remediation order with the customer owner and retain the evidence-backed run as the baseline.",
            "- Use the Technical Report for analyst detail and the Evidence Appendix for replay artifacts.",
            "- Schedule retest coverage for any item that remains open after remediation.",
            "",
        ]
    ).rstrip() + "\n"


def _render_evidence_markdown(run: Run, context: dict[str, object]) -> str:
    findings = context["findings"]
    tasks = context["tasks"]
    lines = [
        f"# AegisPT Evidence Appendix: {run.id}",
        "",
        *_render_configuration_markdown(context),
        "## Discovery Results",
        "",
        *_inventory_summary_lines(context),
        "## Methodology References",
        "",
        *[f"- {reference}" for reference in report_methodology_references(run)],
        "",
        "## Findings Evidence Map",
        "",
    ]
    if findings:
        for finding in findings:
            lines.extend(
                [
                    f"### {finding.title}",
                    "",
                    f"- Evidence Ref: {finding.evidence_ref}",
                    f"- Severity: {finding.severity}",
                    f"- Status: {finding.status}",
                    *finding_methodology_lines(finding),
                    "",
                ]
            )
    else:
        lines.extend(["- No findings recorded.", ""])

    lines.extend(["## Task Evidence", ""])
    if tasks:
        for task in tasks:
            lines.extend(
                [
                    f"### Task {task.id}",
                    "",
                    f"- Tool: {task.tool}",
                    f"- Target: {task_targets_display(task)}",
                    f"- Status: {task.status}",
                ]
            )
            for execution in task.executions:
                lines.append(
                    f"- Execution {execution.id}: exit_code={execution.exit_code}, tool_version={execution.tool_version}"
                )
                for artifact in sort_artifacts(list(execution.artifacts)):
                    lines.append(
                        f"  artifact: {artifact.metadata_json.get('name', artifact.id)} download={artifact_download_path(artifact.id)}"
                    )
            lines.append("")
    else:
        lines.extend(["- No task evidence recorded.", ""])

    return "\n".join(lines).rstrip() + "\n"


def _render_retest_markdown(run: Run, context: dict[str, object]) -> str:
    findings = context["findings"]
    lines = [
        f"# AegisPT Retest / Verification Report: {run.id}",
        "",
        "## Verification Summary",
        "",
        f"- Run Status: {run.status}",
        f"- Verification Status Counts: {context['findings_by_status'] or {}}",
        f"- Resolved Findings: {sum(1 for finding in findings if finding.status == 'resolved')}",
        f"- Still Open: {sum(1 for finding in findings if finding.status in {'open', 'triaged', 'in_progress', 'reopened'})}",
        "",
        *_render_proof_of_resolution_markdown(run, context),
        *_render_configuration_markdown(context),
        "## Discovery Results",
        "",
        *_inventory_summary_lines(context),
        "## Findings Verification State",
        "",
    ]
    if findings:
        for finding in findings:
            lines.extend(
                [
                    f"### {finding.title}",
                    "",
                    f"- Severity: {finding.severity}",
                    f"- Status: {finding.status}",
                    f"- Replay Status: {replay_status_for_finding(finding)}",
                    f"- Remediation Summary: {default_remediation_summary(finding.control_family)}",
                    "",
                ]
            )
    else:
        lines.extend(["- No findings recorded.", ""])
    lines.extend(
        [
            "## Retest Guidance",
            "",
            "- Re-run validated checks after remediation and attach new evidence under the same engagement dossier.",
            "- Update finding status only after replay confirms the fix or the customer accepts residual risk.",
            "",
        ]
    )
    return "\n".join(lines).rstrip() + "\n"


def build_report_catalog(run: Run) -> list[RunReportCatalogItemRead]:
    context = report_context(run)
    linked_evidence = sum(1 for finding in context["findings"] if finding.evidence_ref)
    catalog: list[RunReportCatalogItemRead] = []
    for variant, title in REPORT_VARIANT_LABELS.items():
        markdown_content = render_markdown_report(run, variant=variant)
        catalog.append(
            RunReportCatalogItemRead(
                variant=variant,
                title=title,
                description=REPORT_VARIANT_DESCRIPTIONS[variant],
                source_run_id=run.id,
                generated_at=run.created_at,
                available_formats=["markdown", "html", "pdf"],
                methodology_references=report_methodology_references(run),
                source_scope_profile={
                    "run_profile": context["profile_name"],
                    "assessment_type": context["configuration"].get("assessment_type"),
                    "enabled_modules": context["configuration"].get("enabled_modules", []),
                    "targets": context["configuration"].get("targets", {}),
                },
                included_findings={
                    "count": len(context["findings"]),
                    "by_severity": context["findings_by_severity"],
                    "by_status": context["findings_by_status"],
                },
                included_inventory={
                    "host_count": context["inventory_summary"].get("host_count", 0),
                    "service_count": context["inventory_summary"].get("service_count", 0),
                    "endpoint_count": context["inventory_summary"].get("endpoint_count", 0),
                    "technology_count": context["inventory_summary"].get("technology_count", 0),
                    "confidence_score": context["inventory_summary"].get("confidence_score", 0.0),
                },
                evidence_status={
                    "linked_findings": linked_evidence,
                    "total_findings": len(context["findings"]),
                    "completeness_ratio": (linked_evidence / len(context["findings"])) if context["findings"] else 0.0,
                },
                adaptive_change_summary=context["adaptive_change"],
                version_label=f"{variant}-{run.created_at:%Y%m%dT%H%M%S}",
                content_sha256=hashlib.sha256(markdown_content.encode("utf-8")).hexdigest(),
                export_paths={
                    "markdown": f"/api/v1/runs/{run.id}/report?format=markdown&variant={variant}",
                    "html": f"/api/v1/runs/{run.id}/report?format=html&variant={variant}",
                    "pdf": f"/api/v1/runs/{run.id}/report?format=pdf&variant={variant}",
                },
                download_names={
                    "markdown": f"aegispt-run-{run.id}-{variant}.md",
                    "html": f"aegispt-run-{run.id}-{variant}.html",
                    "pdf": f"aegispt-run-{run.id}-{variant}.pdf",
                },
            )
        )
    return catalog


def render_markdown_report(run: Run, *, variant: str = "technical") -> str:
    context = report_context(run)
    if variant == "executive":
        return _render_executive_markdown(run, context)
    if variant == "evidence":
        return _render_evidence_markdown(run, context)
    if variant == "retest":
        return _render_retest_markdown(run, context)

    profile_name = context["profile_name"]
    engagement_name = context["engagement_name"]
    client_name = context["client_name"]
    findings = context["findings"]
    tasks = context["tasks"]
    approvals = context["approvals"]
    findings_by_severity = context["findings_by_severity"]
    findings_by_status = context["findings_by_status"]
    methodology = context["methodology"]
    adaptive_pack = context["adaptive_pack"]
    adaptive_change = context["adaptive_change"]
    coverage = context["coverage"]
    latest_scope = context["latest_scope"]
    remediation_counts = context["remediation_counts"]
    inventory_summary = context["inventory_summary"]
    inventory_summary = context["inventory_summary"]

    lines = [
        f"# AegisPT Run Report: {run.id}",
        "",
        "## Executive Summary",
        "",
        f"- Engagement: {engagement_name}",
        f"- Client: {client_name}",
        f"- Run Profile: {profile_name}",
        f"- Run Status: {run.status}",
        f"- Requested By: {run.requested_by}",
        f"- Created At: {run.created_at.isoformat()}",
        f"- Operator Workflow Stage: {methodology['operator_stage']}",
        f"- PTES Mapping for This Run: {methodology['ptes_phase_label']}",
        f"- NIST Mapping for This Run: {methodology['nist_phase_label']}",
        f"- Adaptive Coverage: {adaptive_pack['label']}",
        f"- Adaptive Change Review: {adaptive_change['summary_line']}",
        f"- Finding Count: {len(findings)}",
        "",
        "## Discovery Summary",
        "",
        *_inventory_summary_lines(context),
        "## Scope",
        "",
    ]

    if latest_scope is not None:
        lines.extend(
            [
                "### Allowlist",
                "",
                "```json",
                format_json_block(latest_scope.allowlist_json),
                "```",
                "",
                "### Denylist",
                "",
                "```json",
                format_json_block(latest_scope.denylist_json),
                "```",
                "",
            ]
        )
    else:
        lines.extend(["- No scope snapshot loaded for this run.", ""])

    lines.extend(_render_configuration_markdown(context))

    lines.extend(
        [
            "## Rules of Engagement Summary",
            "",
            f"- ROE Reference: {run.engagement.roe_ref if run.engagement is not None and run.engagement.roe_ref else 'Not Recorded'}",
            f"- Approval Records: {len(approvals)}",
            "- Guardrails: evidence-first collection, replayable artifacts, and approval-gated active validation where applicable.",
            "",
            "## Methodology",
            "",
            "- Assessment lifecycle: PTES",
            f"- Web/API technical coverage model: OWASP WSTG {WSTG_STABLE_VERSION}",
            "- Structured testing and reporting discipline: NIST SP 800-115",
            f"- Optional control-verification layer: OWASP ASVS {ASVS_STABLE_VERSION} when a precise reference is assigned",
            "",
            "### PTES Lifecycle Alignment",
            "",
            "- Pre-Engagement -> engagement definition, scope, and rules of engagement setup",
            "- Intelligence Gathering -> reconnaissance and target discovery activities",
            "- Analysis / Validation -> passive validation and evidence-backed issue confirmation",
            "- Controlled Exploitation / Verification -> approval-gated active validation and internal adversary simulation steps",
            "- Reporting -> executive and technical reporting with linked evidence",
            "- Retest -> rerun and verification-state updates after remediation",
            "",
            "### NIST SP 800-115 Alignment",
            "",
            "- Planning -> scope, logistics, approvals, and rules of engagement",
            "- Discovery -> reconnaissance, identification, and technical analysis",
            "- Attack -> controlled validation of exploitable weaknesses",
            "- Reporting -> structured findings, evidence, remediation, and verification output",
            "- Post-Testing -> remediation follow-up and retest handling",
            "",
            "## Coverage Summary",
            "",
            f"- Tools Executed: {', '.join(coverage['tools']) or 'None'}",
            f"- WSTG Areas Covered: {', '.join(coverage['wstg_areas']) or 'Not Assigned'}",
            f"- Control Families Seen: {', '.join(coverage['control_families']) or 'Not Assigned'}",
            f"- Methodology Tags Seen: {', '.join(coverage['methodology_tags']) or 'Not Assigned'}",
            f"- By Severity: {findings_by_severity or {}}",
            f"- By Status: {findings_by_status or {}}",
            "",
            "## Adaptive Coverage",
            "",
            f"- Runtime Pack: {adaptive_pack['label']}",
            f"- Deployment Target: {adaptive_pack['deployment_target'] or 'Not Bound'}",
            f"- Deployment Status: {adaptive_pack['deployment_status'] or 'Not Bound'}",
            f"- Inventory Snapshot Used: {adaptive_pack['manifest'].get('inventory_snapshot_id') or 'Not Assigned'}",
            f"- Relevance Decision: {adaptive_pack['manifest'].get('relevance_decision_id') or 'Not Assigned'}",
            f"- Threat Intel References: {', '.join(adaptive_pack['manifest'].get('threat_intel_refs', [])) or 'None'}",
            f"- Generation Reason: {adaptive_pack['manifest'].get('generation_reason') or 'Standard coverage only'}",
            "",
            *_render_adaptive_change_markdown(context),
            "## Remediation Priorities",
            "",
            f"- Priority Counts: {remediation_counts or {}}",
        ]
    )

    if findings:
        for finding in findings[:5]:
            lines.append(f"- {remediation_priority_for_finding(finding)}: {finding.title}")
    else:
        lines.append("- No confirmed findings recorded.")

    lines.extend(["", "## Confirmed Findings", ""])
    if findings:
        for index, finding in enumerate(findings, start=1):
            lines.extend(
                [
                    f"### {index}. {finding.title}",
                    "",
                    f"- Severity: {finding.severity}",
                    f"- Status: {finding.status}",
                    f"- Verification Status: {finding.status}",
                    f"- Remediation Priority: {remediation_priority_for_finding(finding)}",
                    f"- Target: {finding.target_id}",
                    f"- Evidence Ref: {finding.evidence_ref}",
                    f"- Replay Status: {replay_status_for_finding(finding)}",
                ]
            )
            lines.extend(finding_methodology_lines(finding))
            if finding.summary:
                lines.append(f"- Summary: {finding.summary}")
            lines.append(f"- Remediation Summary: {default_remediation_summary(finding.control_family)}")
            lines.append(f"- Remediation Detail: {default_remediation_detail(finding.control_family)}")
            lines.append("")
    else:
        lines.extend(["No findings recorded.", ""])

    lines.extend(["## Evidence and Reproduction", ""])
    if tasks:
        for task in tasks:
            target_label = task_targets_display(task)
            lines.extend(
                [
                    f"### Task {task.id}",
                    "",
                    f"- Tool: {task.tool}",
                    f"- Target: {target_label}",
                    f"- Status: {task.status}",
                ]
            )
            if task.executions:
                for execution in task.executions:
                    lines.extend(
                        [
                            f"- Execution {execution.id}: exit_code={execution.exit_code}, tool_version={execution.tool_version}",
                        ]
                    )
                    for artifact in sort_artifacts(list(execution.artifacts)):
                        artifact_name = str(artifact.metadata_json.get("name", artifact.id))
                        lines.append(
                            f"  artifact: {artifact_name} ({artifact.uri}) download={artifact_download_path(artifact.id)}"
                        )
            else:
                lines.append("- No executions recorded")
            lines.append("")
    else:
        lines.extend(["No tasks recorded.", ""])

    lines.extend(
        [
            "## Retest and Verification",
            "",
            f"- Verification Status Counts: {findings_by_status or {}}",
            f"- Resolved Findings: {sum(1 for finding in findings if finding.status == 'resolved')}",
            f"- Findings Requiring Further Validation: {sum(1 for finding in findings if finding.status in {'open', 'triaged', 'in_progress', 'reopened'})}",
            "",
        ]
    )

    return "\n".join(lines).rstrip() + "\n"


def render_html_report(run: Run, *, variant: str = "technical") -> str:
    context = report_context(run)
    profile_name = context["profile_name"]
    engagement_name = context["engagement_name"]
    client_name = context["client_name"]
    findings = context["findings"]
    tasks = context["tasks"]
    approvals = context["approvals"]
    findings_by_severity = context["findings_by_severity"]
    findings_by_status = context["findings_by_status"]
    methodology = context["methodology"]
    adaptive_pack = context["adaptive_pack"]
    adaptive_change = context["adaptive_change"]
    coverage = context["coverage"]
    latest_scope = context["latest_scope"]
    remediation_counts = context["remediation_counts"]
    inventory_summary = context["inventory_summary"]

    summary_rows = [
        ("Engagement", engagement_name),
        ("Client", client_name),
        ("Run Profile", profile_name),
        ("Run Status", run.status),
        ("Requested By", run.requested_by),
        ("Created At", run.created_at.isoformat()),
        ("Operator Workflow Stage", methodology["operator_stage"]),
        ("PTES Mapping", methodology["ptes_phase_label"]),
        ("NIST Mapping", methodology["nist_phase_label"]),
        ("Adaptive Coverage", str(adaptive_pack["label"])),
        ("Adaptive Change Review", str(adaptive_change["summary_line"])),
        ("Finding Count", str(len(findings))),
        ("Hosts Observed", str(inventory_summary.get("host_count", 0))),
        ("Services Observed", str(inventory_summary.get("service_count", 0))),
        ("Endpoints Observed", str(inventory_summary.get("endpoint_count", 0))),
    ]
    summary_html = "".join(
        f"<tr><th>{escape(label)}</th><td>{escape(value)}</td></tr>" for label, value in summary_rows
    )

    approvals_html = "".join(
        "<li>"
        f"{escape(approval.step_id)}: {escape(approval.decision)} by {escape(approval.approver_id)} "
        f"at {escape(approval.created_at.isoformat())}"
        "</li>"
        for approval in approvals
    ) or "<li>No approvals recorded</li>"

    scope_html = (
        "<div class='scope-grid'>"
        f"<section><h3>Allowlist</h3><pre>{escape(format_json_block(latest_scope.allowlist_json))}</pre></section>"
        f"<section><h3>Denylist</h3><pre>{escape(format_json_block(latest_scope.denylist_json))}</pre></section>"
        "</div>"
        if latest_scope is not None
        else "<p>No scope snapshot loaded for this run.</p>"
    )

    methodology_html = (
        "<ul>"
        "<li>PTES governs the assessment lifecycle and operator workflow alignment.</li>"
        f"<li>OWASP WSTG {escape(WSTG_STABLE_VERSION)} governs web and API technical coverage references.</li>"
        "<li>NIST SP 800-115 governs technical testing discipline, evidence handling, and reporting structure.</li>"
        f"<li>OWASP ASVS {escape(ASVS_STABLE_VERSION)} remains an optional control-reference layer when analysts assign precise references.</li>"
        "</ul>"
    )

    coverage_html = (
        "<ul>"
        f"<li><strong>Tools Executed:</strong> {escape(', '.join(coverage['tools']) or 'None')}</li>"
        f"<li><strong>WSTG Areas Covered:</strong> {escape(', '.join(coverage['wstg_areas']) or 'Not Assigned')}</li>"
        f"<li><strong>Control Families Seen:</strong> {escape(', '.join(coverage['control_families']) or 'Not Assigned')}</li>"
        f"<li><strong>Priority Counts:</strong> {escape(str(remediation_counts or {}))}</li>"
        "</ul>"
    )
    inventory_html = (
        "<ul>"
        f"<li><strong>Hosts Observed:</strong> {escape(str(inventory_summary.get('host_count', 0)))}</li>"
        f"<li><strong>Services Observed:</strong> {escape(str(inventory_summary.get('service_count', 0)))}</li>"
        f"<li><strong>Endpoints Observed:</strong> {escape(str(inventory_summary.get('endpoint_count', 0)))}</li>"
        f"<li><strong>Technologies Observed:</strong> {escape(str(inventory_summary.get('technology_count', 0)))}</li>"
        f"<li><strong>Inventory Confidence:</strong> {escape(str(inventory_summary.get('confidence_score', 0.0)))}</li>"
        "</ul>"
        if inventory_summary
        else "<p>No discovery-confirmed inventory snapshot is linked to this run.</p>"
    )

    adaptive_pack_html = (
        "<ul>"
        f"<li><strong>Runtime Pack:</strong> {escape(str(adaptive_pack['label']))}</li>"
        f"<li><strong>Deployment Target:</strong> {escape(str(adaptive_pack['deployment_target'] or 'Not Bound'))}</li>"
        f"<li><strong>Deployment Status:</strong> {escape(str(adaptive_pack['deployment_status'] or 'Not Bound'))}</li>"
        f"<li><strong>Inventory Snapshot Used:</strong> {escape(str(adaptive_pack['manifest'].get('inventory_snapshot_id') or 'Not Assigned'))}</li>"
        f"<li><strong>Relevance Decision:</strong> {escape(str(adaptive_pack['manifest'].get('relevance_decision_id') or 'Not Assigned'))}</li>"
        f"<li><strong>Threat Intel References:</strong> {escape(', '.join(adaptive_pack['manifest'].get('threat_intel_refs', [])) or 'None')}</li>"
        f"<li><strong>Generation Reason:</strong> {escape(str(adaptive_pack['manifest'].get('generation_reason') or 'Standard coverage only'))}</li>"
        "</ul>"
    )
    adaptive_change_html = _render_adaptive_change_html(context)

    findings_html = "".join(
        "<article class='finding'>"
        f"<div class='finding-header'><h3>{escape(finding.title)}</h3><span class='priority'>{escape(remediation_priority_for_finding(finding))}</span></div>"
        f"<p><strong>Severity:</strong> {escape(finding.severity)} | "
        f"<strong>Status:</strong> {escape(finding.status)} | "
        f"<strong>Target:</strong> {escape(finding.target_id)}</p>"
        f"<p><strong>Evidence Ref:</strong> <code>{escape(finding.evidence_ref)}</code></p>"
        f"<p><strong>Methodology:</strong> PTES {escape(ptes_phase_label(finding.ptes_phase) or 'Not Assigned')} | "
        f"NIST {escape(nist_phase_label(finding.nist_phase) or 'Not Assigned')} | "
        f"WSTG {escape(format_wstg_reference(finding.wstg_id, finding.wstg_version) or 'Not Assigned')}</p>"
        f"<p><strong>Control Family:</strong> {escape(control_family_label(finding.control_family) or 'Not Assigned')}</p>"
        f"<p><strong>Finding Origin:</strong> {escape(finding.finding_origin)} | "
        f"<strong>Source Pack Version:</strong> {escape(finding.source_pack_version or 'Standard Coverage')}</p>"
        + (f"<p>{escape(finding.summary)}</p>" if finding.summary else "")
        + f"<p><strong>Remediation Summary:</strong> {escape(default_remediation_summary(finding.control_family))}</p>"
        + "</article>"
        for finding in findings
    ) or "<p>No findings recorded.</p>"

    task_sections: list[str] = []
    for task in tasks:
        target_label = task_targets_display(task)
        execution_lines: list[str] = []
        for execution in task.executions:
            artifact_lines = "".join(
                "<li>"
                f"{escape(str(artifact.metadata_json.get('name', artifact.id)))} - "
                f"<code>{escape(artifact.uri)}</code> - "
                f"<a href=\"{escape(artifact_download_path(artifact.id))}\">download</a>"
                "</li>"
                for artifact in sort_artifacts(list(execution.artifacts))
            )
            execution_lines.append(
                "<li>"
                f"Execution {escape(str(execution.id))}: exit_code={execution.exit_code}, "
                f"tool_version={escape(execution.tool_version)}"
                + (f"<ul>{artifact_lines}</ul>" if artifact_lines else "")
                + "</li>"
            )
        task_sections.append(
            "<article class='task'>"
            f"<h3>Task {escape(str(task.id))}</h3>"
            f"<p><strong>Tool:</strong> {escape(task.tool)} | "
            f"<strong>Target:</strong> {escape(target_label)} | "
            f"<strong>Status:</strong> {escape(task.status)}</p>"
            + (f"<ul>{''.join(execution_lines)}</ul>" if execution_lines else "<p>No executions recorded.</p>")
            + "</article>"
        )

    tasks_html = "".join(task_sections) or "<p>No tasks recorded.</p>"

    configuration_html = _render_configuration_html(context)

    executive_panel = f"""
    <section class="panel">
      <h2>Risk Highlights</h2>
      <p><strong>Priority Counts:</strong> {escape(str(remediation_counts or {}))}</p>
      <ul class="meta-list">{"".join(f"<li>{escape(finding.severity.upper())}: {escape(finding.title)}</li>" for finding in findings[:5]) or "<li>No confirmed findings recorded.</li>"}</ul>
    </section>
    """

    report_context_html = "".join(
        f"<span class='context-chip'><strong>{escape(label)}:</strong> {escape(value)}</span>"
        for label, value in [
            ("Engagement", engagement_name),
            ("Client", client_name),
            ("Profile", profile_name),
            ("Status", run.status),
            ("Run", str(run.id)),
        ]
    )

    if variant == "executive":
        findings_section = executive_panel
        evidence_section = ""
        verification_section = """
        <section class="panel">
          <h2>Recommended Next Steps</h2>
          <ul class="meta-list">
            <li>Use the Technical Report for analyst detail and the Evidence Appendix for replay artifacts.</li>
            <li>Prioritize remediation in the order shown above and schedule retest coverage for remaining open items.</li>
          </ul>
        </section>
        """
        title = "AegisPT Executive Report"
    elif variant == "evidence":
        findings_section = f"""
        <section class="panel">
          <h2>Findings Evidence Map</h2>
          {findings_html}
        </section>
        """
        evidence_section = f"""
        <section class="panel">
          <h2>Task Evidence</h2>
          {tasks_html}
        </section>
        """
        verification_section = ""
        title = "AegisPT Evidence Appendix"
    elif variant == "retest":
        findings_section = f"""
        <section class="panel">
          <h2>Findings Verification State</h2>
          {findings_html}
        </section>
        """
        evidence_section = ""
        verification_section = _render_proof_of_resolution_html(run, context) + f"""
        <section class="panel">
          <h2>Retest and Verification</h2>
          <p><strong>Verification Status Counts:</strong> {escape(str(findings_by_status or {}))}</p>
          <p><strong>Resolved Findings:</strong> {sum(1 for finding in findings if finding.status == 'resolved')}</p>
          <p><strong>Findings Requiring Further Validation:</strong> {sum(1 for finding in findings if finding.status in {'open', 'triaged', 'in_progress', 'reopened'})}</p>
        </section>
        """
        title = "AegisPT Retest / Verification Report"
    else:
        findings_section = f"""
        <section class="panel">
          <h2>Confirmed Findings</h2>
          {findings_html}
        </section>
        """
        evidence_section = f"""
        <section class="panel">
          <h2>Evidence and Reproduction</h2>
          {tasks_html}
        </section>
        """
        verification_section = f"""
        <section class="panel">
          <h2>Retest and Verification</h2>
          <p><strong>Verification Status Counts:</strong> {escape(str(findings_by_status or {}))}</p>
          <p><strong>Resolved Findings:</strong> {sum(1 for finding in findings if finding.status == 'resolved')}</p>
          <p><strong>Findings Requiring Further Validation:</strong> {sum(1 for finding in findings if finding.status in {'open', 'triaged', 'in_progress', 'reopened'})}</p>
        </section>
        """
        title = "AegisPT Run Report"

    return f"""<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <title>{escape(title)} {escape(str(run.id))}</title>
    <style>
      :root {{
        --ink: #1f2937;
        --muted: #4b5563;
        --line: #d1d5db;
        --panel: #ffffff;
        --panel-alt: #f8fafc;
        --accent: #9a3412;
      }}
      body {{
        font-family: "Segoe UI", "Helvetica Neue", sans-serif;
        font-size: 14px;
        line-height: 1.6;
        margin: 0 auto;
        max-width: 1100px;
        padding: 2rem 1.6rem 3rem;
        color: var(--ink);
        background: linear-gradient(180deg, #fffaf5 0%, #ffffff 10rem);
      }}
      h1, h2, h3 {{
        color: #111827;
      }}
      h1 {{
        margin-bottom: 0.25rem;
        font-size: 2rem;
      }}
      h2 {{
        margin: 0 0 0.85rem;
        padding-bottom: 0.45rem;
        border-bottom: 1px solid #e5e7eb;
        font-size: 1.12rem;
      }}
      h3 {{
        margin-top: 0;
      }}
      .lede {{
        color: var(--muted);
        margin: 0.2rem 0 0;
      }}
      .report-cover {{
        margin-bottom: 1.5rem;
      }}
      .report-context {{
        display: flex;
        flex-wrap: wrap;
        gap: 0.55rem;
        margin-top: 0.9rem;
      }}
      .context-chip {{
        display: inline-flex;
        gap: 0.3rem;
        align-items: center;
        padding: 0.38rem 0.65rem;
        border-radius: 999px;
        border: 1px solid #e5e7eb;
        background: #fcfcfd;
        color: #374151;
        font-size: 0.82rem;
      }}
      table {{
        border-collapse: collapse;
        width: 100%;
        margin-bottom: 1.5rem;
        background: var(--panel);
        table-layout: fixed;
      }}
      th, td {{
        border: 1px solid var(--line);
        padding: 0.65rem 0.75rem;
        text-align: left;
        vertical-align: top;
      }}
      th {{
        width: 14rem;
        background: #fcfcfd;
        color: #374151;
        font-weight: 600;
      }}
      tr:nth-child(even) td {{
        background: #fcfcfd;
      }}
      .panel {{
        border: 1px solid var(--line);
        padding: 1rem 1.25rem;
        margin-bottom: 1.15rem;
        border-radius: 0.75rem;
        background: var(--panel);
        box-shadow: 0 8px 24px rgba(15, 23, 42, 0.04);
      }}
      .scope-grid {{
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(18rem, 1fr));
        gap: 1rem;
      }}
      .finding, .task {{
        border: 1px solid var(--line);
        padding: 1rem 1.25rem;
        margin-bottom: 1rem;
        border-radius: 0.75rem;
        background: var(--panel);
      }}
      .finding-header {{
        display: flex;
        align-items: baseline;
        justify-content: space-between;
        gap: 1rem;
      }}
      .finding p,
      .task p {{
        margin: 0.38rem 0;
      }}
      .priority {{
        color: var(--accent);
        font-weight: 700;
        padding: 0.26rem 0.55rem;
        border-radius: 999px;
        border: 1px solid #fdba74;
        background: #fff7ed;
        font-size: 0.8rem;
      }}
      code, pre {{
        background: var(--panel-alt);
        border-radius: 0.5rem;
        overflow-wrap: anywhere;
        word-break: break-word;
      }}
      code {{
        padding: 0.1rem 0.3rem;
        font-family: "SFMono-Regular", Consolas, "Liberation Mono", monospace;
      }}
      pre {{
        padding: 0.85rem;
        overflow-x: auto;
        white-space: pre-wrap;
        line-height: 1.5;
      }}
      ul, ol {{
        padding-left: 1.1rem;
      }}
      .meta-list li {{
        margin-bottom: 0.35rem;
      }}
    </style>
  </head>
  <body>
    <header class="report-cover pdf-cover">
      <h1>{escape(title)}</h1>
      <p class="lede">Evidence-first assessment output aligned to PTES, OWASP WSTG, and NIST SP 800-115 without changing the core execution model.</p>
      <div class="report-context">{report_context_html}</div>
    </header>

    <section class="panel">
      <h2>Summary</h2>
      <table>{summary_html}</table>
      <p><strong>By Severity:</strong> {escape(str(findings_by_severity or {}))}</p>
      <p><strong>By Status:</strong> {escape(str(findings_by_status or {}))}</p>
    </section>

    <section class="panel">
      <h2>Scope</h2>
      {scope_html}
    </section>

    <section class="panel">
      <h2>Run Configuration</h2>
      {configuration_html}
    </section>

    <section class="panel">
      <h2>Rules of Engagement Summary</h2>
      <p><strong>ROE Reference:</strong> {escape(run.engagement.roe_ref if run.engagement is not None and run.engagement.roe_ref else "Not Recorded")}</p>
      <ul class="meta-list">{approvals_html}</ul>
    </section>

    <section class="panel">
      <h2>Methodology Summary</h2>
      {methodology_html}
    </section>

    <section class="panel">
      <h2>Coverage Summary</h2>
      {coverage_html}
    </section>

    <section class="panel">
      <h2>Discovery Results</h2>
      {inventory_html}
    </section>

    <section class="panel">
      <h2>Adaptive Coverage</h2>
      {adaptive_pack_html}
    </section>

    <section class="panel">
      <h2>Adaptive Change Summary</h2>
      {adaptive_change_html}
    </section>

    {findings_section}
    {evidence_section}
    {verification_section}
  </body>
</html>
"""
